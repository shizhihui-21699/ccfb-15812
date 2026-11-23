# Design

This document explains *why* the governor works the way it does. It is the
place to look before changing a threshold, and the place to check an assumption
against the field reality it was written for.

The governing principle throughout: **a write limiter that breaks a legitimate
heavy writer is worse than no limiter at all**, because the OEM will ship with it
disabled. Every design decision below is chosen to keep honest workloads
running while containing dishonest ones.

---

## 1. Where the bytes are counted: cgroup v2, not per-process

The requirement is "charge application X for the bytes it causes to be written,
including when it writes through a system service or a shared directory". The
only kernel mechanism that gets this right *by construction* is the cgroup:

- **A process cannot escape its cgroup.** `exec`, `fork`, `setsid`, `chdir`,
  `unshare` — every descendant stays in the same subtree. So every write the
  app's own processes issue is attributed to the app, whichever path or service
  it goes through.
- **`io.stat`** counts the bytes the block layer sees for that cgroup: after
  page-cache coalescing, including metadata the kernel writes on the app's
  behalf.
- **`io.max`** throttles the same subtree: a per-app cgroup under a mediated
  subtree is bounded both individually and in aggregate.

We read `wbytes` from `io.stat`, sum over all devices, and charge the **delta**
between samples. A first sighting of a cgroup charges zero (we have no baseline;
charging the lifetime total would instantly bankrupt every app on first boot).
A counter reset clamps to zero rather than going negative.

### The one hole, and how the mediator closes it

cgroup accounting cannot see a write made by *another* cgroup's process on the
app's behalf: app X asks the download manager to fetch a file, and the download
manager writes it into its own cgroup. Two mechanisms close this:

1. **Attribution hook.** The mediating service reports
   `{mediator, package, bytes}` over a unix socket. The governor charges those
   bytes to the sponsor's bucket immediately — so a delegated 3 GiB download
   tightens the sponsor's cap at once, not at the next tick.
2. **Aggregate cap on the mediator.** Whatever it fails to report draws on the
   mediator's own allowance. A rogue app that abuses the mediator can at worst
   exhaust the mediator; the flash is still bounded.

There is a deliberate fallback for `single_tenant` services: if exactly one app
uses the mediator, unattributed bytes are charged to it and an alert is raised.
This is honest about being a heuristic — it is reported, not silent.

---

## 2. Turning a daily allowance into an instantaneous cap

`io.max` wants a **rate in bytes per second**. The policy thinks in **bytes per
day**. `bytes/day ÷ 86400` is the naive bridge, and it is the single most common
way a write limiter breaks real software.

Navigation wants to push a 2 GiB map delta in twenty minutes. A dashcam wants to
flush a segment at ignition-off. Both are overwhelmingly legitimate, and both
look, at any one instant, exactly like a runaway writer. Pinned to their daily
average they never finish.

### The signed token bucket

Each app has a token bucket:

- `quota_bpd` — the **sustained refill rate**. An app that writes forever
  converges to exactly this average.
- `capacity` (burst) — how much may be spent at full device speed from banked
  allowance. Defaults to a quarter of the daily quota, with a floor; essential
  apps get a large default burst because their writes are big and indivisible.
- `balance` — **signed**. An app that outruns its bucket goes into debt and runs
  at a trickle until repaid.

The instantaneous cap presented to the kernel is

```
rate = balance / TAU + refill
```

i.e. the rate that would exactly drain the current balance over `TAU` seconds
while letting the ongoing refill through. A full bucket is effectively
unlimited; as it empties the cap collapses to the refill rate and, in debt, to a
floor.

### Two bugs this design has to avoid, both found by the tests

**Tick-length dependence.** A naive `advance(); charge(spent)` is wrong for any
interval longer than the bucket's drain time: the refill is clipped at
`capacity` *before* the interval's spending is subtracted, so a day's worth of
allowance is silently thrown away and a legitimate app on a coarse tick is
starved. The fix is a single `advance_charge(now, spent)` that allows the
balance to rise to `capacity + spent` and *then* subtracts `spent`, so the result
does not depend on the tick length. (Test: `tick_length_does_not_change_totals`,
and `unlike_the_naive_order_this_keeps_the_budget` demonstrates the bug.)

**A floor that is a back door.** The floor exists so a throttled app is never
*hung* — a `wbps` of 0 blocks every write forever, which users experience as a
crashed unit. But a fixed byte floor lets an app on a tiny allowance write orders
of magnitude over budget while nominally "throttled": 4 MiB/day at a 16 KiB/s
floor is ~350× over. The resolution is that an app's own sustainable rate is
already a non-zero trickle, so the floor is capped at it: *throttled means "on
allowance"*, not "off the hook". Only a zero allowance (an app cut off at Red)
uses the absolute minimum trickle. (Test:
`trickle_never_exceeds_the_apps_own_allowance`.)

### Sizing bursts correctly — an OEM pitfall worth stating

The burst must cover the largest single operation **plus** the steady traffic
between two of them. If the burst is set to exactly the size of the map delta,
the delta is perpetually a hundred megabytes short (the daily POI writes nibbled
the bucket during the week), and it trickles past its deadline forever. The
simulator surfaced exactly this: a 2 GiB delta with a 2 GiB burst, on a 327
MiB/day allowance, never completed. The reference dashboard and config size the
burst as `largest_operation + one period of steady traffic`, times a margin.

---

## 3. Following the device's real wear, not the datasheet

The integrator writes `target_tbw_gib` from the part datasheet, and that number
is frequently wrong: parts are binned differently, some ship with more spare
area, and the same board may ship with two different parts across a production
run.

The eMMC knows how worn it is. EXT_CSD exposes:

| byte | field | meaning |
|---|---|---|
| 267 | `PRE_EOL_INFO` | 0 unknown, 1 normal (<80%), 2 warning (80–90%), 3 urgent (>90%) |
| 268 | `DEVICE_LIFE_TIME_EST_TYP_A` | bucket 0x01–0x0A = 0–10%…90–100%, 0x0B = exceeded |
| 269 | `DEVICE_LIFE_TIME_EST_TYP_B` | same, different region of the die |

We take the **worse** of Type A and Type B: whichever region wears out first is
what takes the device down. A bucket is read at its *upper* bound (a device
reporting "80–90%" is treated as 90%), because the policy must behave for the
wear the device might already have. Wear is ratcheted monotonic: a garbled read
cannot reset a worn device to "healthy".

### Solving for real endurance in the field

The datasheet TBW is untrustworthy, but the governor counts host writes itself.
Once the life estimate has moved off zero we can *solve* for the part's actual
endurance:

```
estimated_total_bytes ≈ lifetime_host_bytes / (life_permille / 1000)
```

This turns a coarse 10%-wide bucket into a byte budget that tracks the actual
drive and self-corrects as it ages. Until enough wear has accumulated for the
estimate to be trustworthy (below 2% consumed, one bucket step could be off by
5×), it falls back to the configured TBW — and never trusts an estimate *below*
the configured TBW, which would mean we under-accounted writes somewhere.

The result is the one number operators care about: **bytes per day sustainable
until the service date**, which is the ceiling for the whole system.

### The reserve must be a share of the *real* ceiling

A subtle bug, caught in review: the critical reserve was computed from the
*datasheet* ceiling. On a worn device the true ceiling shrinks to a fraction of
the datasheet rate, and a reserve sized off the datasheet then exceeds the entire
budget — starving every non-critical app to nothing while reserving room nobody
could use. The reserve is now a percentage of the *actual* ceiling.

---

## 4. The stage ladder, and the pace distinction

Two different triggers exist, and conflating them is a mistake:

- **Rate pressure** is driven by **pace**, not absolute wear. A fleet writing
  exactly its sustainable rate is perfectly on plan at 60% consumed with 60% of
  its service life gone, and throttling it there punishes compliant users for
  nothing. The right signal is `consumed_life − elapsed_life`: wear that races
  ahead of the calendar, visible years before the absolute percentage is
  alarming. (This is why the 8-year simulator shows the adequate device reaching
  **orange** at 71.5% wear — it is on pace, so it is being trimmed gently, not
  throttled hard.)

- **Hard protection** is driven by the absolute **stage**:

  | stage | absolute wear | what happens |
  |---|---|---|
  | green | < amber | nothing reduced; the ceiling is the only limit |
  | amber | ≥ 60% | ordinary apps trimmed by pace |
  | orange | ≥ 80% or pre-EOL warning | essentials feel it; bursts shrink but stay map-sized |
  | red | ≥ 90% or pre-EOL urgent | untrusted allowance → 0; critical untouched |

  The ladder is the promise to the driver: at the very end, the reversing camera
  and the cluster keep writing normally, because those are what make the car
  safe. Untrusted apps are cut to a trickle (or frozen, if the OEM opts in);
  everything else degrades in proportion.

Hysteresis on the stage prevents flapping from a noisy EXT_CSD read. A pre-EOL
urgent flag forces Red even if the percentage arithmetic disagrees — it is the
vendor's own signal and outranks ours.

---

## 5. The governor must not be a writer

This is stated as a requirement in the brief, and it drives the persistence
design:

- **Small.** The state image is a fixed 4 KiB — one eMMC page — so a save is one
  program cycle regardless of how many apps are watched. The layout is
  hand-rolled (not JSON) so the size is exact and it can be read by a recovery
  tool without a parser.
- **Rare.** Saved at most once per `persist_secs` (default 10 min), and only when
  it *materially* changed, compared in coarse buckets so the few bytes of
  drift between ticks never trigger a write. A parked car costs zero writes.
  Expected cost: ~9 MB a year at the default cadence — a rounding error against
  the endurance model, and it reports its own total.
- **Atomic.** `write tmp → fsync → rename → fsync(dir)`, with the previous image
  kept as `.bak`. A power cut leaves the old image or the new one, never a torn
  file. Worst case we lose the last 10 minutes of accounting — and wear is
  re-read from EXT_CSD on every boot, so that is not cumulative.
- **Bounded.** A hard lifetime cap (`self_write_budget_bytes`) means that if a
  configuration bug ever made the daemon save in a loop, it would stop writing
  rather than wear the flash out itself.

---

## 6. What this does not do — honestly

- **It cannot fix an already-worn device.** It slows further wear and protects
  critical functions; it does not restore endurance. A unit already at 95% should
  be replaced, and the governor's alerts say so.
- **It cannot attribute bytes from a process that genuinely lives outside any
  managed cgroup.** The attribution-gap detector raises an alert when writes
  reach the flash without a cgroup we manage, but it cannot charge them. The fix
  is to bring the new writer into the tree.
- **It does not defend against an attacker with root**, who can stop the daemon
  or rewrite the config. It is a containment control for untrusted and buggy
  *applications*, which is the actual failure mode in the field — not a security
  boundary against a compromised system.
- **It cannot make an undersized part fit the workload.** On an oversubscribed
  device it makes the failure graceful (criticals survive, life extends) but the
  OEM still needs a bigger part or a smaller workload. The simulator shows both
  outcomes so the decision can be made before shipping.
- **It does not create the cgroup tree.** It enforces within the cgroups the
  platform already provides; wiring that up is the platform's job (Android
  `cgroups.json`, or systemd slices on a plain Linux HAL).

---

## 7. Thresholds and defaults, and why

| setting | default | reasoning |
|---|---|---|
| `stages.amber` | 600 permille | first slowdown; leaves 40% to react |
| `stages.orange` | 800 | matches pre-EOL *warning* |
| `stages.red` | 900 | matches pre-EOL *urgent*; freeze/cutover |
| `critical_reserve_pct` | 15 | room for the cluster/camera to always write |
| `burst_tau_secs` | 60 | a full bucket releases over a minute: fast for a map delta, not minutes of line-rate |
| `floor_bps` | 16 KiB/s | never zero (a zero cap hangs the app); capped at the app's own rate |
| `tick_ms` | 15000 | 4 ticks/min: responsive enough for `io.max`, cheap enough to be free |
| `wear_sample_secs` | 900 | EXT_CSD reads are cheap but the value moves slowly |
| `persist_secs` | 600 | ~9 MB/year of self-writes |
| Essential default quota | 512 MiB/day | map deltas + dashcam are large but predictable |
| Untrusted default quota | 4 MiB/day | no legitimate reason to write much at all |

These are starting points an OEM tunes. The one thing that must not be tuned away
is the non-zero floor: a zero `wbps` turns a throttle into a hang, which is the
symptom users report as "the head unit crashed".

---

## 8. How the simulator earns its keep

The simulator models *workload shapes*, not constant rates: nav spikes weekly,
the dashcam runs while driving, OTA is rare and huge, the browser dribbles, the
cluster is tiny and critical, the rogue writes flat out. It runs the real policy
engine tick by tick with a token-bucket device model and EXT_CSD-style coarse
wear reporting.

It has already caught, in this codebase:

- the tick-length dependence of the bucket (would have starved legitimate apps
  on a coarse tick);
- the reserve-sized-off-the-datasheet bug;
- the "burst exactly equals the file" sizing trap;
- a workload that counted its own flush twice, inflating its apparent demand;
- the fact that a *declared* quota is not a *trusted* quota — a rogue app declares
  a small allowance to avoid standing out, and must be caught from observed
  writes, not from the number it reports.

That last point is the philosophy of the whole thing: trust measurement, not
declarations.
