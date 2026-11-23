# flashgov — a flash write governor for car head units

A long-lived daemon that stops a head unit's eMMC from being worn out by badly
behaved applications, **without** breaking the workloads that legitimately write
a lot — navigation map updates, the dashcam recorder, and OTA.

It is deliberately split into three crates so the hard part (the policy) can be
proven on a laptop and against years of simulated device life, not just on a
test rig:

| crate | what it is | why it is separate |
|---|---|---|
| `flashgov-core` | the pure policy engine: budgets, wear model, attribution, stage ladder | no syscalls, deterministic, exhaustively unit-tested |
| `flashgovd` | the resident daemon: cgroup v2 + eMMC + persistence + IPC | every OS touch point is behind a small trait |
| `flashgov-sim` | a year-scale, deterministic fleet simulator | proves the policy on *realistic workload shapes*, not toy rates |

## The problem, stated precisely

A car head unit's storage is a soldered eMMC or UFS part with a finite write
endurance (TBW). A malicious or merely badly-written app that writes in a
background loop can consume that endurance in **weeks**. When the part wears
out, the whole unit fails — including the reversing camera and the instrument
cluster, because they share the same flash. The customer is told to buy a new
motherboard.

The incident that motivated this project: a third-party app wrote continuously
in the background, the eMMC failed within months, and the screen went black with
no reversing camera.

The naive fix — "limit every app to a small write rate" — breaks the product.
Map updates, the dashcam and OTA all write large amounts *legitimately*, and a
crude limiter makes maps stale, the dashcam lose footage, or the OTA never
finish. The four hard problems are:

1. **A daily allowance must become an instantaneous cap** that `io.max` can
   enforce, without throttling bursty-but-legitimate writes into failure.
2. **Writes made through system services** (download manager, package installer,
   media scanner) are not in the app's own cgroup and are hard to attribute.
3. **The governor must protect critical functions** (reversing camera, cluster,
   eCall) when the device is near end of life.
4. **The governor must not itself become a significant writer.**

## The design in one screen

```
 /sys/fs/cgroup/.../io.stat ─┐
 EXT_CSD wear (sysfs/ioctl) ─┼─▶  flashgov-core  ─▶  io.max  ─▶  kernel
 mediator attribution socket ┘   (pure policy)        │
                                                      └─▶ 4 KiB snapshot, rarely
```

- **Accounting** comes from cgroup v2 `io.stat`. A process cannot leave its
  cgroup, so *every* write an app's processes make — through any path or service
  — is attributed to it automatically.
- **Enforcement** is cgroup v2 `io.max`, which bounds the same subtree in
  aggregate and per-leaf.
- **The allocation** is a signed token bucket per app: a *sustained* allowance
  (the daily quota) plus a *burst* capacity (how much may be spent at full speed
  after idling). That is what lets a 2 GiB map delta land at flash speed while a
  runaway writer converges to its allowance.
- **The ceiling** follows the device's *actual* wear from EXT_CSD, not the
  datasheet, and is solved in the field (see [`docs/DESIGN.md`](docs/DESIGN.md)).
- **Persistence** is a fixed 4 KiB image, saved at most every 10 minutes and
  only when it changed — a parked car costs zero writes.

## Does it actually work?

`flashgov-sim` runs the real policy engine against a realistic fleet over a full
service life. The fleet is: navigation (2 GiB map delta every week), a dashcam
(90 minutes/day), an OTA updater (4 GiB a quarter), a browser, the instrument
cluster (critical), and one rogue writer that writes flat out.

**Adequate device (3 TiB part) — the governor should be invisible to honest apps:**

```
== GOVERNED ==
  survived 8.0y at 71.5% wear   final stage: orange
  com.oem.nav      essential   904.4 GiB  904.4 GiB    0.0%    0.0%   418/418 deltas on time
  com.oem.dashcam  essential   641.6 GiB  641.6 GiB    0.0%    0.0%   100% of demand met
  com.oem.ota      essential   132.0 GiB  132.0 GiB    0.0%    0.0%    33/33 updates on time
  com.oem.browser  normal      114.1 GiB  114.1 GiB    0.0%    0.0%
  com.oem.cluster  critical     17.1 GiB   17.1 GiB    0.0%    0.0%   100% of demand met
  com.evil.sync    untrusted   160.4 TiB   11.4 GiB  100.0%  100.0%   contained

== BASELINE (no governor) ==
  DEVICE DIED after 44.0 d
```

Every legitimate app gets **exactly what it needs**, the rogue app is cut
**14,359×**, and the device survives eight years instead of dying in six weeks.

**Oversubscribed device (1 TiB part) — the workload genuinely does not fit:**

The governor cannot make the workload fit; it makes the failure *graceful*:
critical functions keep writing, the device lasts the service life instead of
days, and the rationing is fair and explainable rather than first-come,
first-served. See the full comparison by running:

```sh
cargo run --release -p flashgov-sim -- --years 8
```

## Quick start

```sh
# Run the policy engine's own smoke test — no privileges, no hardware.
cargo run -p flashgovd -- --simulate

# Validate a configuration.
cargo run -p flashgovd -- --check --config config.example.json

# Run the 8-year fleet comparison.
cargo run --release -p flashgov-sim -- --years 8
```

## Deploying on a head unit

```sh
# 1. Lay out the cgroups the apps live in and hand them the io controller.
mkdir -p /sys/fs/cgroup/apps/{nav,dashcam,ota,browser,cluster,evil}
echo '+io' > /sys/fs/cgroup/apps/cgroup.subtree_control

# 2. Place the binary and config.
install -m0755 target/aarch64-unknown-linux-gnu/release/flashgovd /usr/bin/flashgovd
install -m0644 config.example.json /etc/flashgov.json

# 3. Run it (a systemd unit is in deploy/flashgovd.service).
flashgovd --config /etc/flashgov.json
```

The apps must be started *inside* their cgroups (Android's `cgroups.json` does
this; on a plain Linux HAL this is a `systemd` `Slice=`/`Delegate=` setting).
The governor enforces the *dimension*; it does not create the cgroup tree.

### Making system services attribute their writes

A download manager writes on behalf of whichever app asked for the file. Install
the small attribution hook so it reports the sponsor:

```sh
printf '{"mediator":"downloads","package":"com.evil.sync","bytes":%d}\n' "$n" \
  | socat - UNIX-CONNECT:/run/flashgov/attrib.sock
```

Anything it fails to report is charged to the mediator's own aggregate cap — so
a rogue app can at worst exhaust the download manager, never the flash.

## Repository layout

```
crates/flashgov-core/   policy engine (pure)
crates/flashgovd/       the daemon (OS backend, persistence, IPC)
crates/flashgov-sim/    year-scale simulator
docs/DESIGN.md          the reasoning, the trade-offs, what it does not do
config.example.json     a working configuration
deploy/flashgovd.service
```

## Testing

```sh
cargo test                       # 51 core + 23 daemon unit tests
cargo clippy --all-targets       # clean
cargo clippy --target x86_64-unknown-linux-gnu -p flashgovd   # the real code paths
```

The daemon's Linux-only code (cgroup, MMC ioctl, `localtime_r`) is type-checked
and clippy-checked against the Linux target from a non-Linux host, so a macOS
developer cannot merge code that fails to build on the device.

## What this does not solve

Honesty about scope is in [`docs/DESIGN.md`](docs/DESIGN.md), but in brief: it
cannot fix a device that is *already* worn out, it cannot attribute writes from
processes that genuinely live outside any managed cgroup, and it does not defend
against an attacker with root (who can simply stop the daemon). It is a
*containment* control for untrusted and buggy applications, which is the actual
failure mode in the field.
