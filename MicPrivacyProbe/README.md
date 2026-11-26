# MicPrivacyProbe

A microphone-privacy **regression test** for **CVE-2026-65339** — the `audiomxd`
audit-token flaw that let a sandboxed app record the mic with no permission grant
and no orange indicator. Apple fixed it in **iOS/iPadOS 26.6.1** (advisory HT148282),
iOS 18.7.11 (HT149225), iOS 27 beta 5/6, and the matching macOS/tvOS/watchOS/visionOS
releases.

This app does **not** reproduce the exploit. It confirms the fix is present, and
produces vendor-ready evidence if it ever finds the fix *missing* on a device.

## What it checks

1. **Permission state** — reads `AVAudioApplication.recordPermission` without requesting it.
2. **Capture enforcement** — opens the legitimate `RemoteIO` input path (the unit the
   CVE abused) and measures whether real audio arrives while permission is *not* granted.
   Silent / zero-filled / no frames ⇒ **PASS** (blocked). Non-silent audio ⇒ **FAIL**.
3. **Property-2009 gate** — calls the `AudioUnitSetProperty` "client audit token"
   setter (id `2009`) with the app's *own* kernel audit token and records whether the
   OS rejects it. A patched OS gates it behind the kernel audit-token check plus the
   private entitlement `com.apple.private.audio.client-audit-token-override`.
4. **Report** — builds an Apple-ready write-up (expected-vs-actual, log, environment).

## What it deliberately omits — the line

To confirm the fix you do **not** need, and this project does **not** contain, the
weaponized core of the exploit:

- forging the `audiomxd` audit token,
- brute-forcing the daemon `pidversion` (0–1023),
- the MIG bad-id audit-trailer trick to locate `audiomxd`.

Those three steps are what turn the bug into covert surveillance. On a patched device
the enforcement probe above already shows the gate holds; if it somehow doesn't, that
result is itself the proof. A full PoC, if Apple requests one, goes through the
coordinated-disclosure channel — not into this repo.

## Build & run

Requires Xcode 26+ and a device on iOS 26 (a simulator has no real mic and will read
as PASS trivially — **test on hardware**).

```sh
brew install xcodegen          # one-time
cd MicPrivacyProbe
xcodegen generate              # creates MicPrivacyProbe.xcodeproj
open MicPrivacyProbe.xcodeproj # set your signing team, run on device
```

Before each run: **Settings → Privacy & Security → Microphone** — make sure this app
is **off** (or has never been granted). If permission is granted the test is
inconclusive by design.

## Reading the result

| Verdict | Meaning | Action |
|---|---|---|
| **PASS** | Capture blocked; fix present | Keep report as test evidence. Done. |
| **FAIL** | Audio captured without permission | Confirm it reproduces, then report to Apple. Do not disclose publicly first. |
| **INCONCLUSIVE** | Usually permission was already granted | Reset permission, re-run. |

## If you get a FAIL — reporting to Apple

1. Re-run 2–3 times to confirm it reproduces; note the exact **Version/build** from
   Settings → General → About.
2. Tap **Build Apple report**, then **Share report**.
3. File through **Apple Security Bounty** (security.apple.com) and/or email
   **product-security@apple.com**. Follow coordinated disclosure — give Apple time
   to fix before any public write-up.

## Expected result today

Every shipping iOS 26 build is **26.6.1 or later**, i.e. past the fix. The expected
verdict on current hardware is **PASS**. A FAIL on a current build would be the
genuinely report-worthy outcome.
