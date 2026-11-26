# audio-recording-without-permission

Defensive verification tooling for **CVE-2026-65339**, an `audiomxd` audit-token flaw that allowed microphone capture without a permission grant and without the orange privacy indicator. Apple fixed it in iOS/iPadOS 26.6.1 (HT148282), iOS 18.7.11 (HT149225), and iOS 27 beta 5/6. Public write-up: https://rtx.meta.security/exploitation/2026/11/09/CVE-2026-65339.html

## What's here

- **`MicPrivacyProbe/`**: an iOS app that checks whether the microphone-permission gate holds on a device. It:
  - reads the record-permission state without requesting it,
  - opens the normal RemoteIO input path and measures whether non-silent audio arrives without a grant,
  - checks whether the audio-unit property 2009 (client audit token) setter rejects the app's own token.

  See [`MicPrivacyProbe/README.md`](MicPrivacyProbe/README.md) for build and run steps.

## What's deliberately not here

The probe doesn't include the exploit's weaponized core: forging the `audiomxd` audit token, brute-forcing its pidversion, or the MIG audit-trailer discovery. Confirming a fix doesn't need them, and including them would make this a covert recorder. A probe result of "silent" on an unpatched device means this tool is incomplete, not that the device is safe.

## Interpreting results

| Result | Meaning |
|---|---|
| Permission gate holds (silent capture, setter rejected) | Consistent with a patched build (26.6.1+ / 18.7.11+) |
| Setter accepted on an unpatched build | Consistent with the vulnerable state: the gate is missing |
| Non-silent audio without a grant | Potential new regression. Reproduce, then report privately |

Confirm reports against the device model and exact build number (Settings → General → About).

## Reporting

If a run shows non-silent audio without a permission grant on a current build, report it privately through Apple Security Bounty (security.apple.com) or product-security@apple.com. Follow coordinated disclosure and don't publish details before Apple ships a fix.

## Requirements

- Xcode 26+ and XcodeGen (`brew install xcodegen`)
- A physical iPhone on iOS 26 (the simulator has no real microphone, so its results aren't meaningful)

## Status

Early scaffold. The project builds for the simulator; on-device verification is ongoing.
