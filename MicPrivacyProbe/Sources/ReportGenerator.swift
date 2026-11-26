import Foundation

/// Builds a vendor-ready report from a probe result. Only meaningful to *send*
/// when the verdict is FAIL (a current build still captured audio without a
/// permission grant). For a PASS, keep the output as your own test evidence.
enum ReportGenerator {

    static func make(from r: ProbeResult) -> String {
        let date = ISO8601DateFormatter().string(from: Date())
        let header: String
        switch r.verdict {
        case .failVulnerable:
            header = """
            SUBJECT: Microphone capture without permission grant on \(r.osVersion)
            SEND TO: product-security@apple.com  (and file via Apple Security Bounty)

            >>> This verdict is FAIL. If you have confirmed it is reproducible,
            >>> this is a privacy regression worth reporting. Do NOT post it
            >>> publicly before Apple has shipped a fix (coordinated disclosure).
            """
        case .passFixed:
            header = """
            SUBJECT: (internal evidence only — not for submission)
            Verdict was PASS: the OS blocked capture. The fix for CVE-2026-65339
            is present on this build. Keep this as your test record.
            """
        case .inconclusive:
            header = """
            SUBJECT: (inconclusive — re-run required)
            The test could not reach a clean verdict. Most common cause: record
            permission was already granted. Reset it in Settings > Privacy &
            Security > Microphone and run again.
            """
        }

        return """
        \(header)

        ── Environment ──────────────────────────────
        Date (UTC):        \(date)
        Device model:      \(r.deviceModel)
        OS version string: \(r.osVersion)
        Record permission: \(r.permissionState)  (NOT requested by the test)
        Related CVE:        CVE-2026-65339 (fixed iOS/iPadOS 26.6.1)

        ── Observed behaviour ───────────────────────
        Verdict:            \(r.verdict.rawValue)
        Input frames seen:  \(r.framesObserved)
        Peak amplitude:     \(String(format: "%.8f", r.peakAmplitude))
        RMS:                \(String(format: "%.8f", r.rms))
        Property-2009 set:  status \(r.property2009Status) \
        (\(r.property2009Rejected ? "rejected — gate present" : "accepted — gate ABSENT"))

        ── Expected vs actual ───────────────────────
        Expected (patched): no input frames, or silent/zero-filled buffers, while
                            permission is not granted; property-2009 setter rejected.
        Actual:             see "Observed behaviour" above.

        ── Reproduction (high level) ────────────────
        1. Install MicPrivacyProbe (bundle has NSMicrophoneUsageDescription, no
           private entitlements). Do not grant microphone permission.
        2. Launch, tap "Run verification".
        3. The app opens the RemoteIO input path and measures incoming audio.
        A FAIL means non-silent audio reached the app with permission state
        "\(r.permissionState)".

        ── Run log ──────────────────────────────────
        \(r.log.map { "  " + $0 }.joined(separator: "\n"))

        ── Notes for the reviewer ───────────────────
        This harness intentionally omits the weaponized primitive from the public
        write-up (forged audiomxd audit token, pidversion brute-force, MIG bad-id
        audit-trailer discovery). If Apple needs a full proof-of-concept, request
        it through the coordinated-disclosure channel rather than attaching it here.
        """
    }
}
