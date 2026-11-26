import SwiftUI

struct ContentView: View {
    @State private var result: ProbeResult?
    @State private var running = false
    @State private var reportText = ""

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {

                    Text("CVE-2026-65339 — microphone bypass regression test")
                        .font(.headline)
                    Text("Fixed in iOS/iPadOS 26.6.1. On a patched device this should report PASS.")
                        .font(.caption).foregroundStyle(.secondary)

                    Button(action: runTest) {
                        Label(running ? "Running…" : "Run verification",
                              systemImage: "mic.slash.circle")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(running)

                    if let r = result {
                        verdictBadge(r)
                        detailRows(r)
                        logView(r)

                        Button("Build Apple report") {
                            reportText = ReportGenerator.make(from: r)
                        }
                        if !reportText.isEmpty {
                            Text(reportText)
                                .font(.system(.footnote, design: .monospaced))
                                .textSelection(.enabled)
                                .padding()
                                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                            ShareLink(item: reportText) {
                                Label("Share report", systemImage: "square.and.arrow.up")
                            }
                        }
                    }
                }
                .padding()
            }
            .navigationTitle("MicPrivacyProbe")
        }
    }

    private func runTest() {
        running = true
        reportText = ""
        DispatchQueue.global(qos: .userInitiated).async {
            let r = AudioCaptureProbe().run()
            DispatchQueue.main.async {
                result = r
                running = false
            }
        }
    }

    @ViewBuilder private func verdictBadge(_ r: ProbeResult) -> some View {
        let color: Color = r.verdict == .passFixed ? .green
                         : r.verdict == .failVulnerable ? .red : .orange
        Text(r.verdict.rawValue)
            .font(.subheadline.weight(.semibold))
            .padding(.horizontal, 12).padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(color.opacity(0.18), in: RoundedRectangle(cornerRadius: 8))
            .foregroundStyle(color)
    }

    @ViewBuilder private func detailRows(_ r: ProbeResult) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            row("Device", r.deviceModel)
            row("OS", r.osVersion)
            row("Permission", r.permissionState)
            row("Frames observed", "\(r.framesObserved)")
            row("Peak amplitude", String(format: "%.6f", r.peakAmplitude))
            row("RMS", String(format: "%.6f", r.rms))
            row("Property 2009 setter", r.property2009Rejected
                ? "rejected (status \(r.property2009Status))"
                : "accepted (status \(r.property2009Status))")
        }
        .font(.system(.footnote, design: .monospaced))
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k).foregroundStyle(.secondary); Spacer(); Text(v) }
    }

    @ViewBuilder private func logView(_ r: ProbeResult) -> some View {
        DisclosureGroup("Log (\(r.log.count) lines)") {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(Array(r.log.enumerated()), id: \.offset) { _, line in
                    Text(line).font(.system(.caption2, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }
}
