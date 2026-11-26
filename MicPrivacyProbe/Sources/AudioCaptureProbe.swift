import Foundation
import AVFoundation
import AudioToolbox

/// Result of one verification run.
struct ProbeResult {
    enum Verdict: String { case passFixed = "PASS — capture blocked (fix present)"
                           case failVulnerable = "FAIL — audio captured without permission"
                           case inconclusive = "INCONCLUSIVE" }

    var verdict: Verdict = .inconclusive
    var permissionState: String = "unknown"
    var osVersion: String = ""
    var deviceModel: String = ""
    var framesObserved: Int = 0
    var peakAmplitude: Float = 0        // 0.0 == pure silence
    var rms: Float = 0
    var property2009Status: OSStatus = noErr
    var property2009Rejected: Bool = false
    var log: [String] = []
}

/// Audio-unit property the CVE abused ("client audit token"), handled server-side
/// by AUIOServer_SetProperty. Public writeup refers to it by raw id 2009.
private let kClientAuditTokenProperty: AudioUnitPropertyID = 2009

final class AudioCaptureProbe {

    private var ioUnit: AudioUnit?
    private var result = ProbeResult()
    private let bus1: AudioUnitElement = 1   // input bus (microphone)
    private var captureBuffer = [Float](repeating: 0, count: 4096)

    // MARK: - Public entry point

    func run() -> ProbeResult {
        result = ProbeResult()
        result.osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        result.deviceModel = Self.hardwareModel()
        result.permissionState = Self.permissionStateString()
        log("Device: \(result.deviceModel)")
        log("OS: \(result.osVersion)")
        log("Record permission (not requested): \(result.permissionState)")

        // Only meaningful when permission is NOT granted. If it is granted,
        // capture is allowed and the test can't distinguish fix from bypass.
        if result.permissionState == "granted" {
            log("Permission is GRANTED — reset it in Settings before testing, or the result is meaningless.")
            result.verdict = .inconclusive
            return result
        }

        guard setUpRemoteIO() else {
            result.verdict = .inconclusive
            return result
        }

        runEnforcementProbe()        // non-weaponized property-2009 gate check
        measureCapture()             // does real audio arrive without permission?
        tearDown()
        decideVerdict()
        return result
    }

    // MARK: - RemoteIO setup (the legitimate path the CVE abused)

    private func setUpRemoteIO() -> Bool {
        var desc = AudioComponentDescription(
            componentType: kAudioUnitType_Output,
            componentSubType: kAudioUnitSubType_RemoteIO,
            componentManufacturer: kAudioUnitManufacturer_Apple,
            componentFlags: 0, componentFlagsMask: 0)

        guard let comp = AudioComponentFindNext(nil, &desc) else {
            log("AudioComponentFindNext failed"); return false
        }
        var unit: AudioUnit?
        var status = AudioComponentInstanceNew(comp, &unit)
        guard status == noErr, let unit else {
            log("AudioComponentInstanceNew failed: \(status)"); return false
        }
        ioUnit = unit

        // Enable input on bus 1.
        var enable: UInt32 = 1
        status = AudioUnitSetProperty(unit, kAudioOutputUnitProperty_EnableIO,
                                      kAudioUnitScope_Input, bus1,
                                      &enable, UInt32(MemoryLayout<UInt32>.size))
        log("EnableIO(input) status: \(status)")

        // Mono float32 at 48k.
        var fmt = AudioStreamBasicDescription(
            mSampleRate: 48000,
            mFormatID: kAudioFormatLinearPCM,
            mFormatFlags: kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked,
            mBytesPerPacket: 4, mFramesPerPacket: 1, mBytesPerFrame: 4,
            mChannelsPerFrame: 1, mBitsPerChannel: 32, mReserved: 0)
        status = AudioUnitSetProperty(unit, kAudioUnitProperty_StreamFormat,
                                      kAudioUnitScope_Output, bus1,
                                      &fmt, UInt32(MemoryLayout<AudioStreamBasicDescription>.size))
        log("StreamFormat status: \(status)")

        // Install input callback.
        var cb = AURenderCallbackStruct(
            inputProc: Self.inputCallback,
            inputProcRefCon: Unmanaged.passUnretained(self).toOpaque())
        status = AudioUnitSetProperty(unit, kAudioOutputUnitProperty_SetInputCallback,
                                      kAudioUnitScope_Global, bus1,
                                      &cb, UInt32(MemoryLayout<AURenderCallbackStruct>.size))
        log("SetInputCallback status: \(status)")

        status = AudioUnitInitialize(unit)   // aborts without NSMicrophoneUsageDescription
        log("AudioUnitInitialize status: \(status)")
        guard status == noErr else { return false }
        return true
    }

    // MARK: - Non-weaponized enforcement probe

    /// Calls the property-2009 setter with the app's OWN audit token. A patched
    /// OS rejects this (entitlement / kernel-audit-token gate). We intentionally
    /// do NOT supply a forged audiomxd token or brute-force its pidversion, so
    /// this cannot actually enable covert recording — it only reveals whether
    /// the setter is gated.
    private func runEnforcementProbe() {
        guard let unit = ioUnit else { return }
        var token = Self.selfAuditToken()
        let status = AudioUnitSetProperty(unit, kClientAuditTokenProperty,
                                          kAudioUnitScope_Global, 0,
                                          &token, UInt32(MemoryLayout<audit_token_t>.size))
        result.property2009Status = status
        result.property2009Rejected = (status != noErr)
        log("Property 2009 (client audit token) setter status: \(status) -> " +
            (status != noErr ? "REJECTED (gate present)" : "accepted"))
    }

    // MARK: - Capture measurement

    private func measureCapture() {
        guard let unit = ioUnit else { return }
        let status = AudioOutputUnitStart(unit)
        log("AudioOutputUnitStart status: \(status)")
        guard status == noErr else { return }

        // Let a few hundred ms of buffers flow, then stop.
        Thread.sleep(forTimeInterval: 0.6)
        AudioOutputUnitStop(unit)

        log("Frames observed: \(result.framesObserved), peak: \(result.peakAmplitude), rms: \(result.rms)")
    }

    private func tearDown() {
        if let unit = ioUnit {
            AudioUnitUninitialize(unit)
            AudioComponentInstanceDispose(unit)
        }
        ioUnit = nil
    }

    private func decideVerdict() {
        // Silence threshold: real mic audio, even in a quiet room, sits well
        // above this; a blocked input returns exact zeros or fails to render.
        let silenceFloor: Float = 1e-5
        if result.framesObserved == 0 {
            result.verdict = .passFixed
            log("No input frames delivered — capture blocked.")
        } else if result.peakAmplitude <= silenceFloor {
            result.verdict = .passFixed
            log("Frames were silent (zero-filled) — capture blocked.")
        } else {
            result.verdict = .failVulnerable
            log("⚠️ Non-silent audio captured without a permission grant.")
        }
    }

    // MARK: - Render callback

    private static let inputCallback: AURenderCallback = {
        (refCon, ioActionFlags, inTimeStamp, inBusNumber, inNumberFrames, ioData) -> OSStatus in
        let probe = Unmanaged<AudioCaptureProbe>.fromOpaque(refCon).takeUnretainedValue()
        guard let unit = probe.ioUnit else { return noErr }

        let frames = Int(inNumberFrames)
        if probe.captureBuffer.count < frames {
            probe.captureBuffer = [Float](repeating: 0, count: frames)
        }

        var status: OSStatus = noErr
        probe.captureBuffer.withUnsafeMutableBufferPointer { ptr in
            var bufList = AudioBufferList(
                mNumberBuffers: 1,
                mBuffers: AudioBuffer(mNumberChannels: 1,
                                      mDataByteSize: UInt32(frames * MemoryLayout<Float>.size),
                                      mData: ptr.baseAddress))
            status = AudioUnitRender(unit, ioActionFlags, inTimeStamp,
                                     inBusNumber, inNumberFrames, &bufList)
            if status == noErr {
                var peak: Float = 0
                var sumSq: Float = 0
                for i in 0..<frames {
                    let v = ptr[i]
                    peak = max(peak, abs(v))
                    sumSq += v * v
                }
                probe.result.framesObserved += frames
                probe.result.peakAmplitude = max(probe.result.peakAmplitude, peak)
                probe.result.rms = (sumSq / Float(max(frames, 1))).squareRoot()
            }
        }
        return status
    }

    // MARK: - Helpers

    private func log(_ s: String) {
        result.log.append(s)
        print("[MicPrivacyProbe] \(s)")
    }

    private static func permissionStateString() -> String {
        switch AVAudioApplication.shared.recordPermission {
        case .granted: return "granted"
        case .denied: return "denied"
        case .undetermined: return "undetermined"
        @unknown default: return "unknown"
        }
    }

    /// The app's own audit token, obtained the legitimate way (kernel-supplied).
    private static func selfAuditToken() -> audit_token_t {
        var token = audit_token_t()
        _ = task_audit_token_fetch(&token)
        return token
    }

    private static func hardwareModel() -> String {
        var size = 0
        sysctlbyname("hw.machine", nil, &size, nil, 0)
        var machine = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.machine", &machine, &size, nil, 0)
        return String(cString: machine)
    }
}

/// Fetch THIS process's kernel-supplied audit token (no forgery).
private func task_audit_token_fetch(_ token: inout audit_token_t) -> kern_return_t {
    var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
    return withUnsafeMutablePointer(to: &token) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
            task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), intPtr, &count)
        }
    }
}
