// ESDaemon — reads one line per event from stdin and writes each one to the macOS unified log
// under a fixed subsystem/category, so the Bindplane macOS unified-logging receiver can select it by predicate.
// Given a heartbeat interval it also logs a liveness record of its own (see Writer).
//
// Why not /usr/bin/logger: modern macOS logger cannot set a subsystem, so a Bindplane predicate can't select it.
// %{public}@ is mandatory: without it every dynamic string is redacted to <private> in `log stream`.
// Build:  swiftc -O -o ESDaemon ESDaemon.swift
// Usage:  ESDaemon [subsystem] [category] [heartbeat] [format]
//         (defaults: com.apple.eslogger / events — same as eslogger --oslog — and no heartbeat; filter.sh passes all four)
import Foundation
import os.log

// The read loop and the heartbeat timer both log through here, and nothing else writes this stream. One os_log call
// is one whole message, so a heartbeat can never land inside an event record (a second process printing into stdin
// could: jq writes a big record in several writes). Each call and its count share one lock, so a heartbeat's
// "records" are exactly the records logged between it and the previous heartbeat.
final class Writer: @unchecked Sendable {   // @unchecked: `lock` guards `records`
    private let log: OSLog, heartbeat: Int, sysmon: Bool
    private let lock = NSLock()
    private var records = 0
    private var timer: DispatchSourceTimer?   // held for the life of the process: a released timer stops firing

    // heartbeat: seconds, 1-86400 ([settings] heartbeat), anything else = off. The first one comes a full interval after
    // start, so a filter that keeps restarting sends none; this process ends with the filter job (EOF when the job's
    // jq exits, or launchd killing the job), and its heartbeats end with it.
    init(_ log: OSLog, heartbeat: Int, sysmon: Bool) {
        self.log = log; self.heartbeat = heartbeat; self.sysmon = sysmon
        guard (1...86400).contains(heartbeat) else { return }
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + .seconds(heartbeat), repeating: .seconds(heartbeat))
        t.setEventHandler { [weak self] in self?.beat() }
        t.resume()
        timer = t
    }

    func write(_ line: String) {
        lock.lock(); defer { lock.unlock() }
        os_log("%{public}@", log: log, type: .default, line)   // %@ + Swift String bridges to NSString; %s would expect a C string
        records += 1
    }

    // {"eslogger_scoped_heartbeat":300,"time":"2026-10-27T12:00:00Z","records":42}: the interval, the time as the
    // restart marker writes it, the records logged since the previous heartbeat. In a sysmon format the gap marker's
    // Sysmon envelope comes first: {"EventID":100,"EventType":"eslogger_scoped_heartbeat","UtcTime":"2026-10-27 12:00:00.000",...}
    private func beat() {
        lock.lock(); defer { lock.unlock() }
        let time = ISO8601DateFormatter().string(from: Date())
        let fields = #""eslogger_scoped_heartbeat":\#(heartbeat),"time":"\#(time)","records":\#(records)"#
        let utc = time.replacingOccurrences(of: "T", with: " ").replacingOccurrences(of: "Z", with: ".000")
        let record = sysmon ? #"{"EventID":100,"EventType":"eslogger_scoped_heartbeat","UtcTime":"\#(utc)",\#(fields)}"# : "{\(fields)}"
        os_log("%{public}@", log: log, type: .default, record)
        records = 0
    }
}

let args = CommandLine.arguments
let subsystem = args.count > 1 ? args[1] : "com.apple.eslogger"
let category  = args.count > 2 ? args[2] : "events"
let writer = Writer(OSLog(subsystem: subsystem, category: category),
                    heartbeat: args.count > 3 ? Int(args[3]) ?? 0 : 0,
                    sysmon: args.count > 4 && args[4].hasPrefix("sysmon"))   // format = sysmon or sysmon+extras

setvbuf(stdin, nil, _IOLBF, 0)
while let line = readLine(strippingNewline: true) {
    if line.isEmpty { continue }
    writer.write(line)
}
