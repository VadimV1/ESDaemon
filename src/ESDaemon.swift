// ESDaemon — reads one line per event from stdin and writes each one to the macOS unified log
// under a fixed subsystem/category, so the Bindplane macOS unified-logging receiver can select it by predicate.
//
// Why not /usr/bin/logger: modern macOS logger cannot set a subsystem, so a Bindplane predicate can't select it.
// %{public}@ is mandatory: without it every dynamic string is redacted to <private> in `log stream`.
// Build:  swiftc -O -o ESDaemon ESDaemon.swift
// Usage:  ESDaemon [subsystem] [category] [format]
//         (defaults: com.apple.eslogger / events — same as eslogger --oslog. filter.sh passes all three; each line is
//          already shaped to [format] upstream by scope.jq, so the writer accepts the argument but logs lines verbatim.)
import Foundation
import os.log

// The read loop logs through here, and nothing else writes this stream. Every line read becomes exactly one os_log
// call, and one os_log call is one whole message, so each record is written whole or not at all — it can never be
// cut into invalid JSON the way a second process printing into the pipe could (jq writes a big record in several
// writes). That atomicity is the whole reason ESDaemon exists rather than piping eslogger's output to logger.
final class Writer {
    private let log: OSLog
    init(_ log: OSLog) { self.log = log }

    func write(_ line: String) {
        os_log("%{public}@", log: log, type: .default, line)   // %@ + Swift String bridges to NSString; %s would expect a C string
    }
}

let args = CommandLine.arguments
let subsystem = args.count > 1 ? args[1] : "com.apple.eslogger"
let category  = args.count > 2 ? args[2] : "events"
// args[3] (format) is part of the documented invocation but the writer does not read it: scope.jq shapes each line.
let writer = Writer(OSLog(subsystem: subsystem, category: category))

setvbuf(stdin, nil, _IOLBF, 0)
while let line = readLine(strippingNewline: true) {
    if line.isEmpty { continue }
    writer.write(line)
}
