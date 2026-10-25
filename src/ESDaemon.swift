// ESDaemon — reads one line per event from stdin and writes each one to the macOS unified log
// under a fixed subsystem/category, so the Bindplane macOS unified-logging receiver can select it by predicate.
//
// Why not /usr/bin/logger: modern macOS logger cannot set a subsystem, so a Bindplane predicate can't select it.
// %{public}@ is mandatory: without it every dynamic string is redacted to <private> in `log stream`.
// Build:  swiftc -O -o ESDaemon ESDaemon.swift
// Usage:  ESDaemon [subsystem] [category]      (defaults: com.apple.eslogger / events — same as eslogger --oslog)
import Foundation
import os.log

let args = CommandLine.arguments
let subsystem = args.count > 1 ? args[1] : "com.apple.eslogger"
let category  = args.count > 2 ? args[2] : "events"
let log = OSLog(subsystem: subsystem, category: category)

setvbuf(stdin, nil, _IOLBF, 0)
while let line = readLine(strippingNewline: true) {
    if line.isEmpty { continue }
    os_log("%{public}@", log: log, type: .default, line)   // %@ + Swift String bridges to NSString; %s would expect a C string
}
