// Read public window metadata only; never request Accessibility/Screen Recording.
import AppKit
import CoreGraphics
import Foundation

guard CommandLine.arguments.count == 2, let process = Int32(CommandLine.arguments[1]) else {
    exit(2)
}
let application = NSRunningApplication(processIdentifier: process)
let raw = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID)
let windows = (raw as? [[String: Any]] ?? []).filter { item in
    guard (item[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == process,
          (item[kCGWindowLayer as String] as? NSNumber)?.intValue == 0,
          let bounds = item[kCGWindowBounds as String] as? [String: Any],
          let width = bounds["Width"] as? NSNumber,
          let height = bounds["Height"] as? NSNumber else { return false }
    return width.doubleValue > 100 && height.doubleValue > 100
}
let result: [String: Any] = [
    "running": application != nil && application?.isTerminated == false,
    "application_name": application?.localizedName ?? "",
    "window_found": !windows.isEmpty,
    "window_id": (windows.first?[kCGWindowNumber as String] as? NSNumber)?.intValue ?? 0,
    "window_name": windows.first?[kCGWindowName as String] as? String ?? "",
    "screen_recording_preapproved": CGPreflightScreenCaptureAccess(),
]
let output = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
FileHandle.standardOutput.write(output)
FileHandle.standardOutput.write(Data([0x0a]))
