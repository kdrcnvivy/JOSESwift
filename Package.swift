// swift-tools-version:5.2
import PackageDescription

let package = Package(
    name: "JOSESwift",
    platforms: [.iOS(.v10), .macOS(.v10_15), .watchOS(.v4)],
    products: [
        .library(name: "JOSESwift", targets: ["JOSESwift"])
    ],
    dependencies: [.package(name: "JOSESwift", url: "https://github.com/kdrcnvivy/JOSESwift.git", from: "2.5.1"),],
    targets: [
        .target(name: "JOSESwift", path: "JOSESwift")
    ],
    swiftLanguageVersions: [.v5])
