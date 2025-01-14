// swift-tools-version:5.2
import PackageDescription

let package = Package(
    name: "JOSESwift",
    platforms: [.iOS(.v10), .macOS(.v10_15), .watchOS(.v4)],
    products: [
        .library(name: "JOSESwift", targets: ["JOSESwift"])
    ],
    dependencies: [.package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMajor(from: "1.5.1"))],
    targets: [
        .target(name: "JOSESwift", dependencies: ["CryptoSwift"], path: "JOSESwift")
    ],
    swiftLanguageVersions: [.v5])
