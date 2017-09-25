// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "JWTMiddleware",
    targets: [
        Target(name: "JWTMiddleware"),
        Target(name: "UnitTests", dependencies: ["JWTMiddleware"]),
    ],
    dependencies: [
        .Package(url: "https://github.com/IBM-Swift/Kitura.git", majorVersion: 1, minor: 7),
        .Package(url: "https://github.com/IBM-Swift/HeliumLogger.git", majorVersion: 1, minor: 7),
        .Package(url: "https://github.com/PerfectlySoft/Perfect-Crypto.git", majorVersion: 1)
    ]    
)
