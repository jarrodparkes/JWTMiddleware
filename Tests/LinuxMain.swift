import XCTest

@testable import UnitTests

XCTMain([
    testCase(JWTMiddlewareTests.allTests),
    testCase(JWTComposerTests.allTests)
])
