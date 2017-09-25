import XCTest

@testable import PerfectCrypto
@testable import JWTMiddleware

class JWTComposerTests: XCTestCase {

    // MARK: Properties

    let privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEArS1xqfQwxYJ0GyrRCstVtdmLhtEqMD6JOeDQq0Hu+y7md4dvbZIO/AugS/afhHcdnarpQRzhmrJVK5LQT9I+JhScX7/VaFxrEHffJ3cPKScOoO5Q6qItaYpVrmbhf/iFmUgdaNmc9VdEcUhldOjqQIDCt2aUSxvDl+RPgFh8qJJ1DSzszi7gxBXnARStknn8ffAYRjLGlJTQmZT26xvkVnxVfNcZbnmkWN54ZDa2/9ZGvl2AtE5Ati9rFyvs9U961N0oWV3PfpOkhcibQARbetFx0a+lucnIzfPUpdIwQd75ceaRLIshls3C+I4KllEgU3FxXyOhiytSsYSYJ2L2tQIDAQABAoIBAB7+QBZrloLyqvblvc3RwEAwc/En5AYIWyTZoF7WCQA5T5Pa0E1q03W2WvTdaYUakFlUajR2B8ZY3jdTKibu+KJ2E9prCbWIvLyQx4ZXn4X88HhKzn5/keMOl/EDhp4Ri094gZLvR1D9Ukl37Hh06t+qa67JFAcxK9s2SCgvLfg5Gozx8KTG2Pe4vZllkHQXibNvfJogiyv7899lqe+h3nVSQtKbLkwj+rbYK6jPs3T2FaeGfuEgd3oHxORCUY3xrDrD3ouEsedtK5Wj6W4hs0zYVLDglfuRBOpCVuOLaVnXmE2cZXrQMJSA+rr89ZmwQtRuSvwjMZ3gfCEmhwJFnC0CgYEA1MnglknWv5aOUMqCLOvDheB7zBb7NSWxnPkl5Pig3HEwtB/pIc9rMCcynl6T/FCzIiLPiRYivGMTa7MnRNlrk1XfOGEyg9lzd0AJ1xbeW7DIA45nbDqzUOnmmIcuoNwKCsUulKGEhpxAkuO9TzLTT12AjGMlCWn2WZ0Yh63YKIsCgYEA0FhT9tvVvsXRVKTmfkIBs/KHZQ2OzRKgETiNEuxDrXGOlxBc7xog7Au3zSqwUjWTOqkgkLchtCgr+ePOZpSxjB8xxJeaxlPjBPw+0bxXfd4U1YpBSXK2VcU0plm84YCoS2NYbeHWAvczK9kEqmTIQRa+P56NbjjG7McZZ6c2Bb8CgYEAsmNj8tqIPCnduYFsTHiCfBPL9Tc29kFZe32r9R8yzFvgNsGh0oRvGfliiD5F1ftZkb6ZOhXinQh6WYnh2+hiNSyCbGOf08VS9aAsH7O+SiQUKlcSATvc5HKSrUB3KMgPayQPfu9BiRApWnuuU10Kpbh/cjIT9KZuroXy8JwfYS0CgYBMXFNJ4wDQTwiOEXI5TE/7eCSPsQxptS3dofByww17AGfWjjTBnb37RcAz/jVprCEuGtbIs5YyxZZ4nDoF9vGr/bLr7vTXQ9+s8BbGIFWg2Eiii22qUdTqUsEdRz6nF9SW7O54N5GMvLWQmJXRLecHlCJehuonP8AJAGAbUXnHWQKBgQCnjCHPw050qAbq7CZ8FXvI+TQYVTISrp1YeuzSI4xboa/NjVfaXptoX9JTkw0ZyQl9eux0L7QkhRSAdasGqdnVtYiONAmNBvJw2n5eTbAW9ckzbeFu5ZPNQ95Q4as8ST4HBx9Am+gs+HJwcZZg8gU9DT1uPTL7m8cetj3nHPxLgA==\n-----END RSA PRIVATE KEY-----"
    let publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArS1xqfQwxYJ0GyrRCstVtdmLhtEqMD6JOeDQq0Hu+y7md4dvbZIO/AugS/afhHcdnarpQRzhmrJVK5LQT9I+JhScX7/VaFxrEHffJ3cPKScOoO5Q6qItaYpVrmbhf/iFmUgdaNmc9VdEcUhldOjqQIDCt2aUSxvDl+RPgFh8qJJ1DSzszi7gxBXnARStknn8ffAYRjLGlJTQmZT26xvkVnxVfNcZbnmkWN54ZDa2/9ZGvl2AtE5Ati9rFyvs9U961N0oWV3PfpOkhcibQARbetFx0a+lucnIzfPUpdIwQd75ceaRLIshls3C+I4KllEgU3FxXyOhiytSsYSYJ2L2tQIDAQAB\n-----END PUBLIC KEY-----"
    var composer: JWTComposer!
    var validToken: String!
    var invalidToken: String!

    // MARK: Setup

    public override func setUp() {
        super.setUp()

        composer = JWTComposer(privateKey: privateKey, publicKey: publicKey, algorithm: .rs256)

        validToken = try! composer.createSignedTokenWithPayload([
            "author": "jarrod",
            "sub": "middleware",
            "iss": "http://jarrodparkes.com",
            "exp": Date().timeIntervalSince1970 + (60 * 60) /* expires in 1 hour */
        ])

        invalidToken = try! composer.createSignedTokenWithPayload([
            "author": "james",
            "sub": "invalid",
            "iss": "http://example.com",
            "exp": Date().timeIntervalSince1970
        ])
    }

    // MARK: Tests

    func testCreateTokenString() {
        let jwtComposer = JWTComposer(privateKey: privateKey, publicKey: nil, algorithm: .rs256)
        var token: String? = nil

        do {
            token = try jwtComposer.createSignedTokenWithPayload([:])
        } catch {}

        XCTAssertNotNil(token, "Token creation failed.")
    }

    func testCreateTokenWithInvalidPrivateKeyThrows() {
        let jwtComposer = JWTComposer(privateKey: "", publicKey: nil, algorithm: .rs256)
        var signingError = false

        do {
            let _ = try jwtComposer.createSignedTokenWithPayload([:])
        } catch JWTError.cannotSignJWT {
            signingError = true
        } catch {}

        XCTAssertNotNil(signingError, "Catch signingError failed.")
    }

    func testCreateTokenStringWithoutPrivateKeyThrows() {
        let jwtComposer = JWTComposer(privateKey: nil, publicKey: nil, algorithm: .rs256)
        var missingPrivateKey = false

        do {
            let _ = try jwtComposer.createSignedTokenWithPayload([:])
        } catch JWTError.missingPrivateKey {
            missingPrivateKey = true
        } catch {}

        XCTAssertTrue(missingPrivateKey, "Catch missingPrivateKey failed.")
    }

    func testGetJWTVerifier() {
        let jwtComposer = JWTComposer(privateKey: nil, publicKey: nil, algorithm: .rs256)

        do {
            let _ = try jwtComposer.getJWTVerifierWithSignedToken(validToken)
        } catch {
            XCTAssertTrue(true, "Failed to get a JWTVerifier.")
        }
    }

    func testVerifyTokenWithoutPublicKeyThrows() {
        let jwtComposer = JWTComposer(privateKey: privateKey, publicKey: nil, algorithm: .rs256)
        var missingPublicKey = false

        do {
            let verifier = try jwtComposer.getJWTVerifierWithSignedToken(validToken)
            try jwtComposer.verifyAlgorithmAndKeyForJWT(verifier)
        } catch JWTError.missingPublicKey {
            missingPublicKey = true
        } catch {}

        XCTAssertTrue(missingPublicKey, "Catch missingPublicKey failed.")
    }

    func testVerifyTokenWithWrongAlgThrows() {
        let jwtComposer = JWTComposer(privateKey: privateKey, publicKey: publicKey, algorithm: .rs512)
        var cannotVerifyAlgAndKey = false

        do {
            let verifier = try jwtComposer.getJWTVerifierWithSignedToken(validToken)
            try jwtComposer.verifyAlgorithmAndKeyForJWT(verifier)
        } catch JWTError.cannotVerifyAlgAndKey {
            cannotVerifyAlgAndKey = true
        } catch {}

        XCTAssertTrue(cannotVerifyAlgAndKey, "Catch cannotVerifyAlgAndKey failed.")
    }

    func testVerifyTokenWithInvalidIssuerClaim() {
        var invalidPayload = false

        do {
            let verifier = try composer.getJWTVerifierWithSignedToken(invalidToken)
            try composer.verifyReservedClaimsForJWT(verifier, iss: "http://jarrodparkes.com", sub: "middleware")
        } catch JWTError.invalidPayload(let message) {
            XCTAssertEqual(message, "JWT iss claim is invalid")
            invalidPayload = true
        } catch {}

        XCTAssertTrue(invalidPayload, "Catch invalidPayload failed.")
    }

    func testVerifyTokenWithInvalidSubjectClaim() {
        var invalidPayload = false

        do {
            let verifier = try composer.getJWTVerifierWithSignedToken(invalidToken)
            try composer.verifyReservedClaimsForJWT(verifier, iss: "http://example.com", sub: "middleware")
        } catch JWTError.invalidPayload(let message) {
            XCTAssertEqual(message, "JWT sub claim is invalid")
            invalidPayload = true
        } catch {}

        XCTAssertTrue(invalidPayload, "Catch invalidPayload failed.")
    }

    func testVerifyTokenWithInvalidExpirationClaim() {
        var invalidPayload = false

        do {
            let verifier = try composer.getJWTVerifierWithSignedToken(invalidToken)
            try composer.verifyReservedClaimsForJWT(verifier, iss: "http://example.com", sub: "invalid")
        } catch JWTError.invalidPayload(let message) {
            XCTAssertEqual(message, "JWT has expired")
            invalidPayload = true
        } catch {}

        XCTAssertTrue(invalidPayload, "Catch invalidPayload failed.")
    }

    func testVerifyTokenWithInvalidCustomClaim() {
        var invalidPayload = false

        do {
            let verifier = try composer.getJWTVerifierWithSignedToken(invalidToken)
            try composer.invalidPrivateClaimsForJWT(verifier) { payload in
                guard let author = payload["author"] as? String, author == "jarrod" else {
                    return ["author"]
                }
                return []
            }
        } catch JWTError.invalidPayload(let message) {
            XCTAssertEqual(message, "JWT private claims are invalid: [\"author\"]")
            invalidPayload = true
        } catch {}

        XCTAssertTrue(invalidPayload, "Catch invalidPayload failed.")
    }

    func testVerifyTokenWithValidReservedClaims() {
        var tokenIsValid = true

        do {
            let verifier = try composer.getJWTVerifierWithSignedToken(validToken)
            try composer.verifyReservedClaimsForJWT(verifier, iss: "http://jarrodparkes.com", sub: "middleware")
        } catch {
            tokenIsValid = false
        }

        XCTAssertTrue(tokenIsValid, "Token should be valid.")
    }

    func testVerifyTokenWithAllValidClaims() {
        var tokenIsValid = true

        do {
            let verifier = try composer.getJWTVerifierWithSignedToken(validToken)
            try composer.verifyReservedClaimsForJWT(verifier, iss: "http://jarrodparkes.com", sub: "middleware")
            try composer.invalidPrivateClaimsForJWT(verifier) { payload in
                guard let author = payload["author"] as? String, author == "jarrod" else {
                    return ["author"]
                }
                return []
            }
        } catch {
            tokenIsValid = false
        }

        XCTAssertTrue(tokenIsValid, "Token should be valid.")
    }
}

#if os(Linux)
extension JWTComposerTests {
    static var allTests = [
        ("testCreateTokenString", testCreateTokenString),
        ("testCreateTokenWithInvalidPrivateKeyThrows", testCreateTokenWithInvalidPrivateKeyThrows),
        ("testCreateTokenStringWithoutPrivateKeyThrows", testCreateTokenStringWithoutPrivateKeyThrows),
        ("testGetJWTVerifier", testGetJWTVerifier),
        ("testVerifyTokenWithoutPublicKeyThrows", testVerifyTokenWithoutPublicKeyThrows),
        ("testVerifyTokenWithWrongAlgThrows", testVerifyTokenWithWrongAlgThrows),
        ("testVerifyTokenWithInvalidIssuerClaim", testVerifyTokenWithInvalidIssuerClaim),
        ("testVerifyTokenWithInvalidSubjectClaim", testVerifyTokenWithInvalidSubjectClaim),
        ("testVerifyTokenWithInvalidExpirationClaim", testVerifyTokenWithInvalidExpirationClaim),
        ("testVerifyTokenWithInvalidCustomClaim", testVerifyTokenWithInvalidCustomClaim),
        ("testVerifyTokenWithValidReservedClaims", testVerifyTokenWithValidReservedClaims),
        ("testVerifyTokenWithAllValidClaims", testVerifyTokenWithAllValidClaims)
    ]
}
#endif
