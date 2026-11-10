// Native macOS signing helper. One JSON request, one operation, then exit.
//
// A file-based login Keychain is deliberate: data-protection Keychain access
// groups require a provisioning profile, unavailable to this ad-hoc development
// build. No LAContext dialog is used as a substitute for key access control.
// The Security framework enforces an empty trusted-app signing ACL. Both before
// and after each signature we reject an ACL that permits unattended access.
// Selecting "Always Allow" changes that policy and makes this key unusable here.
//
// https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
// https://developer.apple.com/documentation/security/access-control-lists
// https://developer.apple.com/documentation/security/seckeychainpromptselector
import Foundation
import Security

let namespace = "net.excyberlab.skyseal.desktop.macos"
let method = "macos-keychain-p256-v0.1"
let keyPrefix = "skyseal-key-"
let keyLabel = "SkySeal researcher signing key"
let maximumRequestBytes = 16384

struct SignerError: Error {
    let code: String
    let message: String
}

func fail(_ code: String, _ message: String) throws -> Never {
    throw SignerError(code: code, message: message)
}

func check(_ status: OSStatus, _ context: String) throws {
    if status == errSecSuccess { return }
    let code: String
    switch status {
    case errSecUserCanceled: code = "approval_cancelled"
    case errSecAuthFailed: code = "approval_failed"
    case errSecInteractionNotAllowed: code = "approval_unavailable"
    case errSecItemNotFound: code = "signing_key_missing"
    default: code = "macos_keychain_error"
    }
    throw SignerError(code: code, message: "\(context) (Security status \(status))")
}

func securityFailure(_ error: Unmanaged<CFError>?, _ context: String) throws -> Never {
    if let error = error?.takeRetainedValue() {
        try check(OSStatus(CFErrorGetCode(error)), context)
    }
    throw SignerError(code: "macos_keychain_error", message: context)
}

func b64(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

func decodeChallenge(_ text: String) throws -> Data {
    guard text.count == 43, text.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
          let value = Data(base64Encoded: text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "="),
          value.count == 32, b64(value) == text else {
        throw SignerError(code: "invalid_challenge", message: "A canonical 32-byte challenge is required")
    }
    return value
}

func keyTag(_ keyID: String) throws -> Data {
    guard keyID.hasPrefix(keyPrefix),
          String(keyID.dropFirst(keyPrefix.count)).range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else {
        throw SignerError(code: "invalid_key_id", message: "Invalid SkySeal key identifier")
    }
    return Data((namespace + "." + keyID).utf8)
}

func authorizations(_ acl: SecACL) -> Set<String> {
    Set((SecACLCopyAuthorizations(acl) as NSArray).compactMap { $0 as? String })
}

func aclList(_ access: SecAccess) throws -> [SecACL] {
    var raw: CFArray?
    try check(SecAccessCopyACLList(access, &raw), "Cannot inspect Keychain policy")
    guard let raw = raw else { throw SignerError(code: "key_policy_invalid", message: "Keychain policy is missing") }
    return (raw as NSArray).map { unsafeBitCast($0 as AnyObject, to: SecACL.self) }
}

func requirePrompt(_ acl: SecACL) throws {
    var applications: CFArray?
    var description: CFString?
    var selector = SecKeychainPromptSelector(rawValue: 0)
    try check(SecACLCopyContents(acl, &applications, &description, &selector), "Cannot inspect signing permission")
    guard let applications = applications, CFArrayGetCount(applications) == 0,
          selector.contains(.requirePassphase) else {
        let trustedCount = applications.map { String(CFArrayGetCount($0)) } ?? "unrestricted"
        let rights = authorizations(acl).sorted().joined(separator: ",")
        throw SignerError(code: "key_policy_invalid", message: "This key permits unattended access (rights=\(rights), trusted_apps=\(trustedCount), prompt_flags=\(selector.rawValue)). Create a new identity; do not select Always Allow in the Keychain prompt.")
    }
}

func verifyACL(_ access: SecAccess) throws {
    var signingEntries = 0
    var ownerEntries = 0
    for acl in try aclList(access) {
        let rights = authorizations(acl)
        if rights.contains(kSecACLAuthorizationAny as String) {
            throw SignerError(code: "key_policy_invalid", message: "Unrestricted Keychain authorization is not permitted")
        }
        if rights.contains(kSecACLAuthorizationSign as String) {
            guard rights == [kSecACLAuthorizationSign as String] else {
                throw SignerError(code: "key_policy_invalid", message: "Signing authorization must be isolated: \(rights.sorted().joined(separator: ", "))")
            }
            try requirePrompt(acl)
            signingEntries += 1
        }
        if rights.contains(kSecACLAuthorizationChangeACL as String) {
            guard rights == [kSecACLAuthorizationChangeACL as String] else {
                throw SignerError(code: "key_policy_invalid", message: "Policy ownership must be isolated")
            }
            try requirePrompt(acl)
            ownerEntries += 1
        }
        let forbidden: Set<String> = [kSecACLAuthorizationDecrypt as String,
            kSecACLAuthorizationDerive as String, kSecACLAuthorizationExportClear as String,
            kSecACLAuthorizationExportWrapped as String]
        guard rights.isDisjoint(with: forbidden) else {
            throw SignerError(code: "key_policy_invalid", message: "The signing key grants an unexpected private-key operation")
        }
    }
    guard signingEntries == 1, ownerEntries == 1 else {
        throw SignerError(code: "key_policy_invalid", message: "Expected one protected signing policy and one owner policy")
    }
}

func makeACL() throws -> SecAccess {
    var access: SecAccess?
    try check(SecAccessCreate(keyLabel as CFString, [] as CFArray, &access), "Cannot create Keychain policy")
    guard let access = access else { throw SignerError(code: "key_policy_invalid", message: "Missing Keychain access object") }
    for acl in try aclList(access) {
        if authorizations(acl).contains(kSecACLAuthorizationChangeACL as String) {
            // The owner authorization is immutable (errSecInvalidOwnerEdit),
            // even when replacing it with the same CHANGE_ACL value. Require
            // the exact owner right supplied by SecAccessCreate instead.
            guard authorizations(acl) == [kSecACLAuthorizationChangeACL as String] else {
                throw SignerError(code: "key_policy_invalid", message: "Unexpected default policy ownership")
            }
            try check(SecACLSetContents(acl, [] as CFArray, keyLabel as CFString, .requirePassphase), "Cannot protect policy ownership")
        } else {
            // SecACLRemove keeps a deleted entry in the in-memory Access map
            // until persistence. Clear its rights first so subsequent policy
            // inspection cannot mistake its stale tags for a live grant.
            try check(SecACLUpdateAuthorizations(acl, [] as CFArray), "Cannot clear default key permissions")
            try check(SecACLRemove(acl), "Cannot remove default key permissions")
        }
    }
    var signing: SecACL?
    try check(SecACLCreateWithSimpleContents(access, [] as CFArray, keyLabel as CFString, .requirePassphase, &signing), "Cannot create protected signing permission")
    guard let signing = signing else { throw SignerError(code: "key_policy_invalid", message: "Missing signing policy") }
    try check(SecACLUpdateAuthorizations(signing, [kSecACLAuthorizationSign] as CFArray), "Cannot restrict signing permission")
    try verifyACL(access)
    return access
}

func publicJWK(_ key: SecKey) throws -> [String: String] {
    guard let publicKey = SecKeyCopyPublicKey(key) else { throw SignerError(code: "key_invalid", message: "Cannot read public key") }
    var error: Unmanaged<CFError>?
    guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
        try securityFailure(error, "Cannot encode public key")
    }
    guard raw.count == 65, raw.first == 4 else { throw SignerError(code: "key_invalid", message: "Expected a P-256 public key") }
    return ["kty": "EC", "crv": "P-256", "x": b64(raw.subdata(in: 1..<33)), "y": b64(raw.subdata(in: 33..<65))]
}

func verifyKey(_ key: SecKey) throws {
    guard let attributes = SecKeyCopyAttributes(key) as NSDictionary?,
          attributes[kSecAttrIsExtractable] as? Bool == false,
          attributes[kSecAttrKeySizeInBits] as? Int == 256 else {
        throw SignerError(code: "key_policy_invalid", message: "The key is not a nonextractable P-256 key")
    }
    // The legacy Security API represents a persistent SecKey as a keychain item.
    let item = unsafeBitCast(key, to: SecKeychainItem.self)
    var access: SecAccess?
    try check(SecKeychainItemCopyAccess(item, &access), "Cannot inspect stored key policy")
    guard let access = access else { throw SignerError(code: "key_policy_invalid", message: "Stored key has no access policy") }
    try verifyACL(access)
    _ = try publicJWK(key)
}

func currentUserKeychain() throws -> SecKeychain {
    var keychain: SecKeychain?
    try check(SecKeychainCopyDefault(&keychain), "Open or create your user Keychain before registering")
    guard let keychain = keychain else { throw SignerError(code: "keychain_unavailable", message: "No default user Keychain is available") }
    var length: UInt32 = 4096
    var buffer = [CChar](repeating: 0, count: Int(length))
    try check(SecKeychainGetPath(keychain, &length, &buffer), "Cannot locate the default user Keychain")
    let path = URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath().standardizedFileURL.path
    let home = FileManager.default.homeDirectoryForCurrentUser.resolvingSymlinksInPath().standardizedFileURL.path
    guard path.hasPrefix(home + "/Library/Keychains/") else {
        throw SignerError(code: "keychain_scope_invalid", message: "SkySeal requires a Keychain inside your user Library/Keychains folder")
    }
    return keychain
}

func lookup(_ keyID: String, in explicitKeychain: SecKeychain? = nil) throws -> SecKey {
    var value: CFTypeRef?
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: try keyTag(keyID),
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecMatchSearchList as String: [try explicitKeychain ?? currentUserKeychain()],
        kSecUseDataProtectionKeychain as String: false,
        kSecReturnRef as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
    try check(SecItemCopyMatching(query as CFDictionary, &value), "Cannot find the SkySeal signing key")
    guard let value = value, CFGetTypeID(value) == SecKeyGetTypeID() else {
        throw SignerError(code: "key_invalid", message: "Keychain returned an invalid key")
    }
    let key = unsafeBitCast(value, to: SecKey.self)
    try verifyKey(key)
    return key
}

func createProtectedKey(_ keyID: String, in keychain: SecKeychain) throws -> SecKey {
    let access = try makeACL()
    let privateAttributes: [String: Any] = [kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: try keyTag(keyID),
        kSecAttrLabel as String: keyLabel]
    // A later process resolves SecKeyCopyPublicKey through the matching public
    // Keychain item; the generator's in-memory public-key cache does not persist.
    let publicAttributes: [String: Any] = [kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: try keyTag(keyID),
        kSecAttrLabel as String: keyLabel + " (public)"]
    // The legacy CDSA generator reads Access and IsExtractable from the outer
    // dictionary, unlike persistence/tag fields that accept private overrides.
    // Public keys remain extractable; this flag restricts the private key.
    let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256, kSecPrivateKeyAttrs as String: privateAttributes,
        kSecPublicKeyAttrs as String: publicAttributes,
        kSecAttrAccess as String: access, kSecAttrIsExtractable as String: false,
        kSecUseKeychain as String: keychain, kSecUseDataProtectionKeychain as String: false]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        try securityFailure(error, "Cannot create a protected SkySeal key")
    }
    try verifyKey(key)
    return key
}

func register() throws -> [String: Any] {
    let keyID = keyPrefix + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    let key = try createProtectedKey(keyID, in: currentUserKeychain())
    // Prove that persistence retained the requested policy. The activation
    // signature is a separate helper invocation so creation cannot authorize it.
    let stored = try lookup(keyID)
    let jwk = try publicJWK(stored)
    guard jwk == (try publicJWK(key)) else { throw SignerError(code: "key_invalid", message: "Stored public key differs from the generated key") }
    return ["key_id": keyID, "algorithm": -7, "public_key": jwk,
            "method": method, "key_storage": "login-keychain-nonextractable",
            "approval_policy": "password-per-signature", "hardware_attested": false]
}

func sign(_ keyID: String, _ challenge: Data) throws -> [String: Any] {
    let key = try lookup(keyID)
    guard SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else {
        throw SignerError(code: "algorithm_unavailable", message: "P-256 signing is unavailable")
    }
    var error: Unmanaged<CFError>?
    // The OS prompts here while authorizing use of this protected key. There is
    // no separately evaluated UI result and no unprotected signing fallback.
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, challenge as CFData, &error) as Data? else {
        try securityFailure(error, "The signing operation was not approved")
    }
    try verifyKey(key)
    _ = try lookup(keyID) // fresh persisted ACL also rejects "Always Allow"
    guard let publicKey = SecKeyCopyPublicKey(key),
          SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256, challenge as CFData, signature as CFData, &error) else {
        try securityFailure(error, "Native signature verification failed")
    }
    return ["method": method, "signature": b64(signature)]
}

func status() -> [String: Any] {
    do {
        _ = try currentUserKeychain()
        return ["available": true,
            "backend": "macos-keychain", "approval_method": method,
            "keychain_password_required": true, "hardware_attested": false,
            "reason": "macOS Keychain password approval; Touch ID is not required"]
    } catch let error as SignerError {
        return ["available": false, "backend": "macos-keychain", "approval_method": method,
                "keychain_password_required": true, "hardware_attested": false,
                "reason": error.message, "error_code": error.code]
    } catch {
        return ["available": false, "backend": "macos-keychain", "approval_method": method,
                "reason": "A default user Keychain is required"]
    }
}

func selfTest() throws -> [String: Any] {
    let access = try makeACL()
    try verifyACL(access)
    let activeRights = try aclList(access).map { authorizations($0) }.filter { !$0.isEmpty }
    guard activeRights.count == 2,
          activeRights.contains([kSecACLAuthorizationSign as String]),
          activeRights.contains([kSecACLAuthorizationChangeACL as String]) else {
        throw SignerError(code: "self_test_failed", message: "Fresh policy must grant only isolated signing and policy ownership")
    }
    var rejectedPermissivePolicy = false
    for acl in try aclList(access) where authorizations(acl).contains(kSecACLAuthorizationSign as String) {
        try check(SecACLSetContents(acl, nil, keyLabel as CFString, []), "Cannot prepare policy rejection check")
    }
    do { try verifyACL(access) } catch { rejectedPermissivePolicy = true }
    guard rejectedPermissivePolicy else { throw SignerError(code: "self_test_failed", message: "Permissive ACL was accepted") }
    var error: Unmanaged<CFError>?
    // This ephemeral key is used only inside this no-authentication diagnostic.
    // Neither its private key, public key, nor signature is returned to callers.
    let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256]
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
          let publicKey = SecKeyCopyPublicKey(key) else { try securityFailure(error, "Diagnostic key creation failed") }
    let challenge = Data(repeating: 0x53, count: 32)
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, challenge as CFData, &error),
          SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256, challenge as CFData, signature, &error) else {
        try securityFailure(error, "Diagnostic signature round-trip failed")
    }
    let changed = Data(repeating: 0x54, count: 32)
    guard !SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256, changed as CFData, signature, &error) else {
        throw SignerError(code: "self_test_failed", message: "Changed challenge was accepted")
    }
    if let error = error { _ = error.takeRetainedValue() }
    return ["ok": true, "method": method, "acl_policy_checked": true,
            "isolated_sign_and_owner": true,
            "permissive_acl_rejected": true, "signature_roundtrip": true,
            "changed_challenge_rejected": true, "persistent_keys_created": false,
            "user_approval_tested": false]
}

func emit(_ result: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
}

#if SKYSEAL_NATIVE_TESTS
// This code is absent from the distributed signer. It tests the exact stored
// policy against macOS Security without touching the user's existing keys.
func keychainPath(_ keychain: SecKeychain) throws -> String {
    var length: UInt32 = 4096
    var buffer = [CChar](repeating: 0, count: Int(length))
    try check(SecKeychainGetPath(keychain, &length, &buffer), "Cannot read test Keychain path")
    return URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath().path
}

func keychainConfiguration() throws -> [String] {
    var list: CFArray?
    try check(SecKeychainCopySearchList(&list), "Cannot inspect Keychain search configuration")
    var configuration = try ((list ?? [] as CFArray) as NSArray).map {
        try keychainPath(unsafeBitCast($0 as AnyObject, to: SecKeychain.self))
    }
    var defaultKeychain: SecKeychain?
    let status = SecKeychainCopyDefault(&defaultKeychain)
    configuration.append("DEFAULT:" + (try defaultKeychain.map { try keychainPath($0) } ?? "status:\(status)"))
    return configuration
}

func policyProbe(path: String, keyID: String) throws -> [String: Any] {
    try check(SecKeychainSetUserInteractionAllowed(false), "Cannot disable test user interaction")
    var keychain: SecKeychain?
    try path.withCString { try check(SecKeychainOpen($0, &keychain), "Cannot open isolated test Keychain") }
    guard let keychain = keychain else { throw SignerError(code: "self_test_failed", message: "Missing test Keychain") }
    var keychainStatus: SecKeychainStatus = 0
    try check(SecKeychainGetStatus(keychain, &keychainStatus), "Cannot inspect isolated Keychain lock state")
    guard keychainStatus & kSecUnlockStateStatus != 0 else {
        throw SignerError(code: "self_test_failed", message: "Test Keychain must be unlocked so rejection proves the signing ACL")
    }
    let key = try lookup(keyID, in: keychain)
    guard SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else {
        throw SignerError(code: "self_test_failed", message: "Stored test key cannot sign P-256")
    }
    var error: Unmanaged<CFError>?
    let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
        Data(repeating: 0x53, count: 32) as CFData, &error)
    guard signature == nil, let detail = error?.takeRetainedValue() else {
        throw SignerError(code: "self_test_failed", message: "Protected key signed without OS authorization")
    }
    let status = OSStatus(CFErrorGetCode(detail))
    try check(SecKeychainGetStatus(keychain, &keychainStatus), "Cannot recheck isolated Keychain lock state")
    guard keychainStatus & kSecUnlockStateStatus != 0 else {
        throw SignerError(code: "self_test_failed", message: "Test Keychain became locked during the signing check")
    }
    guard status == errSecInteractionNotAllowed || status == errSecAuthFailed else {
        throw SignerError(code: "self_test_failed", message: "Signing failed for a reason other than missing authorization (\(status))")
    }
    return ["ok": true, "stored_acl_verified": true, "nonextractable_verified": true,
            "unapproved_signing_rejected": true, "native_rejection_status": Int(status)]
}

func persistentPolicySelfTest() throws -> [String: Any] {
    try check(SecKeychainSetUserInteractionAllowed(false), "Cannot disable test user interaction")
    let configurationBefore = try keychainConfiguration()
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("skyseal-key-policy-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    // Apple's StorageManager adds only System.keychain and paths containing
    // /login.keychain to the search list; a private temporary name avoids that.
    let path = directory.appendingPathComponent("policy-test.keychain").path
    var password = Data(count: 32)
    let randomStatus = password.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
    try check(randomStatus, "Cannot create a private test Keychain password")
    var keychain: SecKeychain?
    var deleted = false
    defer {
        if !deleted, let keychain = keychain { _ = SecKeychainDelete(keychain) }
        try? FileManager.default.removeItem(at: directory)
        password.resetBytes(in: 0..<password.count)
    }
    try path.withCString { cPath in
        try password.withUnsafeBytes { bytes in
            try check(SecKeychainCreate(cPath, UInt32(bytes.count), bytes.baseAddress, false, nil, &keychain), "Cannot create isolated test Keychain")
        }
    }
    guard let keychain = keychain else { throw SignerError(code: "self_test_failed", message: "Test Keychain was not created") }
    try password.withUnsafeBytes {
        try check(SecKeychainUnlock(keychain, UInt32($0.count), $0.baseAddress, true), "Cannot unlock private test Keychain")
    }
    let keyID = keyPrefix + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    _ = try createProtectedKey(keyID, in: keychain)
    _ = try lookup(keyID, in: keychain)
    let task = Process()
    task.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    task.arguments = ["--keychain-policy-probe", path, keyID]
    task.standardInput = FileHandle.nullDevice
    let output = Pipe()
    task.standardOutput = output
    task.standardError = FileHandle.nullDevice
    try task.run()
    let deadline = Date().addingTimeInterval(20)
    while task.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
    if task.isRunning {
        task.terminate()
        throw SignerError(code: "self_test_failed", message: "Isolated policy probe exceeded its time limit")
    }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    guard data.count < maximumRequestBytes,
          let response = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          response["ok"] as? Bool == true, response["unapproved_signing_rejected"] as? Bool == true,
          task.terminationStatus == 0 else {
        // The child never returns credentials, private material, or paths.
        let message = String(data: data, encoding: .utf8) ?? "no result"
        throw SignerError(code: "self_test_failed", message: "Stored-key authorization probe failed: " + String(message.prefix(1000)))
    }
    try check(SecKeychainDelete(keychain), "Cannot delete private test Keychain")
    deleted = true
    guard try keychainConfiguration() == configurationBefore else {
        throw SignerError(code: "self_test_failed", message: "Isolated test unexpectedly changed the default Keychain or search list")
    }
    return ["ok": true, "stored_acl_verified": true, "nonextractable_verified": true,
            "fresh_process_unapproved_signing_rejected": true, "temporary_keychain_deleted": true,
            "user_keychain_configuration_unchanged": true, "user_approval_tested": false]
}
#endif

do {
    #if SKYSEAL_NATIVE_TESTS
    if CommandLine.arguments.dropFirst().elementsEqual(["--keychain-policy-self-test"]) {
        emit(try persistentPolicySelfTest())
        exit(0)
    }
    if CommandLine.arguments.count == 4, CommandLine.arguments[1] == "--keychain-policy-probe" {
        emit(try policyProbe(path: CommandLine.arguments[2], keyID: CommandLine.arguments[3]))
        exit(0)
    }
    #endif
    if CommandLine.arguments.dropFirst().elementsEqual(["--self-test"]) {
        emit(try selfTest())
    } else {
        guard CommandLine.arguments.count == 1 else { throw SignerError(code: "invalid_request", message: "Unexpected arguments") }
        let data = FileHandle.standardInput.readData(ofLength: maximumRequestBytes + 1)
        guard data.count <= maximumRequestBytes,
              let request = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let operation = request["op"] as? String else {
            throw SignerError(code: "invalid_request", message: "Invalid native signing request")
        }
        let result: [String: Any]
        switch operation {
        case "status":
            guard Set(request.keys) == ["op"] else { throw SignerError(code: "invalid_request", message: "Unexpected status fields") }
            result = status()
        case "register":
            guard Set(request.keys) == ["op"] else { throw SignerError(code: "invalid_request", message: "Unexpected registration fields") }
            result = try register()
        case "sign":
            guard Set(request.keys) == ["op", "key_id", "challenge"],
                  let keyID = request["key_id"] as? String,
                  let challenge = request["challenge"] as? String else { throw SignerError(code: "invalid_request", message: "Invalid signing fields") }
            result = try sign(keyID, decodeChallenge(challenge))
        default: throw SignerError(code: "invalid_request", message: "Unsupported native signing operation")
        }
        emit(["ok": true, "result": result])
    }
} catch let error as SignerError {
    emit(["ok": false, "error": ["code": error.code, "message": error.message]])
    exit(1)
} catch {
    emit(["ok": false, "error": ["code": "invalid_request", "message": "The native signing request could not be processed"]])
    exit(1)
}
