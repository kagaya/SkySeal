# SkySeal Phase 1 protocol

Status: reference implementation baseline
Version: 1.1.0-draft.1
Date: 2026-08-30

This protocol connects a PC-local hash commitment to approval by an
ORCID-bound WebAuthn credential. Original files, paths, descendant names, and
the hash list itself do not cross the PC-to-service boundary. A Drive agent may
send the direct-child root name as transient private inbox metadata. That name
is available only to the authenticated identity, is not signed or published,
and is erased when the transaction is approved or expires.

## 1. Trust boundary

- The PC computes and retains the strict `skyseal-sha256-set-v1` file.
- The service receives only its SHA-256 digest, distinct-hash count, and
  protocol state.
- ORCID OAuth authenticates the researcher's ORCID iD but cannot approve a
  seal by itself.
- A separate User-Verified WebAuthn assertion activates the canonical genesis
  for that ORCID. The public activation proof binds the two.
- A WebAuthn assertion with User Present and User Verified approves the exact
  canonical seal payload.
- The relying-party ID and origin are deployment trust anchors. Bundle values
  are hints and never override configured values.
- Raw credential IDs, user handles, OAuth tokens, transaction bearer tokens,
  and session tokens remain private.

## 2. Browser and nearby-device behavior

The approval application calls the standard WebAuthn API. It does not generate
or interpret a proprietary QR code. For assertion requests, stored authenticator
transports are returned and `hybrid` is added as a browser hint. On a supported
PC/browser, choosing a nearby-device passkey invokes the platform FIDO QR and
Bluetooth proximity flow. On iPhone/iPad, the same request can use the local
passkey directly.

Registration requests use:

```json
{
  "attestation": "none",
  "authenticatorSelection": {
    "residentKey": "preferred",
    "userVerification": "required"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -8}
  ]
}
```

The server parses the returned attestation object, requires `fmt == "none"`,
checks RP ID, challenge, origin, User Present, User Verified, credential ID, and
the COSE public key, and stores the credential ID only in its private database.

## 3. ORCID enrollment

1. `GET /api/v1/orcid/start` creates a one-use OAuth state and redirects to
   ORCID with `response_type=code` and `scope=/authenticate`.
2. `GET /api/v1/orcid/callback` compares both the state cookie and database
   record, exchanges the one-use code at the ORCID token endpoint, validates
   the returned ORCID checksum, discards the access and refresh tokens, and
   creates a short-lived local session.
3. `GET /api/v1/me` returns the authenticated ORCID, display name, enrollment
   state, and a CSRF token. It never returns the session token.

Production redirect URIs and cookies require HTTPS. Mock ORCID login and HTTP
localhost are disabled unless the explicit development setting is active.

## 4. Passkey registration and identity activation

1. `POST /api/v1/webauthn/registration/options` returns a random 32-byte
   challenge and stable private user handle.
2. The browser generates a random 256-bit offline recovery code and sends only
   its domain-separated SHA-256 commitment with the registration result.
3. `POST /api/v1/webauthn/registration/complete` verifies the ceremony and
   stores the private credential routing record.
4. The first credential creates a canonical identity-genesis record. Its
   public form contains the public key but not the raw credential ID.
5. The identity remains `pending_activation` until a second, User-Verified
   Passkey assertion activates that exact genesis.

`POST /api/v1/identity/activation/options` creates a canonical payload with the
ORCID iD, identity version, canonical genesis digest, fixed RP ID, 256-bit
nonce, and creation time. The WebAuthn challenge is:

```text
SHA256(
  UTF8("SkySeal Identity Activation Challenge v1\0") ||
  JCS(identity_activation_payload)
)
```

`POST /api/v1/identity/activation/assertion` requires the same authenticated
ORCID session, verifies the credential owner, RP ID, exact origin, challenge,
User Present, User Verified, and signature, and consumes the challenge once.
It then publishes canonical `identity-activation.json`. The proof contains the
assertion bytes and verification hints, but not the raw credential ID or user
handle. Its canonical SHA-256 digest becomes the identity-state digest used by
later seal payloads.

The canonical records are available from
`GET /api/v1/identity/{orcid}/genesis` and
`GET /api/v1/identity/{orcid}/activation`. The legacy OpenPGP fingerprint field
in an existing draft v1 genesis is optional metadata; no OpenPGP signature is
required by this activation protocol.

## 5. PC seal transaction

### Create

`POST /api/v1/seals` accepts exactly:

```json
{
  "commitment_format": "skyseal-sha256-set-v1",
  "subject_digest": "<64 lowercase hexadecimal SHA-256>",
  "entry_count": 1
}
```

It returns a UUIDv7 `seal_id`, a 256-bit bearer token, a browser approval URL
whose token is in the URL fragment, and a 15-minute expiration. The server logs
only the seal ID and status.

### Approve

An ORCID-authenticated browser sends the bearer token in the Authorization
header and a CSRF token in `X-SkySeal-CSRF` to
`POST /api/v1/seals/{seal_id}/webauthn/options`. The service fixes the identity,
nonce, identity-state digest, and canonical payload, then returns WebAuthn
request options plus a short confirmation code.

`POST /api/v1/seals/{seal_id}/webauthn/assertion` accepts the private raw
credential ID and assertion response, verifies them against the transaction and
credential owner, consumes the challenge exactly once, and creates the public
`.skyseal.json` bundle without the raw ID or user handle.

### Poll

`GET /api/v1/seals/{seal_id}` and
`GET /api/v1/seals/{seal_id}/bundle` require the bearer token in the
Authorization header. They expose no source names or paths.
The authenticated identity-inbox response may expose the transient root display
name while a Drive-agent transaction is pending. Bearer status and bundle
responses never expose it.

## 6. Transaction states

```text
pending -> awaiting_assertion -> approved
   |              |
   +-> expired    +-> invalidated
   +-> rejected
```

A source-side CLI may abandon a transaction at any time. An assertion challenge
expires after five minutes and can be consumed once. A transaction expiry is
deployment-configurable from fifteen minutes through seven days; the reference
deployment uses twenty-four hours. Repeating a byte-identical completed
assertion is idempotent; a different assertion is rejected.

## 7. Phase 1 publication boundary

The reference service produces and returns bundles but does not push them to
GitHub or submit them to OpenTimestamps. Those background workers are Phase 2.
An identity without a verified ORCID-and-Passkey activation cannot approve a
production seal or receive a Drive-agent token. Development bypass is explicit,
visible in the UI and report, and must not be enabled on a public deployment.

## 8. Authoritative references

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [FIDO passkeys and cross-device authentication](https://fidoalliance.org/passkeys/)
- [ORCID authenticated iD tutorial](https://info.orcid.org/documentation/api-tutorials/api-tutorial-get-and-authenticated-orcid-id/)
- [WebAuthn authenticator transport storage](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/getTransports)
