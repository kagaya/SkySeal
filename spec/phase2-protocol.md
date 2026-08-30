# SkySeal Phase 2 Drive and publication protocol

Status: reference implementation baseline
Version: 1.1.0-draft.1
Date: 2026-08-30

Phase 2 turns a completed upload in a private Google Drive inbox into a
hash-only approval request and, after WebAuthn approval, a timestamped public
evidence package. It does not make WebAuthn approval unattended: the final user
gesture and user verification remain mandatory.

## 1. Components and trust boundary

The Drive agent is a separate private process. It may read the monitored Drive
folder, raw bytes, private Drive IDs, and private SkySeal transaction bearers.
With the optional owner ledger enabled, it also reads only the root sealing
unit's display name and writes a salted private receipt to one explicitly
shared Google Sheet. The public SkySeal service receives the strict hash-list
digest, distinct hash count, protocol state, and only the receipt commitment.
GitHub and OpenTimestamps receive only public artifacts.

The recommended Google identity is a dedicated service account. Only the inbox
folder is shared read-only with that address. Domain-wide delegation is not
required and should not be enabled.

The hashing inventory's Drive API field mask intentionally omits `name`.
Names are not needed for hashing. If the owner ledger is enabled, a separate
metadata request obtains the direct-child root name solely for the private
receipt; descendants' names and the file-to-hash mapping remain absent.

### 1.1 Optional owner-only ledger

The owner creates a Google Sheet, keeps it non-public, and shares only that
Sheet as Editor with the dedicated service account. The inbox remains Viewer.
The service account requests Drive-readonly and Sheets scopes, while Google
resource sharing limits access to the explicitly shared resources.

Before seal creation the agent constructs
`urn:skyseal:private-ledger-receipt:v1` containing the root Drive ID, current
display name and link, root MIME type, private snapshot digest, public subject
digest, distinct entry count, and a random 256-bit salt. SHA-256 over its JCS
bytes becomes `seal_payload.private_ledger_commitment`; therefore the user's
Passkey signs the private/public correspondence without publishing it.

After local publication the Sheet row is appended idempotently. It includes
the Seal ID, public proof URL, and exact receipt JSON. A Sheets failure leaves
`ledger_status=pending` in the private agent database and is retried; it does
not remove VPS evidence or block the independent GitHub mirror.

## 2. Sealing units and upload stability

Each direct child of the configured inbox folder is one sealing unit:

- a binary or supported Google Workspace file is a one-member unit;
- a folder is traversed recursively and all non-folder descendants form one
  unit;
- shortcuts are rejected;
- an empty folder is observed but not submitted.

The private snapshot fingerprint covers Drive IDs, MIME types, revision or
modification state, sizes, checksums, and parent IDs. It never enters a public
artifact. A unit becomes eligible only after that fingerprint has remained
unchanged for the configured settle interval. A later revision creates a new
seal rather than replacing the old seal.

## 3. Content hashing

Binary Drive files are streamed through local SHA-256. When Drive supplies
`sha256Checksum`, the independently computed digest must match it.

Google Workspace files are exported before hashing:

| Source type | Hashed export |
|---|---|
| Google Docs | PDF |
| Google Sheets | XLSX |
| Google Slides | PDF |
| Google Drawings | PDF |

The resulting digest commits to the exact export bytes, not an abstract editor
document. The agent retains the private revision mapping needed to reproduce
the export. The ordinary `files.export` API is limited to 10 MB; larger or
unsupported native items must be saved as ordinary Drive files before they can
be processed by this reference agent.

All member digests are sorted and deduplicated into the strict
`skyseal-sha256-set-v1` byte format. Names, ordering, topology, and multiplicity
are deliberately absent.

## 4. Identity-bound agent authorization

An operator creates a random 256-bit Drive-agent token only after the ORCID
identity has an active User-Verified Passkey proof. The service stores only the
SHA-256 token hash. The token is displayed once and stored in a mode-600 file
on the agent host.

The agent creates a seal with `Authorization: SkySeal-Agent <token>`. The
service pre-binds the transaction to that ORCID and returns a separate 256-bit
bearer for private status polling and artifact retrieval.

An ORCID-authenticated PWA obtains the researcher's pending Drive transactions
from `GET /api/v1/seals/pending`. The list exposes only seal ID, time, distinct
hash count, state, and expiration. WebAuthn options and assertions can then be
authorized by the identity session without copying the private agent bearer to
the phone.

## 5. Approval and retrieval

The iPhone, iPad, or PC browser performs the Phase 1 WebAuthn assertion. After
approval, the Drive agent uses its transaction bearer to retrieve:

- the strict public hash list;
- the WebAuthn bundle;
- the identity genesis;
- the ORCID-bound Passkey identity activation.

Before publication, the agent independently verifies the hash-list commitment,
WebAuthn signature, trusted RP ID and origin, identity digest, and pinned
identity-activation signature.

## 6. Timestamping and public package

OpenTimestamps stamps the exact WebAuthn bundle and the exact
`identity-activation.json`. The initial proof can remain pending until Bitcoin
confirmation. A later `upgrade` operation replaces only the `.ots` proof and
the manifest that records its digest.

VPS and GitHub paths are derived only from the public creation month and random UUIDv7:

```text
evidence/YYYY/MM/<seal-id>/
  hashes.txt
  seal.skyseal.json
  seal.skyseal.json.ots
  identity-genesis.json
  identity-activation.json
  identity-activation.json.ots
  manifest.json
```

`manifest.json` uses `urn:skyseal:publication-manifest:v2`. The complete package
is written atomically to the VPS public root first. It then appears through
`/proofs/` and `/evidence/` independently of GitHub. The same bytes are mirrored
to GitHub with the manifest uploaded last.
It contains SHA-256 digests of every other artifact and the two proof-to-target
relationships. Publication is idempotent:
identical existing files are accepted, different evidence files are never
overwritten, and only `.ots` proofs plus their manifest may be updated.

## 7. Privacy properties and limits

Public artifacts contain no source name, folder name, path, Drive ID, revision
ID, MIME type, size, or file-to-hash mapping. The private SQLite database does
contain Drive IDs, hash lists, bearer tokens, and the correspondence between a
Drive unit and its seal; it must be protected and excluded from backups that do
not meet the same confidentiality standard.

The public hash set permits known-candidate membership tests. Publication also
reveals ORCID, distinct-hash count, and approximate processing time.
OpenTimestamps calendar submissions can reveal timing and network metadata and
can make closely timed submissions correlatable. These are explicit v1 limits.

The optional Sheet is “owner-only” at the application-sharing level, not an
end-to-end encrypted vault: the owner, the explicitly shared service account,
and administrators able to control that account or VPS root can technically
read it. A third-party auditor receives a selected receipt only when the owner
chooses to disclose it.

## 8. Failure and recovery

- A changing unit returns to the settling state.
- A checksum mismatch prevents submission.
- Expired, rejected, or invalidated approvals become private error records.
- Timestamp proofs are stored privately and the complete public package is
  persisted on the VPS before GitHub mirroring.
- A GitHub failure does not undo local publication. Mirror state remains
  pending and is retried without creating a different proof.
- GitHub files are written serially; the final manifest signals a complete
  package.
- Raw Drive data is streamed and is never written into the public staging
  directory.

## 9. Authoritative references

- [Google Drive changes and polling](https://developers.google.com/workspace/drive/api/guides/manage-changes)
- [Google Drive file checksums](https://developers.google.com/workspace/drive/api/reference/rest/v3/files)
- [Google Drive downloads and exports](https://developers.google.com/workspace/drive/api/guides/manage-downloads)
- [Google service-account OAuth](https://developers.google.com/identity/protocols/oauth2/service-account)
- [GitHub repository contents API](https://docs.github.com/en/rest/repos/contents)
- [OpenTimestamps client](https://github.com/opentimestamps/opentimestamps-client)
