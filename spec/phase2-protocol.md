# SkySeal Phase 2 Drive and publication protocol

Status: reference implementation baseline  
Version: 1.0.0-draft.1  
Date: 2026-08-29

Phase 2 turns a completed upload in a private Google Drive inbox into a
hash-only approval request and, after WebAuthn approval, a timestamped public
evidence package. It does not make WebAuthn approval unattended: the final user
gesture and user verification remain mandatory.

## 1. Components and trust boundary

The Drive agent is a separate private process. It may read the monitored Drive
folder, raw bytes, private Drive IDs, and private SkySeal transaction bearers.
The public SkySeal service receives only the strict hash-list digest, distinct
hash count, and protocol state. GitHub and OpenTimestamps receive only public
artifacts.

The recommended Google identity is a dedicated service account. Only the inbox
folder is shared read-only with that address. Domain-wide delegation is not
required and should not be enabled.

The agent's Drive API field mask intentionally omits `name`. Names are neither
needed for hashing nor stored in the private agent database.

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
identity has an active OpenPGP-verified genesis. The service stores only the
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
- the detached OpenPGP genesis signature.

Before publication, the agent independently verifies the hash-list commitment,
WebAuthn signature, trusted RP ID and origin, identity digest, and pinned
OpenPGP primary fingerprint.

## 6. Timestamping and public package

OpenTimestamps stamps the exact WebAuthn bundle and the exact detached OpenPGP
genesis signature. The initial proof can remain pending until Bitcoin
confirmation. A later `upgrade` operation replaces only the `.ots` proof and
the manifest that records its digest.

GitHub paths are derived only from the public creation month and random UUIDv7:

```text
evidence/YYYY/MM/<seal-id>/
  hashes.txt
  seal.skyseal.json
  seal.skyseal.json.ots
  identity-genesis.json
  identity-genesis.json.asc
  identity-genesis.json.asc.ots
  manifest.json
```

`manifest.json` is uploaded last. It contains SHA-256 digests of every other
artifact and the two proof-to-target relationships. Publication is idempotent:
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

## 8. Failure and recovery

- A changing unit returns to the settling state.
- A checksum mismatch prevents submission.
- Expired, rejected, or invalidated approvals become private error records.
- Timestamp proofs are stored privately before GitHub upload, so a partial
  GitHub failure can resume without creating a different proof.
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

