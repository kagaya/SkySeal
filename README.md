# SkySeal
a time stamp system

## SkySeal v1.2 development

- [Normative v1 core](spec/v1.md)
- [Offline v1.2 verifier](verifier/README.md)
- `make_public_hashlist_v1.sh`: strict v1 hash-set creator
- [Phase 1 ORCID/passkey service](service/README.md)
- [Phase 1 PC client](cli/skyseal_pc.py)
- [Phase 2 Drive and publication protocol](spec/phase2-protocol.md)
- [Private Google Drive agent](drive_agent/README.md)
- [Owner-disclosed private ledger verifier](verifier/skyseal_private_ledger_verify.py)
- [Complete publication verifier](verifier/skyseal_publication_verify.py)
- [Phase 3 production deployment runbook (Japanese)](deploy/README.ja.md)
- [Production architecture, operations, and cross-platform maintenance manual
  (Japanese)](docs/operations-and-maintenance.ja.md)
- `deploy/bootstrap_agent_vps.sh`: one-command isolated Drive-agent setup on
  the always-on production VPS
- `sudo skyseal-update`: one-command production updates with database backups,
  managed configuration checks, service restarts, and endpoint verification
- Public evidence index: `https://proof.excyberlab.net/proofs/`; complete
  packages are persisted on the VPS before GitHub mirroring
- New seals include a signed JMA Himawari full-disk infrared image as
  `sky-witness.json` and `sky-witness.jpg`. This is the physical Earth-state
  witness from which the SkySeal name is derived.

Existing root-level evidence files remain legacy artifacts and are not rewritten
by the v1 work.

## Independent or posthumous audit of a disclosed file

An auditor does **not** need the private Google Sheet, the VPS database, the
owner's Passkey, or access to Google Drive to verify that exact disclosed bytes
were included in a public SkySeal seal. The public evidence contains the hash
set, WebAuthn signature, public credential and ORCID-bound identity activation,
manifest, and OpenTimestamps proofs needed for independent verification.

The exact bytes matter. A PDF that has been re-exported, optimized, annotated,
or otherwise rewritten is a different candidate even when it looks identical.

Clone this repository and install the verifier plus OpenTimestamps client:

```bash
git clone https://github.com/kagaya/SkySeal.git
cd SkySeal
python3 -m venv .venv-audit
. .venv-audit/bin/activate
python3 -m pip install -r verifier/requirements.txt opentimestamps-client==0.7.2
```

Locate every public evidence directory containing the exact file:

```bash
python3 verifier/skyseal_find.py /path/to/disclosed-file ./evidence
```

For each reported `evidence_directory`, verify the complete package:

```bash
python3 verifier/skyseal_publication_verify.py \
  ./evidence/YYYY/MM/<seal-id> \
  --rp-id proof.excyberlab.net \
  --origin https://proof.excyberlab.net
```

A successful report with `"ok": true`, the expected ORCID, User Present and
User Verified signature checks, and confirmed OpenTimestamps establishes that
the exact candidate hash was in the Passkey-approved set and that the timestamp
targets existed before the independently attested Bitcoin time. No secret key
or cooperation from the owner is required after sealing.

For a v1.2 package, the report also returns `sky_witness` with
`artifacts_checked: true`. The verifier has then confirmed that the published
Himawari JPEG hash equals the JMA observation record embedded in the
Passkey-signed payload. The observation supplies human-inspectable physical
context and a provider-dependent lower-bound claim: the complete signed bundle
could not have included those exact image bytes before that observation
existed. OpenTimestamps supplies the independent upper bound. A historical JMA
image can be copied later, so the sky witness alone is not a trustless timestamp
and does not replace OpenTimestamps.

For the current production identity, the expected `identity_id` is
`https://orcid.org/0000-0003-3001-7690`. Associating that ORCID record with
Katsushi Kagaya remains an identity-record question; the cryptographic proof
binds the seal to that exact ORCID identifier and its activated Passkey.

If OpenTimestamps is not yet confirmed, `--allow-pending-ots` verifies the other
layers but does **not** establish independent time evidence. If the locator
reports `member of a multi-hash seal`, it proves membership in a set rather
than possession of the complete sealed unit.

The private ledger receipt is optional for this byte-level audit. It is needed
only for the additional claim that a seal corresponded to a particular private
Drive name and Drive ID. SkySeal does not by itself prove authorship, scientific
correctness, exclusive possession, or an exact creation time. See the
[verifier guide](verifier/README.md) for detailed interpretation.

## Selected production deployment profile

The root domain, DNS, VPS, HTTPS service, ORCID OAuth, and first iPhone Passkey
registration are configured. The fixed production identifiers are:

- root domain: `excyberlab.net`
- WebAuthn origin and PWA: `https://proof.excyberlab.net`
- WebAuthn RP ID: `proof.excyberlab.net`
- ORCID callback: `https://proof.excyberlab.net/api/v1/orcid/callback`

The machine-readable authority is
[`deploy/production-profile.json`](deploy/production-profile.json). Changing the
origin or RP ID after passkey enrollment requires an explicit identity migration.

# scripts
make_public_hashlist.sh
https://gist.github.com/kagaya/a15dd35e66cb749fa2eb4a7860f90d1c
sign_and_stamp.sh
https://gist.github.com/kagaya/0b02a24cd10d5d4607d2a31ddb2195d0
