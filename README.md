# SkySeal
a time stamp system

## SkySeal v1.1 development

- [Normative v1 core](spec/v1.md)
- [Offline v1.1 verifier](verifier/README.md)
- `make_public_hashlist_v1.sh`: strict v1 hash-set creator
- [Phase 1 ORCID/passkey service](service/README.md)
- [Phase 1 PC client](cli/skyseal_pc.py)
- [Phase 2 Drive and publication protocol](spec/phase2-protocol.md)
- [Private Google Drive agent](drive_agent/README.md)
- [Complete publication verifier](verifier/skyseal_publication_verify.py)
- [Phase 3 production deployment runbook (Japanese)](deploy/README.ja.md)
- `deploy/bootstrap_agent_vps.sh`: one-command isolated Drive-agent setup on
  the always-on production VPS
- `sudo skyseal-update`: one-command production updates with database backups,
  managed configuration checks, service restarts, and endpoint verification
- Public evidence index: `https://proof.excyberlab.net/proofs/`; complete
  packages are persisted on the VPS before GitHub mirroring

Existing root-level evidence files remain legacy artifacts and are not rewritten
by the v1 work.

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
