# SkySeal v1 Phase 0 verifier

This is the executable reference implementation for the normative core in
[`../spec/v1.md`](../spec/v1.md). It never reads Google Drive and does not need
private SkySeal server state.

Requirements:

- Python 3.10 or later
- `cryptography` 45 or 46

Install the dependency in an isolated environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r verifier/requirements.txt
```

Strictly validate a new v1 hash list:

```bash
python3 verifier/skyseal_verify.py hash-list path/to/public.txt
```

Test whether exact candidate bytes are a member:

```bash
python3 verifier/skyseal_verify.py contains path/to/public.txt candidate.bin
```

Verify the Phase 0 WebAuthn core:

```bash
python3 verifier/skyseal_verify.py bundle \
  --hash-list spec/test-vectors/v1/valid/public.txt \
  --bundle spec/test-vectors/v1/valid/public.txt.skyseal.json \
  --identity-genesis spec/test-vectors/v1/valid/identity-genesis.json \
  --rp-id seal.example.org \
  --origin https://seal.example.org
```

The JSON report separates completed checks from checks not yet implemented.
Phase 0 does not claim to verify the detached OpenPGP genesis signature, later
credential-event authorization, or OpenTimestamps proof.

## Phase 2 publication directory

After downloading one complete `evidence/YYYY/MM/<seal-id>/` directory, verify
its manifest, hash set, WebAuthn bundle, OpenPGP genesis signature, and both OTS
proofs with:

```bash
python3 verifier/skyseal_publication_verify.py ./evidence-directory \
  --public-key publickey_kkagaya@mail.kitami-it.ac.jp.asc \
  --rp-id proof.excyberlab.net \
  --origin https://proof.excyberlab.net
```

Before Bitcoin confirmation, add `--allow-pending-ots` to verify every other
layer while reporting each proof as `pending_or_unverified`. This option does
not claim independent time evidence.

Run the standard-library test suite:

```bash
python3 -m unittest discover -s verifier/tests -v
```

Historical root-level SkySeal artifacts predate the strict v1 format. Do not
run a result through a formatter or rewrite it merely to make the v1 parser
accept it.
