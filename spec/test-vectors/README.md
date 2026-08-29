# SkySeal v1 conformance vectors

The `v1/` tree contains only deterministic public test material. It does not
use a real ORCID account, passkey, recovery code, or private research data.

- `v1/valid-es256/` is a complete valid Phase 0 vector using a known P-256 test
  private value of 1.
- `v1/valid-ed25519/` is a complete valid vector using a seed derived from a
  public test label.
- `v1/invalid/` contains one-fault examples for strict hash-list formatting,
  signature tampering, wrong origin, missing User Verified flag, wrong subject
  digest, and forbidden raw credential-ID publication.

The candidate files deliberately reveal a mapping to the test hash list so the
membership command can be tested. This is test scaffolding, not a model for
real public seal directories.

Regenerate the generated `v1/` tree from the repository root:

```bash
python3 tools/generate_test_vectors.py
```

Generation is byte-for-byte deterministic with the supported `cryptography`
version range.
