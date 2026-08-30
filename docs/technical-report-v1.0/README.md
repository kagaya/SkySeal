# SkySeal Technical Report v1.0

**SkySeal: Identity-Bound Timestamping of Private Research Files with a
Himawari Earth-State Witness**

Katsushi Kagaya, 30 August 2026.

- [Technical report (PDF)](SkySeal_Technical_Report_v1.0_20260830.pdf)
- [Reproducible LaTeX source](source/)

## Independent SkySeal records

The PDF and the expanded source directory were sealed separately. The report
PDF was not modified after sealing. This README is publication metadata and is
not part of either sealed object.

| Sealed object | Seal ID | Public evidence |
|---|---|---|
| PDF as published here | `01a051b7-c62c-798c-87e9-bd9c51989bff` | [proof](https://proof.excyberlab.net/proofs/01a051b7-c62c-798c-87e9-bd9c51989bff) |
| Expanded `source/` file set | `01a051b7-e0f5-71a2-b0b3-c8d25f4cfaaf` | [proof](https://proof.excyberlab.net/proofs/01a051b7-e0f5-71a2-b0b3-c8d25f4cfaaf) |

The PDF SHA-256 is:

```text
9f3ebad2f432978c6e118515f4cdc52702b08de62d2ed34e61967a44dbfe73c3
```

The expanded source seal contains these exact file bytes:

| Published path | SHA-256 |
|---|---|
| `source/SkySeal_Technical_Report_v1.0_20260830.tex` | `13cac0388f494728d2246918bcafab46e9777496643a2959b72f25eba1f71aa1` |
| `source/skyseal-report.bib` | `87a5cc01cc723d21dc90aac53d53d75ff2e5a6a1dd7a0d74dcbc4ee0a03e6ce5` |
| `source/figures/sky-witness.jpg` | `db39b5314243315e43b2aa11ea377e76e6db9d5ca3fc4bc1b62a415b6e3f6318` |

SkySeal v1 commits to a sorted set of distinct file hashes. The source seal
therefore proves inclusion of these exact three byte strings in one approved
set. It does not cryptographically preserve the directory name, file names,
hierarchy, or duplicate multiplicity.

## Independent verification

From the repository root, install the verifier as described in the main
[README](../../README.md). Locate the PDF record with:

```bash
python3 verifier/skyseal_find.py \
  docs/technical-report-v1.0/SkySeal_Technical_Report_v1.0_20260830.pdf \
  ./evidence
```

Check every source file in the same way:

```bash
find docs/technical-report-v1.0/source -type f -print0 |
while IFS= read -r -d '' file; do
  python3 verifier/skyseal_find.py "$file" ./evidence
done
```

All three source files should resolve to the source Seal ID above. Verify each
complete evidence package independently:

```bash
python3 verifier/skyseal_publication_verify.py \
  evidence/2026/08/01a051b7-c62c-798c-87e9-bd9c51989bff \
  --rp-id proof.excyberlab.net \
  --origin https://proof.excyberlab.net

python3 verifier/skyseal_publication_verify.py \
  evidence/2026/08/01a051b7-e0f5-71a2-b0b3-c8d25f4cfaaf \
  --rp-id proof.excyberlab.net \
  --origin https://proof.excyberlab.net
```

Until both OpenTimestamps receipts are Bitcoin-confirmed, the option
`--allow-pending-ots` checks the other layers but does not establish the
independent upper time bound.

## Suggested citation

Kagaya, K. (2026). *SkySeal: Identity-Bound Timestamping of Private Research
Files with a Himawari Earth-State Witness*. SkySeal Technical Report v1.0,
30 August 2026.
