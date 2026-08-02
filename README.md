# SkySeal

A timestamp and signature system that publishes evidence without publishing
the names or contents of the source files.

## One-command workflow

From the directory where the public artifacts should be created:

```sh
bash skyseal seal /path/to/private-recordings
```

This performs the existing SkySeal workflow in one command:

1. recursively calculate SHA-256 for the files in the target directory;
2. create `YYYYMMDD_HHMM_public.txt` containing hashes only;
3. create its detached ASCII-armored GPG signature;
4. create an OpenTimestamps proof for the signature;
5. export the public key if it is not already present.

The command automatically uses the signing key when the GPG keyring contains
exactly one secret key. If more than one key exists, specify it explicitly:

```sh
bash skyseal seal --uid "GPG UID or fingerprint" /path/to/private-recordings
```

Alternatively, set `SKYSEAL_GPG_UID` once in the shell environment. Use
`--output-dir DIR` to place the artifacts elsewhere. OpenTimestamps is required
by default; `--no-ots` is available only when deliberately creating a
signature without a timestamp.

Requirements: Bash, GnuPG (`gpg`), OpenTimestamps client (`ots`), and either
`sha256sum` or `shasum`.

## Existing scripts

- [`make_public_hashlist.sh`](https://gist.github.com/kagaya/a15dd35e66cb749fa2eb4a7860f90d1c)
- [`sign_and_stamp.sh`](https://gist.github.com/kagaya/0b02a24cd10d5d4607d2a31ddb2195d0)

The original scripts and previously published artifacts remain valid. The
one-command workflow adds a convenient entry point and does not rewrite past
records.

## Test

```sh
bash tests/test_skyseal.sh
```
