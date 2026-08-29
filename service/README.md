# SkySeal Phase 1 reference service

This service implements ORCID enrollment, initial WebAuthn credential
registration, PC-created hash-only transactions, nearby-device-compatible
assertion options, and public bundle generation.

It is a reference server intended to run behind an HTTPS reverse proxy. The
built-in HTTP server must not be exposed directly to the internet.

## Production configuration

Copy values from `service/env.example` into the deployment secret/configuration
system. Do not commit the ORCID client secret or database.

```bash
python3 -m pip install -r verifier/requirements.txt
python3 service/app.py
```

Required production properties:

- exact HTTPS `SKYSEAL_ORIGIN`;
- matching `SKYSEAL_RP_ID`;
- ORCID Public API client ID, client secret, and registered callback;
- private persistent SQLite location;
- HTTPS proxy preserving the configured public origin.
- reverse-proxy request-rate limits, especially for unauthenticated
  `POST /api/v1/seals`;
- encrypted storage and restricted backup access for the private SQLite data.

The OAuth callback discards ORCID access and refresh tokens after reading the
authenticated iD and display name.

## Loopback development

```bash
export SKYSEAL_ORIGIN=http://localhost:8787
export SKYSEAL_RP_ID=localhost
export SKYSEAL_DEV_ALLOW_HTTP_LOCALHOST=1
export SKYSEAL_DEV_MOCK_ORCID=1
export SKYSEAL_DEV_ALLOW_UNSEALED_IDENTITY=1
export SKYSEAL_DATABASE=/tmp/skyseal-development.sqlite3
python3 service/app.py
```

Then open `http://localhost:8787/api/v1/orcid/mock`. Development bundles use an
HTTP origin, visibly bypass OpenPGP activation, and are not publishable v1
evidence.

## Initial OpenPGP bootstrap

After registering the first passkey:

1. Download `identity-genesis.json` from the PWA.
2. On a PC holding the established secret key, sign the exact bytes:

   ```bash
   gpg --armor --detach-sign \
     --local-user 85F79058BD83EB3889DEF766B065C54586067E2E \
     identity-genesis.json
   ```

3. On the service host, verify and activate with the public key only:

   ```bash
   python3 service/bootstrap_identity.py \
     --database /var/lib/skyseal/skyseal.sqlite3 \
     --orcid 0000-0000-0000-0000 \
     --signature identity-genesis.json.asc \
     --public-key publickey_kkagaya@mail.kitami-it.ac.jp.asc
   ```

The OpenPGP secret key never enters the service. OpenTimestamps stamping of the
genesis signature is added by the Phase 2 background worker.

## PC workflow

Create a strict hash list locally, then create an approval transaction:

```bash
./make_public_hashlist_v1.sh --output completed_public.txt ./completed_dataset
python3 cli/skyseal_pc.py create completed_public.txt \
  --server https://proof.excyberlab.net \
  --rp-id proof.excyberlab.net
```

Open the printed URL. On a PC, select the browser's nearby-device passkey option
and scan its standard FIDO QR code with iPhone/iPad. After approval:

```bash
python3 cli/skyseal_pc.py wait completed_public.txt.pending.json
```

The private pending-state file contains the transaction bearer and local hash
list path. It must not be published.

## Phase 2 Drive agent

After the identity is OpenPGP-activated, create a one-time-display token for a
private Drive agent:

```bash
python3 service/create_agent_token.py \
  --database /var/lib/skyseal/skyseal.sqlite3 \
  --orcid 0000-0000-0000-0000 \
  --output /etc/skyseal/drive-agent.token
```

Only the SHA-256 token hash is retained by the service. Agent-created seals are
pre-bound to that ORCID and appear in the authenticated PWA under "Driveからの
承認待ち". The phone does not receive the agent's transaction bearer. Continue
with `drive_agent/README.md` for the isolated Drive and publication worker.
