# SkySeal private Drive agent

The agent watches one private Google Drive inbox, hashes stable sealing units,
creates ORCID-bound approval requests, retrieves approved evidence, verifies it,
stamps it with OpenTimestamps, persists an opaque package on the VPS, and then
mirrors that package to GitHub. The
original remains in Google Drive; bytes are streamed through the agent for
hashing and are not persisted as source-file copies.

Its normal hashing inventory never requests the Drive `name` field. If the
optional private ledger is enabled, it requests only the root sealing unit's
name for an owner-held receipt. Names and IDs never enter public logs or
evidence. Read `spec/phase2-protocol.md` before deployment.

## Placement and trust

For always-on iPhone/iPad uploads, the agent may run on the same Sakura VPS as
the public service. Use the separate `skyseal-agent` Unix account and private
directories installed by `deploy/bootstrap_agent_vps.sh`. The public Web
process then cannot read the agent credentials through ordinary Unix file
permissions.

This convenience expands the VPS trust boundary: compromise of the host or its
root account could expose bytes readable through the dedicated Drive service
account. Limit that account to Viewer access on `SkySeal Inbox`; never grant
domain-wide delegation or access to the rest of Drive. A separate trusted
Ubuntu host remains the stronger-isolation alternative. WSL is suitable for
manual or delayed processing but does not run while Windows/WSL is stopped.

## Prerequisites

1. Deploy Phase 1, authenticate the ORCID iD, register the first passkey, and
   activate the identity with a User-Verified passkey assertion.
2. Create a Google Cloud service account and enable Drive API v3. Also enable
   Google Sheets API when using the optional private ledger.
3. Share only the private inbox folder with the service-account email as a
   viewer. Do not enable domain-wide delegation.
4. Create a fine-grained GitHub token restricted to the evidence repository
   with `Contents: write`.
5. Install Python dependencies; `opentimestamps-client` supplies the `ots`
   command:

   ```bash
   python3 -m pip install -r verifier/requirements.txt
   python3 -m pip install -r drive_agent/requirements.txt
   ```

## Create the identity-bound agent token

On the SkySeal service host:

```bash
python3 service/create_agent_token.py \
  --database /var/lib/skyseal/skyseal.sqlite3 \
  --orcid 0000-0000-0000-0000 \
  --output /etc/skyseal/drive-agent.token
```

The command refuses to overwrite an existing token file and creates it with
mode 600. Set the service-account JSON and GitHub token files to mode 600 too.

## Configure and run

Copy the variable names from `drive_agent/env.example` into the private service
environment. A single pass is useful for systemd timers or cron:

```bash
python3 drive_agent/agent.py run-once
```

The foreground worker polls continuously:

```bash
python3 drive_agent/agent.py run
```

Other commands:

```bash
python3 drive_agent/agent.py scan
python3 drive_agent/agent.py pending
python3 drive_agent/agent.py collect
python3 drive_agent/agent.py upgrade
python3 drive_agent/agent.py ledger-check
```

## Owner-only Google Sheet ledger

Create a Google Sheet in the owner's Drive, rename its tab to `Ledger`, keep
link sharing off, and share that Sheet as **Editor** only with the existing
SkySeal service-account email. The service account remains **Viewer** on
`SkySeal Inbox`. Set these private environment values:

```text
SKYSEAL_PRIVATE_LEDGER_SPREADSHEET_ID=<ID between /d/ and /edit>
SKYSEAL_PRIVATE_LEDGER_SHEET=Ledger
```

On the production VPS the configuration and header check are one command:

```bash
sudo bash /opt/skyseal/deploy/configure_private_ledger_vps.sh \
  --spreadsheet-id '<spreadsheet-id>'
```

Future rows contain the root Drive item name/link/ID, Seal ID, public proof URL,
and exact salted receipt JSON. Only a SHA-256 commitment to that receipt is
public and Passkey-signed. The Sheet is not end-to-end encrypted: its owner,
the explicitly shared service account, and VPS/root administrators controlling
that credential can technically read it.

After upload and the settle interval, open the installed SkySeal PWA on an
iPhone or iPad. The pending card shows only arrival time and hash count. Tap the
request and approve it with the passkey. `collect` then verifies the ORCID-bound
identity activation and seal signatures, timestamps both public proofs, and
publishes the package locally before attempting the GitHub mirror. A GitHub
failure leaves the package visible at `/proofs/` and is retried independently.
Run `upgrade` later to add confirmed Bitcoin paths to
pending OTS proofs.

The SQLite database and its WAL files are private state. Do not publish them.
The public root contains only the seven manifest-controlled public artifacts
and a discovery index; it must never receive raw Drive bytes.

On the production Sakura VPS, use the automated deployment described in
`deploy/README.ja.md` instead of performing these steps individually.
