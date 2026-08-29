# SkySeal private Drive agent

The agent watches one private Google Drive inbox, hashes stable sealing units,
creates ORCID-bound approval requests, retrieves approved evidence, verifies it,
stamps it with OpenTimestamps, and publishes an opaque package to GitHub.

It never requests the Drive `name` field. Its logs use a domain-separated hash
of the private Drive unit ID. Read `spec/phase2-protocol.md` before deployment.

## Prerequisites

1. Deploy and activate the Phase 1 SkySeal identity.
2. Create a Google Cloud service account and enable Drive API v3.
3. Share only the private inbox folder with the service-account email as a
   viewer. Do not enable domain-wide delegation.
4. Create a fine-grained GitHub token restricted to the evidence repository
   with `Contents: write`.
5. Install `gpg`, the `ots` command, and Python dependencies:

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
```

After upload and the settle interval, open the installed SkySeal PWA on an
iPhone or iPad. The pending card shows only arrival time and hash count. Tap the
request and approve it with the passkey. `collect` then verifies, timestamps,
and publishes the package. Run `upgrade` later to add confirmed Bitcoin paths
to pending OTS proofs.

The SQLite database and its WAL files are private state. Do not publish them.
