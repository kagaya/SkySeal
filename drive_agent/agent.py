#!/usr/bin/env python3
"""Poll a private Drive inbox, request passkey approval, and publish SkySeal evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from drive_agent.config import AgentConfig, ConfigurationError, read_secret  # noqa: E402
from drive_agent.google_drive import (  # noqa: E402
    DRIVE_SCOPE,
    SHEETS_SCOPE,
    DriveAPIError,
    GoogleDriveRESTClient,
    GoogleServiceAccountTokenProvider,
    hash_unit,
    inventory_unit,
    validate_hash_list_bytes,
)
from drive_agent.private_ledger import (  # noqa: E402
    GoogleSheetsPrivateLedger,
    PrivateLedgerError,
    build_receipt,
)
from drive_agent.publication import (  # noqa: E402
    GitHubPublisher,
    LocalEvidencePublisher,
    OpenTimestampsClient,
    PublicationError,
    PublicationWorker,
)
from drive_agent.skyseal import SkySealAPIError, SkySealClient  # noqa: E402
from drive_agent.sky_witness import JMAHimawariWitness, SkyWitnessError  # noqa: E402
from drive_agent.state import AgentStore  # noqa: E402
from verifier.skyseal_verify import canonical_json  # noqa: E402


@dataclass
class AgentRuntime:
    config: AgentConfig
    drive: Any
    skyseal: Any
    publisher: Any
    store: AgentStore
    ledger: Any | None = None
    sky_witness: Any | None = None

    def scan(self, now: int | None = None) -> list[dict[str, object]]:
        observed_at = int(time.time()) if now is None else now
        current_units = {}
        for root in self.drive.list_children(self.config.drive_folder_id):
            unit = inventory_unit(self.drive, root)
            reference = self.store.observe(unit, observed_at)
            current_units[reference] = unit

        submitted: list[dict[str, object]] = []
        scan_witness = None
        for row in self.store.ready_units(self.config.settle_seconds, observed_at):
            unit = current_units.get(row["unit_ref"])
            if unit is None or not unit.files:
                continue
            hash_list = self.store.cached_expired_hash_list(
                row["unit_ref"], unit.snapshot_digest
            )
            reused_hashes = hash_list is not None
            if hash_list is None:
                hash_list = hash_unit(self.drive, unit)
            after_hash = inventory_unit(self.drive, unit.root)
            if after_hash.snapshot_digest != unit.snapshot_digest:
                self.store.observe(after_hash, observed_at)
                continue
            receipt = None
            if self.ledger is not None:
                receipt = build_receipt(
                    drive_item_id=unit.root.file_id,
                    drive_item_name=self.drive.get_private_display_name(unit.root.file_id),
                    root_mime_type=unit.root.mime_type,
                    snapshot_digest=unit.snapshot_digest,
                    subject_digest=hashlib.sha256(hash_list).hexdigest(),
                    entry_count=len(validate_hash_list_bytes(hash_list)),
                )
            if self.sky_witness is not None and scan_witness is None:
                scan_witness = self.sky_witness.capture()
            witness = scan_witness
            if witness is not None:
                final_inventory = inventory_unit(self.drive, unit.root)
                if final_inventory.snapshot_digest != unit.snapshot_digest:
                    self.store.observe(final_inventory, observed_at)
                    continue
            if witness is not None:
                transaction = self.skyseal.create(
                    hash_list,
                    receipt.commitment if receipt is not None else None,
                    witness.metadata,
                )
            elif receipt is not None:
                transaction = self.skyseal.create(hash_list, receipt.commitment)
            else:
                transaction = self.skyseal.create(hash_list)
            job = self.store.add_job(
                unit_ref=row["unit_ref"],
                snapshot_digest=unit.snapshot_digest,
                hash_list=hash_list,
                seal_id=transaction.seal_id,
                bearer_token=transaction.bearer_token,
                approval_url=transaction.approval_url,
                ledger_receipt=receipt.content if receipt is not None else None,
                ledger_commitment=receipt.commitment if receipt is not None else None,
                sky_witness_json=(
                    canonical_json(witness.metadata) + b"\n" if witness is not None else None
                ),
                sky_witness_image=witness.image if witness is not None else None,
                now=observed_at,
            )
            submitted.append(
                {
                    "unit_ref": row["unit_ref"],
                    "seal_id": job["seal_id"],
                    "entry_count": job["entry_count"],
                    "approval_url": job["approval_url"],
                    "hash_source": "cached_expired" if reused_hashes else "drive",
                }
            )
        return submitted

    def collect(self) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        for job in self.store.jobs_with_status("pending_approval"):
            status = self.skyseal.status(job["seal_id"], job["bearer_token"])
            if status == "approved":
                artifacts = self.skyseal.approved_artifacts(
                    job["seal_id"], job["bearer_token"]
                )
                self.store.store_approved_artifacts(
                    job["seal_id"],
                    bundle_json=artifacts.bundle_json,
                    genesis_json=artifacts.genesis_json,
                    identity_activation=artifacts.identity_activation,
                )
                events.append({"seal_id": job["seal_id"], "event": "approved"})
            elif status in {"expired", "rejected", "invalidated"}:
                self.store.mark_error(
                    job["seal_id"],
                    f"seal_{status}",
                    retryable=status == "expired",
                )
                events.append({"seal_id": job["seal_id"], "event": status})

        for job in self.store.jobs_with_status("approved"):
            if job["ots_proof"] is None or job["identity_ots_proof"] is None:
                stamped = self.publisher.stamp(job)
                self.store.store_timestamp_proofs(
                    job["seal_id"], stamped.bundle_ots, stamped.activation_ots
                )
                job = self.store.get_job(job["seal_id"])
                if job is None:
                    raise ValueError("approved job disappeared after timestamping")
            result = self.publisher.publish(job)
            self.store.mark_published(
                job["seal_id"],
                result.bundle_ots,
                result.activation_ots,
                result.prefix,
            )
            events.append({"seal_id": job["seal_id"], "event": "published_locally"})
        self._sync_pending_ledger(events)
        self._mirror_pending(events)
        return events

    def _sync_pending_ledger(self, events: list[dict[str, str]]) -> None:
        if self.ledger is None:
            return
        for job in self.store.jobs_needing_ledger_sync():
            try:
                self.ledger.sync(job)
            except PrivateLedgerError as exc:
                self.store.mark_ledger_pending(job["seal_id"], str(exc))
                events.append({"seal_id": job["seal_id"], "event": "private_ledger_pending"})
                continue
            self.store.mark_ledger_synced(job["seal_id"])
            events.append({"seal_id": job["seal_id"], "event": "private_ledger_synced"})

    def _mirror_pending(self, events: list[dict[str, str]]) -> None:
        for job in self.store.jobs_needing_github_mirror():
            try:
                self.publisher.mirror(job, updating=True)
            except PublicationError as exc:
                self.store.mark_github_pending(job["seal_id"], str(exc))
                events.append(
                    {"seal_id": job["seal_id"], "event": "github_mirror_pending"}
                )
                continue
            self.store.mark_github_synced(job["seal_id"])
            events.append({"seal_id": job["seal_id"], "event": "github_mirrored"})

    def upgrade(self) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        for job in self.store.jobs_with_status("published"):
            result = self.publisher.upgrade(job)
            self.store.update_ots_proofs(
                job["seal_id"], result.bundle_ots, result.activation_ots
            )
            events.append({"seal_id": job["seal_id"], "event": "timestamps_upgraded"})
        self._sync_pending_ledger(events)
        self._mirror_pending(events)
        return events

    def localize(self) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        for job in self.store.jobs_with_status("published"):
            self.publisher.ensure_local(job, str(job["github_status"]))
            events.append({"seal_id": job["seal_id"], "event": "available_locally"})
        return events


def build_runtime(config: AgentConfig) -> AgentRuntime:
    store = AgentStore(config.database_path)
    store.initialize()
    scopes = (DRIVE_SCOPE,)
    if config.private_ledger_spreadsheet_id is not None:
        scopes = (DRIVE_SCOPE, SHEETS_SCOPE)
    token_provider = GoogleServiceAccountTokenProvider(
        config.google_service_account_file, scopes=scopes
    )
    drive = GoogleDriveRESTClient(token_provider)
    skyseal = SkySealClient(
        config.skyseal_server,
        read_secret(config.skyseal_agent_token_file, "SkySeal agent token"),
    )
    github = GitHubPublisher(
        owner=config.github_owner,
        repository=config.github_repository,
        branch=config.github_branch,
        token=read_secret(config.github_token_file, "GitHub token"),
    )
    publisher = PublicationWorker(
        trusted_rp_id=config.skyseal_rp_id,
        trusted_origin=config.skyseal_server,
        work_directory=config.work_directory,
        github_prefix=config.github_prefix,
        ots=OpenTimestampsClient(),
        local=LocalEvidencePublisher(config.public_root),
        github=github,
    )
    ledger = None
    if config.private_ledger_spreadsheet_id is not None:
        ledger = GoogleSheetsPrivateLedger(
            token_provider,
            config.private_ledger_spreadsheet_id,
            config.private_ledger_sheet,
            config.skyseal_server,
        )
    sky_witness = (
        JMAHimawariWitness() if config.sky_witness_mode == "required" else None
    )
    return AgentRuntime(config, drive, skyseal, publisher, store, ledger, sky_witness)


def print_events(events: list[dict[str, object]]) -> None:
    for event in events:
        print(json.dumps(event, ensure_ascii=False, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "scan",
            "collect",
            "run-once",
            "run",
            "upgrade",
            "localize",
            "pending",
            "ledger-check",
            "retry-expired",
        ),
    )
    parser.add_argument(
        "--seal-id",
        help="expired seal ID to make eligible for a cached retry",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = AgentConfig.from_environment()
        runtime = build_runtime(config)
        if args.command == "scan":
            print_events(runtime.scan())
        elif args.command == "collect":
            print_events(runtime.collect())
        elif args.command == "run-once":
            print_events(runtime.scan())
            print_events(runtime.collect())
        elif args.command == "upgrade":
            print_events(runtime.upgrade())
        elif args.command == "localize":
            print_events(runtime.localize())
        elif args.command == "pending":
            for job in runtime.store.jobs_with_status("pending_approval", "approved"):
                print_events(
                    [
                        {
                            "seal_id": job["seal_id"],
                            "status": job["status"],
                            "approval_url": job["approval_url"],
                        }
                    ]
                )
        elif args.command == "ledger-check":
            if runtime.ledger is None:
                raise ConfigurationError("private ledger is not configured")
            runtime.ledger.check()
            print_events([{"event": "private_ledger_ready"}])
        elif args.command == "retry-expired":
            if not args.seal_id:
                raise ConfigurationError("retry-expired requires --seal-id")
            job = runtime.store.requeue_expired(args.seal_id)
            print_events(
                [
                    {
                        "seal_id": job["seal_id"],
                        "event": "expired_retry_queued",
                    }
                ]
            )
        else:
            while True:
                print_events(runtime.scan())
                print_events(runtime.collect())
                time.sleep(config.poll_seconds)
        return 0
    except KeyboardInterrupt:
        return 130
    except (
        ConfigurationError,
        DriveAPIError,
        SkySealAPIError,
        PublicationError,
        PrivateLedgerError,
        SkyWitnessError,
        ValueError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
