#!/usr/bin/env python3
"""Poll a private Drive inbox, request passkey approval, and publish SkySeal evidence."""

from __future__ import annotations

import argparse
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
    DriveAPIError,
    GoogleDriveRESTClient,
    GoogleServiceAccountTokenProvider,
    hash_unit,
    inventory_unit,
)
from drive_agent.publication import (  # noqa: E402
    GitHubPublisher,
    OpenTimestampsClient,
    PublicationError,
    PublicationWorker,
)
from drive_agent.skyseal import SkySealAPIError, SkySealClient  # noqa: E402
from drive_agent.state import AgentStore  # noqa: E402


@dataclass
class AgentRuntime:
    config: AgentConfig
    drive: Any
    skyseal: Any
    publisher: Any
    store: AgentStore

    def scan(self, now: int | None = None) -> list[dict[str, object]]:
        observed_at = int(time.time()) if now is None else now
        current_units = {}
        for root in self.drive.list_children(self.config.drive_folder_id):
            unit = inventory_unit(self.drive, root)
            reference = self.store.observe(unit, observed_at)
            current_units[reference] = unit

        submitted: list[dict[str, object]] = []
        for row in self.store.ready_units(self.config.settle_seconds, observed_at):
            unit = current_units.get(row["unit_ref"])
            if unit is None or not unit.files:
                continue
            hash_list = hash_unit(self.drive, unit)
            after_hash = inventory_unit(self.drive, unit.root)
            if after_hash.snapshot_digest != unit.snapshot_digest:
                self.store.observe(after_hash, observed_at)
                continue
            transaction = self.skyseal.create(hash_list)
            job = self.store.add_job(
                unit_ref=row["unit_ref"],
                snapshot_digest=unit.snapshot_digest,
                hash_list=hash_list,
                seal_id=transaction.seal_id,
                bearer_token=transaction.bearer_token,
                approval_url=transaction.approval_url,
                now=observed_at,
            )
            submitted.append(
                {
                    "unit_ref": row["unit_ref"],
                    "seal_id": job["seal_id"],
                    "entry_count": job["entry_count"],
                    "approval_url": job["approval_url"],
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
                    genesis_signature=artifacts.genesis_signature,
                )
                events.append({"seal_id": job["seal_id"], "event": "approved"})
            elif status in {"expired", "rejected", "invalidated"}:
                self.store.mark_error(job["seal_id"], f"seal_{status}")
                events.append({"seal_id": job["seal_id"], "event": status})

        for job in self.store.jobs_with_status("approved"):
            if job["ots_proof"] is None or job["genesis_ots_proof"] is None:
                stamped = self.publisher.stamp(job)
                self.store.store_timestamp_proofs(
                    job["seal_id"], stamped.bundle_ots, stamped.genesis_ots
                )
                job = self.store.get_job(job["seal_id"])
                if job is None:
                    raise ValueError("approved job disappeared after timestamping")
            result = self.publisher.publish(job)
            self.store.mark_published(
                job["seal_id"],
                result.bundle_ots,
                result.genesis_ots,
                result.prefix,
            )
            events.append({"seal_id": job["seal_id"], "event": "published"})
        return events

    def upgrade(self) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        for job in self.store.jobs_with_status("published"):
            result = self.publisher.upgrade(job)
            self.store.update_ots_proofs(
                job["seal_id"], result.bundle_ots, result.genesis_ots
            )
            events.append({"seal_id": job["seal_id"], "event": "timestamps_upgraded"})
        return events


def build_runtime(config: AgentConfig) -> AgentRuntime:
    store = AgentStore(config.database_path)
    store.initialize()
    drive = GoogleDriveRESTClient(
        GoogleServiceAccountTokenProvider(config.google_service_account_file)
    )
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
        openpgp_public_key=config.openpgp_public_key,
        work_directory=config.work_directory,
        github_prefix=config.github_prefix,
        ots=OpenTimestampsClient(),
        github=github,
    )
    return AgentRuntime(config, drive, skyseal, publisher, store)


def print_events(events: list[dict[str, object]]) -> None:
    for event in events:
        print(json.dumps(event, ensure_ascii=False, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("scan", "collect", "run-once", "run", "upgrade", "pending"),
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
        ValueError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
