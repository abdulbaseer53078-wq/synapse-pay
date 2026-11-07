"""WORM storage for the audit chain (Step 7.4).

Two implementations behind one interface:

* `LocalWormSink` — a directory of write-once JSON objects. Fine for development, tests and single-node
  deployments. `O_EXCL` + read-only permissions + content-addressed names make a rewrite fail loudly.
* `S3WormSink` — S3 with Object Lock in COMPLIANCE mode: even the account root cannot delete or overwrite an
  object before its retention date. This is the production path and satisfies the five-year RBI retention.

Epochs (Step 17.3): after a region failover the chain continues in a new key space, `<prefix>/epoch-NNNN/...`,
so records written by the old region (and replicated here late) can never collide with the new region's. Epoch 1
keeps the original keys. Keys sort epoch by epoch: `epoch-` sorts after the year folders.

`shortcut:` the local sink is not WORM in the hardware sense — a user with root can rewrite the files. It is
still content-addressed and checked by the verifier, so tampering is detectable, but only S3 Object Lock gives
the "cannot be deleted by anyone" guarantee. Keep that distinction out of compliance claims.
"""
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterator, Protocol

from app.audit.chain import StoredEvent


class WormConflict(RuntimeError):
    """A different object already exists at this key: the chain was attempted twice with different content."""


class WormSink(Protocol):
    def put(self, record: StoredEvent, epoch: int = 1) -> str:
        """Durably write one record and return its key. Idempotent for identical content."""

    def read(self, key: str) -> dict: ...

    def records(self) -> Iterator[tuple[str, dict]]:
        """Every stored record, in chain order (sequence ascending)."""


def object_key(record: StoredEvent, prefix: str = "audit", epoch: int = 1) -> str:
    """Content-addressed and ordered: `audit/2026/11/07/000000000000000042-<hash>.json`, or for a later epoch
    `audit/epoch-0002/2026/11/07/...`."""
    stamp = record.event.timestamp.astimezone(UTC)
    space = prefix if epoch == 1 else f"{prefix}/epoch-{epoch:04d}"
    return f"{space}/{stamp:%Y/%m/%d}/{record.sequence:020d}-{record.hash}.json"


def epoch_of_key(key: str, prefix: str = "audit") -> int:
    """The epoch an object key belongs to (inverse of `object_key`'s key space)."""
    rest = key[len(prefix) + 1:] if key.startswith(prefix + "/") else key
    head = rest.split("/", 1)[0]
    return int(head[len("epoch-"):]) if head.startswith("epoch-") else 1


class LocalWormSink:
    """A filesystem WORM store. Objects are created exclusively and then made read-only."""

    def __init__(self, root: Path | str, prefix: str = "audit"):
        self.root = Path(root)
        self.prefix = prefix

    def _path(self, key: str) -> Path:
        return self.root / key

    def put(self, record: StoredEvent, epoch: int = 1) -> str:
        key = object_key(record, self.prefix, epoch)
        path = self._path(key)
        body = record.to_json()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
        except FileExistsError:
            if path.read_bytes() == body:  # a retried ingest of the same record
                return key
            raise WormConflict(f"{key} already exists with different content")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.chmod(path, 0o444)  # read-only, best effort against accidental edits
        return key

    def read(self, key: str) -> dict:
        return json.loads(self._path(key).read_text(encoding="utf-8"))

    def records(self) -> Iterator[tuple[str, dict]]:
        if not self.root.exists():
            return
        for path in sorted(self.root.rglob("*.json")):
            key = path.relative_to(self.root).as_posix()
            yield key, json.loads(path.read_text(encoding="utf-8"))


class S3WormSink:
    """S3 Object Lock (COMPLIANCE). Requires `pip install boto3` and a bucket created with Object Lock enabled.

    The bucket policy is in infra/s3-audit-bucket.tf — Object Lock must be turned on at *bucket creation*;
    it cannot be added to an existing bucket.
    """

    def __init__(self, bucket: str, prefix: str = "audit", retention_days: int = 1825, client=None):
        if client is None:
            try:
                import boto3  # imported lazily: only the S3 deployment needs the dependency
            except ImportError as exc:  # pragma: no cover - exercised only without boto3
                raise RuntimeError("AUDIT_WORM_BACKEND=s3 needs boto3: pip install boto3") from exc
            client = boto3.client("s3")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.retention = timedelta(days=retention_days)

    def put(self, record: StoredEvent, epoch: int = 1) -> str:
        key = object_key(record, self.prefix, epoch)
        self.client.put_object(
            Bucket=self.bucket, Key=key, Body=record.to_json(),
            ContentType="application/json",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=datetime.now(UTC) + self.retention)
        return key

    def read(self, key: str) -> dict:
        return json.loads(self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read())

    def records(self) -> Iterator[tuple[str, dict]]:
        paginator = self.client.get_paginator("list_objects_v2")
        keys = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            keys.extend(item["Key"] for item in page.get("Contents", []))
        for key in sorted(keys):
            yield key, self.read(key)


def worm_from_env() -> WormSink:
    """The sink the job should use, chosen by AUDIT_WORM_BACKEND. Jobs read env directly, like the others."""
    backend = os.environ.get("AUDIT_WORM_BACKEND", "local").lower()
    if backend == "s3":
        return S3WormSink(os.environ["AUDIT_S3_BUCKET"], os.environ.get("AUDIT_S3_PREFIX", "audit"),
                          int(os.environ.get("AUDIT_RETENTION_DAYS", "1825")))
    return LocalWormSink(os.environ.get("AUDIT_WORM_PATH", "audit-worm"))
