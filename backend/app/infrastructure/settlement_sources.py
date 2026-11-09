"""Where settlement files come from (PR 7): a directory (the sandbox, or an SFTP drop synced to disk) or S3.

shortcut: no SFTP client; an acquirer that only offers SFTP is mirrored into S3 or a directory by the transfer job
that already exists in most acquiring setups. Add a paramiko-based source if one must be pulled directly.
"""
from pathlib import Path
from typing import Iterator


class DirectorySource:
    def __init__(self, path: str):
        self.path = Path(path)

    def files(self) -> Iterator[tuple[str, bytes]]:
        for file in sorted(self.path.glob("*.csv")):
            yield str(file), file.read_bytes()


class S3Source:
    def __init__(self, url: str, client=None):
        bucket, _, prefix = url.removeprefix("s3://").partition("/")
        self.bucket, self.prefix = bucket, prefix
        if client is None:
            import boto3  # only this source needs it
            client = boto3.client("s3")
        self.client = client

    def files(self) -> Iterator[tuple[str, bytes]]:
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in sorted(page.get("Contents", []), key=lambda o: o["Key"]):
                if obj["Key"].endswith(".csv"):
                    body = self.client.get_object(Bucket=self.bucket, Key=obj["Key"])["Body"].read()
                    yield f"s3://{self.bucket}/{obj['Key']}", body


def source(spec: str):
    return S3Source(spec) if spec.startswith("s3://") else DirectorySource(spec.removeprefix("dir:"))
