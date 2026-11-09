"""The edge node's hash chain over the sales it queues (PR 6, audit F-06). Pure rules; the cloud checks them at sync.

Each queued item carries `edge_seq` (1, 2, 3... per edge, never reused) and `prev_hash`, the SHA-256 of the previous
item exactly as sent, signature included ("" for the first). Both are inside the signed canonical JSON. So a sale
deleted, reordered or edited in the edge's SQLite shows up here as a gap or a fork, even to someone who also has the
edge's signing key, because the cloud remembers every hash it has seen.
"""
import hashlib
import json


def chain_hash(item: dict) -> str:
    """The same formula as edge-node/edge_node/crypto.py chain_hash: copied, not imported, like canonical()."""
    return hashlib.sha256(json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


def judge(seq: int, prev_hash: str, item_hash: str, seen: dict[int, str], last_seq: int) -> str | None:
    """None if the item extends (or exactly replays) the chain; otherwise why the chain is broken.

    `seen` maps the sequence numbers this batch may touch to the hashes already accepted for them; `last_seq` is the
    highest accepted so far (0 for a new edge).
    """
    if seq <= last_seq:  # a batch resent after a timeout: must be byte-identical to what was accepted
        return None if seen.get(seq) == item_hash else f"edge_seq {seq} was already accepted with different content"
    if seq != last_seq + 1:
        return f"gap: expected edge_seq {last_seq + 1}, got {seq}"
    expected = seen.get(last_seq, "") if last_seq else ""
    if prev_hash != expected:
        return f"edge_seq {seq} does not follow the previous item (prev_hash mismatch)"
    return None
