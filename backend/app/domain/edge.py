"""Edge nodes (Step 20): identity and the signed offline rules they enforce."""
from datetime import timedelta
from uuid import UUID

EDGE_URI_PREFIX = "urn:synapsepay:edge:"

# How long a rule set stays valid on the edge. Past it, the edge refuses offline payments rather than enforce limits
# the cloud may have tightened since: a box offline for a week must not keep accepting last week's rules.
RULES_TTL = timedelta(hours=72)


def edge_uri(edge_node_id: UUID) -> str:
    """The URI SAN an edge node's certificate carries; the gateway reads the edge_node_id from it."""
    return f"{EDGE_URI_PREFIX}{edge_node_id}"
