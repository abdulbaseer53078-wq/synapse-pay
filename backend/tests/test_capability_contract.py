"""The capability descriptors the code serves must say what the spec's examples promise: a client reads
supports_partial_capture from either one, and a contract that lies is worse than one that says no."""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")  # in requirements.txt; skipped only where it isn't installed yet

from app.infrastructure.methods.card import CARD_CAPABILITIES
from app.infrastructure.methods.offline import OFFLINE_CAPABILITIES
from app.infrastructure.methods.qr import QR_CAPABILITIES
from app.infrastructure.methods.upi import UPI_CAPABILITIES
from app.infrastructure.methods.wallet import WALLET_CAPABILITIES

SPEC = yaml.safe_load((Path(__file__).parents[2] / "spec" / "openapi.yaml").read_text(encoding="utf-8"))
EXAMPLES = SPEC["components"]["examples"]


@pytest.mark.parametrize("example, descriptor", [
    ("CardCapabilities", CARD_CAPABILITIES), ("UpiCapabilities", UPI_CAPABILITIES),
    ("WalletCapabilities", WALLET_CAPABILITIES), ("QrCapabilities", QR_CAPABILITIES),
    ("OfflineCapabilities", OFFLINE_CAPABILITIES),
])
def test_descriptor_matches_the_spec_example(example, descriptor):
    promised, served = EXAMPLES[example]["value"], descriptor.to_dict()
    mismatched = {k: (v, served.get(k)) for k, v in promised.items() if k != "transitions" and served.get(k) != v}
    assert not mismatched, f"{example}: spec example vs code (spec, code): {mismatched}"
