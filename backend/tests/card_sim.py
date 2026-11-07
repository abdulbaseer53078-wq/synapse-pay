"""A simulated terminal's card reader and PIN pad: encrypts the way card-service's SimHsm decrypts
(SIM-DUKPT: HKDF-SHA256(BDK, salt=KSN) + AES-256-GCM, envelope sp1.<ksn>.<nonce||ciphertext>). TEST KEYS ONLY."""
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TEST_BDK_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
TEST_PAN = "4111111111111111"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def seal(plaintext: bytes, usage: str, bdk_hex: str = TEST_BDK_HEX) -> str:
    ksn, nonce = os.urandom(10), os.urandom(12)
    key = HKDF(hashes.SHA256(), 32, salt=ksn, info=f"synapsepay/sim-dukpt/v1/{usage}".encode()) \
        .derive(bytes.fromhex(bdk_hex))
    return f"sp1.{_b64(ksn)}.{_b64(nonce + AESGCM(key).encrypt(nonce, plaintext, usage.encode()))}"


def encrypted_card(pan: str = TEST_PAN, bdk_hex: str = TEST_BDK_HEX) -> str:
    return seal(pan.encode(), "data", bdk_hex)


def format0_pin_block(pin: str, pan: str) -> bytes:
    nibbles = [0, len(pin), *map(int, pin)] + [0xF] * (14 - len(pin))
    pan_field = bytes(2) + bytes.fromhex(pan[-13:-1])
    return bytes(((nibbles[2 * i] << 4) | nibbles[2 * i + 1]) ^ pan_field[i] for i in range(8))


def encrypted_pin(pin: str, pan: str = TEST_PAN) -> str:
    return seal(format0_pin_block(pin, pan), "pin")
