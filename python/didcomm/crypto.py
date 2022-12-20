import base58
import base64
import nacl.utils
import nacl.bindings

from .error import WalletError
from .key_type import KeyType

from typing import Tuple, Union


def b58_to_bytes(val: str) -> bytes:
    """Convert a base 58 string to bytes."""
    return base58.b58decode(val)


def bytes_to_b58(val: bytes) -> str:
    """Convert a byte string to base 58."""
    return base58.b58encode(val).decode("ascii")


def b64_to_bytes(val: str, urlsafe=False) -> bytes:
    """Convert a base 64 string to bytes."""
    if urlsafe:
        return base64.urlsafe_b64decode(pad(val))
    return base64.b64decode(pad(val))


def b64_to_str(val: str, urlsafe=False, encoding=None) -> str:
    """Convert a base 64 string to string on input encoding (default utf-8)."""
    return b64_to_bytes(val, urlsafe).decode(encoding or "utf-8")


def bytes_to_b64(val: bytes, urlsafe=False, pad=True, encoding: str = "ascii") -> str:
    """Convert a byte string to base 64."""
    b64 = (
        base64.urlsafe_b64encode(val).decode(encoding)
        if urlsafe
        else base64.b64encode(val).decode(encoding)
    )
    return b64 if pad else unpad(b64)


def pad(val: str) -> str:
    """Pad base64 values if need be: JWT calls to omit trailing padding."""
    padlen = 4 - len(val) % 4
    return val if padlen > 2 else (val + "=" * padlen)


def unpad(val: str) -> str:
    """Remove padding from base64 values if need be."""
    return val.rstrip("=")


def random_seed() -> bytes:
    """
    Generate a random seed value.

    Returns:
        A new random seed

    """
    return nacl.utils.random(nacl.bindings.crypto_box_SEEDBYTES)


def create_keypair(key_type: KeyType, seed: bytes = None) -> Tuple[bytes, bytes]:
    """
    Create a public and private keypair from a seed value.

    Args:
        key_type: The type of key to generate
        seed: Seed for keypair

    Raises:
        WalletError: If the key type is not supported

    Returns:
        A tuple of (public key, secret key)

    """
    if key_type == KeyType.ED25519:
        return create_ed25519_keypair(seed)
    else:
        raise WalletError(f"Unsupported key type: {key_type.key_type}")


def create_ed25519_keypair(seed: bytes = None) -> Tuple[bytes, bytes]:
    """
    Create a public and private ed25519 keypair from a seed value.

    Args:
        seed: Seed for keypair

    Returns:
        A tuple of (public key, secret key)

    """
    if not seed:
        seed = random_seed()
    pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
    return pk, sk


def ed25519_pk_to_curve25519(public_key: bytes) -> bytes:
    """Covert a public Ed25519 key to a public Curve25519 key as bytes."""
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(public_key)


def seed_to_did(seed: str) -> str:
    """
    Derive a DID from a seed value.

    Args:
        seed: The seed to derive

    Returns:
        The DID derived from the seed

    """
    seed = validate_seed(seed)
    verkey, _ = create_ed25519_keypair(seed)
    did = bytes_to_b58(verkey[:16])
    return did


def validate_seed(seed: Union[str, bytes]) -> bytes:
    """
    Convert a seed parameter to standard format and check length.

    Args:
        seed: The seed to validate

    Returns:
        The validated and encoded seed

    """
    if not seed:
        return None
    if isinstance(seed, str):
        if "=" in seed:
            seed = b64_to_bytes(seed)
        else:
            seed = seed.encode("ascii")
    if not isinstance(seed, bytes):
        raise Exception("Seed value is not a string or bytes")
    if len(seed) != 32:
        raise Exception("Seed value must be 32 bytes in length")
    return seed
