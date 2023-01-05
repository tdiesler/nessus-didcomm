import sys

from .crypto import bytes_to_b58, b58_to_bytes, bytes_to_b64, b64_to_bytes, create_keypair, random_seed, validate_seed
from .did_key import DIDKey
from .did_method import DIDMethod
from .error import WalletError
from .key_type import KeyType

from typing import NamedTuple

DIDInfo = NamedTuple(
    "DIDInfo",
    [
        ("did", str),
        ("metadata", dict),
        ("method", DIDMethod),
        ("key_type", KeyType),
        ("seed", str),
        ("verkey", str),
        ("secret", str),
    ],
)

def create_local_did(
        method: DIDMethod,
        key_type: KeyType,
        seed: str = None,
        did: str = None,
        metadata: dict = None,
) -> DIDInfo:
    """
    Create and store a new local DID.

    Args:
        method: The method to use for the DID
        key_type: The key type to use for the DID
        seed: Optional seed to use for DID
        did: The DID to use
        metadata: Metadata to store with DID

    Returns:
        A `DIDInfo` instance representing the created DID

    Raises:
        WalletDuplicateError: If the DID already exists in the wallet

    """
    seed = validate_seed(seed) or random_seed()

    # validate key_type
    if not method.supports_key_type(key_type):
        raise WalletError(
            f"Invalid key type {key_type.key_type} for method {method.method_name}"
        )

    verkey, secret = create_keypair(key_type, seed)
    verkey_enc = bytes_to_b58(verkey)

    # We need some did method specific handling. If more did methods
    # are added it is probably better create a did method specific handler
    if method == DIDMethod.KEY:
        if did:
            raise WalletError("Not allowed to set DID for DID method 'key'")

        did = DIDKey.from_public_key(verkey, key_type).did
    elif method == DIDMethod.SOV:
        if not did:
            did = bytes_to_b58(verkey[:16])
    else:
        raise WalletError(f"Unsupported DID method: {method.method_name}")

    # if (did in self.profile.local_dids
    #     and self.profile.local_dids[did]["verkey"] != verkey_enc):
    #     raise WalletDuplicateError("DID already exists in wallet")

    # self.profile.local_dids[did] = {
    #     "seed": seed,
    #     "secret": secret,
    #     "verkey": verkey_enc,
    #     "metadata": metadata.copy() if metadata else {},
    #     "key_type": key_type,
    #     "method": method,
    # }

    return DIDInfo(
        did=did,
        metadata=metadata,
        method=method,
        key_type=key_type,
        seed=seed,
        verkey=verkey_enc,
        secret=secret,
    )


def main():

    def did_for_seed(name: str, seed: str):
        didinfo = create_local_did(DIDMethod.KEY, KeyType.ED25519, seed=seed)
        seed_bytes = didinfo.seed
        verkey_bytes = b58_to_bytes(didinfo.verkey)
        secret_bytes = didinfo.secret
        print()
        print(f"{name}")
        print(f"{didinfo.did}")
        print(f"  seed:      {seed}")
        print(f"  verkey58:  {didinfo.verkey}")
        print(f"  verkeyHex: {verkey_bytes.hex()}")
        print(f"  seedHex:   {seed_bytes.hex()}")
        print(f"  secretHex: {secret_bytes.hex()}")

    did_for_seed("Government", "000000000000000000000000Trustee1")
    did_for_seed("Faber", "00000000000000000000000Endorser1")
    did_for_seed("Alice", "00000000000000000000000000Alice1")


if __name__ == '__main__':
    sys.exit(main())
