import sys

from .crypto import bytes_to_b58, bytes_to_b64, create_ed25519_keypair, create_keypair, random_seed, validate_seed
from .did_info import DIDInfo
from .did_key import DIDKey
from .did_method import DIDMethod
from .error import WalletError
from .key_type import KeyType


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
        verkey=verkey_enc,
        metadata=metadata,
        method=method,
        key_type=key_type,
    )


def main():

    seed = validate_seed("000000000000000000000000Trustee1")
    print(f"seed: {seed.hex()}")

    verkey, prvkey = create_ed25519_keypair(seed)
    print(f"pubk: {verkey.hex()}")
    print(f"prvk: {prvkey.hex()}")

    verkey64 = bytes_to_b64(verkey)
    verkey58 = bytes_to_b58(verkey)
    # print(f"verkey64: {verkey64}")
    # print(f"verkey58: {verkey58}")

    did = bytes_to_b58(verkey[:16])
    didinfo = create_local_did(DIDMethod.SOV, KeyType.ED25519, seed=seed)
    print(f"did:sov:{didinfo.did}")
    print(f"verkey: {didinfo.verkey}")
    assert didinfo.verkey == verkey58
    assert didinfo.did == did
    print("")

    didinfo = create_local_did(DIDMethod.KEY, KeyType.ED25519, seed=seed)
    print(f"{didinfo.did}")
    print(f"verkey: {didinfo.verkey}")
    assert didinfo.verkey == verkey58

    return 0


if __name__ == '__main__':
    sys.exit(main())
