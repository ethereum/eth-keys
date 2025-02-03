from typing import (
    cast,
)

import factory

from eth_keys.datatypes import (
    PrivateKey,
    PublicKey,
)


def _mk_random_bytes(num_bytes: int) -> bytes:
    try:
        import secrets
    except ImportError:
        import os

        return os.urandom(num_bytes)
    else:
        return secrets.token_bytes(num_bytes)


class PrivateKeyFactory(factory.Factory):
    class Meta:
        model = PrivateKey

    private_key_bytes = factory.LazyFunction(lambda: _mk_random_bytes(32))


class PublicKeyFactory(factory.Factory):
    class Meta:
        model = PublicKey

    public_key_bytes = factory.LazyFunction(
        lambda: cast(PrivateKey, PrivateKeyFactory()).public_key.to_bytes()
    )
