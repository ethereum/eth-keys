from eth_keys import (
    keys,
)
from eth_keys.tools.factories import (
    PrivateKeyFactory,
    PublicKeyFactory,
)


def test_private_key_factory():
    actual = PrivateKeyFactory()
    assert actual == keys.PrivateKey(actual.to_bytes())


def test_public_key_factory():
    actual = PublicKeyFactory()
    assert actual == keys.PublicKey(actual.to_bytes())
