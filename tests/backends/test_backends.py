import os

import pytest

from eth_keys.backends import CoinCurveECCBackend
from eth_keys.backends import NativeECCBackend

from eth_utils import (
    keccak,
)


MSG = b'message'
MSGHASH = keccak(MSG)


backends = [
    NativeECCBackend(),
]

try:
    import coincurve
    backends.append(CoinCurveECCBackend())
except ImportError:
    if 'REQUIRE_COINCURVE' in os.environ:
        raise


def backend_id_fn(backend):
    return type(backend).__name__


@pytest.mark.parametrize("backend", backends, ids=backend_id_fn)
def test_ecdsa_sign(backend, key_fixture):
    private_key = backend.PrivateKey(key_fixture['privkey'])
    signature = backend.ecdsa_sign(MSGHASH, private_key)

    assert backend.ecdsa_verify(MSGHASH, signature, private_key.public_key)


@pytest.mark.parametrize("backend", backends, ids=backend_id_fn)
def test_ecdsa_verify(backend, key_fixture):
    signature = backend.Signature(vrs=key_fixture['raw_sig'])
    public_key = backend.PublicKey(key_fixture['pubkey'])

    assert backend.ecdsa_verify(MSGHASH, signature, public_key)


@pytest.mark.parametrize("backend", backends, ids=backend_id_fn)
def test_ecdsa_recover(backend, key_fixture):
    signature = backend.Signature(vrs=key_fixture['raw_sig'])
    public_key = backend.PublicKey(key_fixture['pubkey'])

    assert backend.ecdsa_recover(MSGHASH, signature) == public_key
