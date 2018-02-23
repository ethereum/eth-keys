import os

import pytest

from eth_keys import KeyAPI
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


@pytest.fixture(params=backends, ids=backend_id_fn)
def key_api(request):
    return KeyAPI(backend=request.param)


def test_ecdsa_sign(key_api, key_fixture):
    private_key = key_api.PrivateKey(key_fixture['privkey'])
    signature = key_api.ecdsa_sign(MSGHASH, private_key)

    assert key_api.ecdsa_verify(MSGHASH, signature, private_key.public_key)


def test_ecdsa_verify(key_api, key_fixture):
    signature = key_api.Signature(vrs=key_fixture['raw_sig'])
    public_key = key_api.PublicKey(key_fixture['pubkey'])

    assert key_api.ecdsa_verify(MSGHASH, signature, public_key)


def test_ecdsa_recover(key_api, key_fixture):
    signature = key_api.Signature(vrs=key_fixture['raw_sig'])
    public_key = key_api.PublicKey(key_fixture['pubkey'])

    assert key_api.ecdsa_recover(MSGHASH, signature) == public_key
