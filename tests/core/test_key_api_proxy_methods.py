import pytest

from eth_utils import (
    keccak,
)

from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from eth_keys.exceptions import ValidationError


MSG = b'message'
MSGHASH = keccak(MSG)
PK_BYTES = b'\x01' * 32


@pytest.fixture
def ecc_backend():
    return NativeECCBackend()


@pytest.fixture
def key_api(ecc_backend):
    return KeyAPI(ecc_backend)


@pytest.fixture
def private_key(key_api):
    return key_api.PrivateKey(PK_BYTES)


@pytest.fixture
def public_key(private_key):
    return private_key.public_key


@pytest.fixture
def signature(private_key):
    return private_key.sign_hash(MSGHASH)


def test_proxied_backend_properties(key_api, ecc_backend):
    assert key_api.PublicKey is ecc_backend.PublicKey
    assert key_api.PrivateKey is ecc_backend.PrivateKey
    assert key_api.Signature is ecc_backend.Signature


def test_key_api_ecdsa_sign_validation(key_api, private_key):
    with pytest.raises(ValidationError):
        key_api.ecdsa_sign(MSGHASH, bytes(private_key))
    with pytest.raises(ValidationError):
        key_api.ecdsa_sign(MSG, private_key)

    signature = key_api.ecdsa_sign(MSGHASH, private_key)
    assert signature.verify(MSGHASH, private_key.public_key)


def test_key_api_ecdsa_verify_validation(key_api, signature, public_key):
    with pytest.raises(ValidationError):
        key_api.ecdsa_verify(MSGHASH, bytes(signature), public_key)
    with pytest.raises(ValidationError):
        key_api.ecdsa_verify(MSGHASH, signature, bytes(public_key))
    with pytest.raises(ValidationError):
        key_api.ecdsa_verify(MSG, signature, public_key)

    assert key_api.ecdsa_verify(MSGHASH, signature, public_key)


def test_key_api_ecdsa_recover_validation(key_api, signature, public_key):
    with pytest.raises(ValidationError):
        key_api.ecdsa_recover(MSGHASH, bytes(signature))
    with pytest.raises(ValidationError):
        key_api.ecdsa_recover(MSG, signature)

    assert key_api.ecdsa_recover(MSGHASH, signature) == public_key
