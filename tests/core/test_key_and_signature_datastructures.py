from __future__ import unicode_literals

import pytest

from eth_utils import (
    decode_hex,
    keccak,
    is_same_address,
)

from eth_keys.backends import NativeECCBackend


MSG = b'message'
MSGHASH = keccak(MSG)


@pytest.fixture
def ecc_backend():
    return NativeECCBackend()


PK_BYTES = decode_hex(
    '0x58d23b55bc9cdce1f18c2500f40ff4ab7245df9a89505e9b1fa4851f623d241d'
)
ADDRESS = '0xdc544d1aa88ff8bbd2f2aec754b1f1e99e1812fd'


@pytest.fixture
def private_key(ecc_backend):
    return ecc_backend.PrivateKey(PK_BYTES)


def test_signing_from_private_key_obj(ecc_backend, private_key):
    signature = private_key.sign(MSG)

    assert ecc_backend.ecdsa_verify(MSGHASH, signature, private_key.public_key)


def test_hash_signing_from_private_key_obj(ecc_backend, private_key):
    signature = private_key.sign_hash(MSGHASH)

    assert ecc_backend.ecdsa_verify(MSGHASH, signature, private_key.public_key)


def test_recover_from_public_key_class(ecc_backend, private_key):
    signature = ecc_backend.ecdsa_sign(MSGHASH, private_key)
    public_key = ecc_backend.PublicKey.recover(MSGHASH, signature)

    assert public_key == private_key.public_key


def test_verify_from_public_key_obj(ecc_backend, private_key):
    signature = ecc_backend.ecdsa_sign(MSGHASH, private_key)
    public_key = private_key.public_key

    assert public_key.verify(MSGHASH, signature)


def test_from_private_for_public_key_clasS(ecc_backend, private_key):
    public_key = ecc_backend.PublicKey.from_private(private_key)

    assert public_key == private_key.public_key


def test_verify_from_signature_obj(ecc_backend, private_key):
    signature = ecc_backend.ecdsa_sign(MSGHASH, private_key)

    assert signature.verify(MSGHASH, private_key.public_key)


def test_recover_from_signature_obj(ecc_backend, private_key):
    signature = ecc_backend.ecdsa_sign(MSGHASH, private_key)
    public_key = signature.recover(MSGHASH)

    assert public_key == private_key.public_key


def test_to_address_from_public_key(private_key):
    address = private_key.public_key.to_address()
    assert is_same_address(address, ADDRESS)
