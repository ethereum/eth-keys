import pytest

from hypothesis import (
    given,
    strategies as st,
)

from eth_utils import (
    int_to_big_endian,
    keccak,
)

from eth_keys.utils.padding import (
    pad32,
)

from eth_keys.backends import CoinCurveECCBackend
from eth_keys.backends import NativeECCBackend
from eth_keys.constants import (
    SECPK1_N,
)


private_key_st = st.integers(min_value=1, max_value=SECPK1_N).map(
    int_to_big_endian,
).map(pad32)


message_hash_st = st.binary(min_size=32, max_size=32)


MSG = b'message'
MSGHASH = keccak(MSG)


@pytest.fixture
def native_backend():
    return NativeECCBackend()


@pytest.fixture
def coincurve_backend():
    return CoinCurveECCBackend()


@given(private_key_bytes=private_key_st)
def test_public_key_generation_is_equal(private_key_bytes,
                                        native_backend,
                                        coincurve_backend):
    native_public_key = native_backend.PrivateKey(private_key_bytes).public_key
    coincurve_public_key = coincurve_backend.PrivateKey(private_key_bytes).public_key

    assert native_public_key == coincurve_public_key


@given(private_key_bytes=private_key_st, message_hash=message_hash_st)
def test_native_to_coincurve_recover(private_key_bytes,
                                     message_hash,
                                     native_backend,
                                     coincurve_backend):
    native_pk = native_backend.PrivateKey(private_key_bytes)
    native_signature = native_backend.ecdsa_sign(message_hash, native_pk)

    recovered_public_key = coincurve_backend.ecdsa_recover(message_hash, native_signature)
    assert recovered_public_key == native_pk.public_key


@given(private_key_bytes=private_key_st, message_hash=message_hash_st)
def test_coincurve_to_native_recover(private_key_bytes,
                                     message_hash,
                                     native_backend,
                                     coincurve_backend):
    coincurve_pk = coincurve_backend.PrivateKey(private_key_bytes)
    coincurve_signature = coincurve_backend.ecdsa_sign(message_hash, coincurve_pk)

    recovered_public_key = native_backend.ecdsa_recover(message_hash, coincurve_signature)
    assert recovered_public_key == coincurve_pk.public_key
