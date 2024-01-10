import pytest

from eth_keys import (
    KeyAPI,
)
from eth_keys.backends import (
    NativeECCBackend,
)


@pytest.fixture(autouse=True)
def native_backend_env_var(monkeypatch):
    monkeypatch.setenv("ECC_BACKEND_CLASS", "eth_keys.backends.native.NativeECCBackend")


@pytest.mark.parametrize(
    "backend",
    (
        None,
        NativeECCBackend(),
        NativeECCBackend,
        "eth_keys.backends.NativeECCBackend",
        "eth_keys.backends.native.NativeECCBackend",
    ),
)
def test_supported_backend_formats(backend):
    keys = KeyAPI(backend=backend)
    assert isinstance(keys.backend, NativeECCBackend)
