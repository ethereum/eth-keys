import os

from eth_keys.utils.module_loading import (
    import_string,
)
from eth_keys.keyfile import (  # noqa: F401
    load_keyfile,
    create_keyfile_json,
    decode_keyfile_json,
    extract_key_from_keyfile,
)


DEFAULT_ECC_BACKEND = 'eth_keys.backends.coincurve.CoinCurveECCBackend'


def get_backend_class(import_path=None):
    if import_path is None:
        import_path = os.environ.get(
            'ECC_BACKEND_CLASS',
            DEFAULT_ECC_BACKEND,
        )
    return import_string(import_path)


def get_backend(import_path=None):
    backend_class = get_backend_class(import_path)
    return backend_class()
