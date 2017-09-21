from eth_utils import (
    is_string,
)

from eth_keys.backends import (
    BaseECCBackend,
    get_backend,
)
from eth_keys.datatypes import (
    PublicKey,
    PrivateKey,
    Signature,
)
from eth_keys.exceptions import (
    ValidationError,
)
from eth_keys.validation import (
    validate_message_hash,
)


def backend_property_proxy(name):
    @property
    def property_fn(self):
        backend_property = getattr(self.backend, name)
        return backend_property
    return property_fn


class KeyAPI(object):
    backend = None

    def __init__(self, backend=None):
        if backend is None:
            backend = get_backend()
        elif isinstance(backend, BaseECCBackend):
            pass
        elif isinstance(backend, type) and issubclass(backend, BaseECCBackend):
            backend = backend()
        elif is_string(backend):
            backend = get_backend(backend)
        else:
            raise ValueError(
                "Unsupported format for ECC backend.  Must be an instance or "
                "subclass of `eth_keys.backends.BaseECCBackend` or a string of "
                "the dot-separated import path for the desired backend class"
            )

        self.backend = backend

    #
    # Proxy method calls to the backends
    #
    PublicKey = backend_property_proxy('PublicKey')  # noqa: F811
    PrivateKey = backend_property_proxy('PrivateKey')  # noqa: F811
    Signature = backend_property_proxy('Signature')  # noqa: F811

    def ecdsa_sign(self, message_hash, private_key):
        validate_message_hash(message_hash)
        if not isinstance(private_key, PrivateKey):
            raise ValidationError(
                "The `private_key` must be an instance of `eth_keys.datatypes.PrivateKey`"
            )
        signature = self.backend.ecdsa_sign(message_hash, private_key)
        if not isinstance(signature, Signature):
            raise ValidationError(
                "Backend returned an invalid signature.  Return value must be "
                "an instance of `eth_keys.datatypes.Signature`"
            )
        return signature

    def ecdsa_verify(self, message_hash, signature, public_key):
        if not isinstance(public_key, PublicKey):
            raise ValidationError(
                "The `public_key` must be an instance of `eth_keys.datatypes.PublicKey`"
            )
        return self.ecdsa_recover(message_hash, signature) == public_key

    def ecdsa_recover(self, message_hash, signature):
        validate_message_hash(message_hash)
        if not isinstance(signature, Signature):
            raise ValidationError(
                "The `signature` must be an instance of `eth_keys.datatypes.Signature`"
            )
        public_key = self.backend.ecdsa_recover(message_hash, signature)
        if not isinstance(public_key, PublicKey):
            raise ValidationError(
                "Backend returned an invalid public_key.  Return value must be "
                "an instance of `eth_keys.datatypes.PublicKey`"
            )
        return public_key

    def private_key_to_public_key(self, private_key):
        if not isinstance(private_key, PrivateKey):
            raise ValidationError(
                "The `private_key` must be an instance of `eth_keys.datatypes.PrivateKey`"
            )
        public_key = self.backend.private_key_to_public_key(private_key)
        if not isinstance(public_key, PublicKey):
            raise ValidationError(
                "Backend returned an invalid public_key.  Return value must be "
                "an instance of `eth_keys.datatypes.PublicKey`"
            )
        return public_key
