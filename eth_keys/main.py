from typing import (Any, Union)  # noqa: F401

from eth_keys.datatypes import (
    LazyBackend,
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


class KeyAPI(LazyBackend):
    #
    # datatype shortcuts
    #
    PublicKey = PublicKey  # type: PublicKey
    PrivateKey = PrivateKey  # type: PrivateKey
    Signature = Signature  # type: Signature

    #
    # Proxy method calls to the backends
    #
    def ecdsa_sign(self,
                   message_hash,  # type: bytes
                   private_key  # type: PrivateKey
                   ):
        # type: (...) -> Signature
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

    def ecdsa_verify(self,
                     message_hash,  # type: bytes
                     signature,  # type: Signature
                     public_key  # type: PublicKey
                     ):
        # type: (...) -> bool
        if not isinstance(public_key, PublicKey):
            raise ValidationError(
                "The `public_key` must be an instance of `eth_keys.datatypes.PublicKey`"
            )
        return self.ecdsa_recover(message_hash, signature) == public_key

    def ecdsa_recover(self,
                      message_hash,  # type: bytes
                      signature  # type: Signature
                      ):
        # type: (...) -> PublicKey
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


# This creates an easy to import backend which will lazily fetch whatever
# backend has been configured at runtime (as opposed to import or instantiation time).
lazy_key_api = KeyAPI(backend=None)
