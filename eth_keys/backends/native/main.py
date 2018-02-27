from __future__ import absolute_import

from typing import Optional  # noqa: F401

from .ecdsa import (
    ecdsa_raw_recover,
    ecdsa_raw_sign,
    private_key_to_public_key,
)

from eth_keys.backends.base import BaseECCBackend
from eth_keys.datatypes import (  # noqa: F401
    PrivateKey,
    PublicKey,
    Signature,
)


class NativeECCBackend(BaseECCBackend):
    def ecdsa_sign(self,
                   msg_hash: bytes,
                   private_key: PrivateKey) -> Signature:
        signature_vrs = ecdsa_raw_sign(msg_hash, private_key.to_bytes())
        signature = Signature(vrs=signature_vrs, backend=self)
        return signature

    def ecdsa_recover(self,
                      msg_hash: bytes,
                      signature: Signature) -> PublicKey:
        public_key_bytes = ecdsa_raw_recover(msg_hash, signature.vrs)
        public_key = PublicKey(public_key_bytes, backend=self)
        return public_key

    def private_key_to_public_key(self, private_key: PrivateKey) -> PublicKey:
        public_key_bytes = private_key_to_public_key(private_key.to_bytes())
        public_key = PublicKey(public_key_bytes, backend=self)
        return public_key
