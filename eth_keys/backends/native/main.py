from __future__ import absolute_import

from .ecdsa import (
    ecdsa_raw_recover,
    ecdsa_raw_sign,
    private_key_to_public_key,
)

from eth_keys.backends.base import BaseECCBackend


class NativeECCBackend(BaseECCBackend):
    def ecdsa_sign(self, msg_hash, private_key):
        signature_vrs = ecdsa_raw_sign(msg_hash, bytes(private_key))
        signature = self.Signature(vrs=signature_vrs)
        return signature

    def ecdsa_recover(self, msg_hash, signature):
        public_key_bytes = ecdsa_raw_recover(msg_hash, signature.vrs)
        public_key = self.PublicKey(public_key_bytes)
        return public_key

    def private_key_to_public_key(self, private_key):
        public_key_bytes = private_key_to_public_key(bytes(private_key))
        public_key = self.PublicKey(public_key_bytes)
        return public_key
