from typing import Any  # noqa: F401

from eth_keys.datatypes import (
    PrivateKey,
    PublicKey,
    Signature,
)


class BaseECCBackend(object):
    def ecdsa_sign(self,
                   msg_hash: bytes,
                   private_key: PrivateKey) -> Signature:
        raise NotImplementedError()

    def ecdsa_verify(self,
                     msg_hash: bytes,
                     signature: Signature,
                     public_key: PublicKey) -> bool:
        return self.ecdsa_recover(msg_hash, signature) == public_key

    def ecdsa_recover(self,
                      msg_hash: bytes,
                      signature: Signature) -> PublicKey:
        raise NotImplementedError()

    def private_key_to_public_key(self,
                                  private_key: PrivateKey) -> PublicKey:
        raise NotImplementedError()
