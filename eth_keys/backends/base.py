from eth_keys.datatypes import (
    PrivateKey,
    PublicKey,
    Signature,
)


class BaseECCBackend(object):
    def __init__(self):
        self.PublicKey = type(
            '{0}PublicKey'.format(type(self).__name__),
            (PublicKey,),
            {'_backend': self},
        )
        self.PrivateKey = type(
            '{0}PrivateKey'.format(type(self).__name__),
            (PrivateKey,),
            {'_backend': self},
        )
        self.Signature = type(
            '{0}Signature'.format(type(self).__name__),
            (Signature,),
            {'_backend': self},
        )

    def ecdsa_sign(self, msg_hash, private_key):
        raise NotImplementedError()

    def ecdsa_verify(self, msg_hash, signature, public_key):
        return self.ecdsa_recover(msg_hash, signature) == public_key

    def ecdsa_recover(self, msg_hash, signature):
        raise NotImplementedError()

    def private_key_to_public_key(self, private_key):
        raise NotImplementedError()
