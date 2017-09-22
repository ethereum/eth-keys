from __future__ import absolute_import
from __future__ import unicode_literals

import codecs
import collections
import sys

from eth_utils import (
    big_endian_to_int,
    int_to_big_endian,
    keccak,
    to_checksum_address,
    to_normalized_address,
)

from eth_keys.utils.address import (
    public_key_bytes_to_address,
)
from eth_keys.utils.numeric import (
    int_to_byte,
)
from eth_keys.utils.padding import (
    pad32,
)

from eth_keys.exceptions import (
    ValidationError,
    BadSignature,
)
from eth_keys.validation import (
    validate_lt_secpk1n,
    validate_lt_secpk1n2,
    validate_lte,
    validate_gte,
    validate_public_key_bytes,
    validate_private_key_bytes,
    validate_signature_bytes,
    validate_integer,
)


try:
    ByteString = collections.abc.ByteString
except AttributeError:
    ByteString = type(
        b'BaseString',
        (collections.Sequence, basestring),  # noqa: F821
        {},
    )


class BackendProxied(object):
    _backend = None

    @property
    def backend(self):
        from eth_keys.backends import get_backend

        if self._backend is None:
            return get_backend()
        else:
            return self._backend

    @classmethod
    def get_backend(cls):
        from eth_keys.backends import get_backend

        if cls._backend is None:
            return get_backend()
        else:
            return cls._backend


class BaseKey(ByteString, collections.Hashable):
    _raw_key = None

    def _to_hex(self):
        return '0x' + codecs.decode(codecs.encode(self._raw_key, 'hex'), 'ascii')

    def __bytes__(self):
        return self._raw_key

    def __hash__(self):
        return big_endian_to_int(keccak(bytes(self)))

    def __str__(self):
        if sys.version_info.major == 2:
            return self.__bytes__()
        else:
            return self._to_hex()

    def __unicode__(self):
        return self.__str__()

    def __int__(self):
        return big_endian_to_int(self._raw_key)

    def __len__(self):
        return 64

    def __getitem__(self, index):
        return self._raw_key[index]

    def __eq__(self, other):
        return bytes(self) == bytes(other)

    def __repr__(self):
        return "'{0}'".format(self._to_hex())

    def __index__(self):
        return self.__int__()

    def __hex__(self):
        if sys.version_info.major == 2:
            return codecs.encode(self._to_hex(), 'ascii')
        else:
            return self._to_hex()


class PublicKey(BaseKey, BackendProxied):
    def __init__(self, public_key_bytes):
        validate_public_key_bytes(public_key_bytes)

        self._raw_key = public_key_bytes

    @classmethod
    def from_private(cls, private_key):
        return cls.get_backend().private_key_to_public_key(private_key)

    @classmethod
    def recover_msg(cls, message, signature):
        message_hash = keccak(message)
        return cls.recover_msg_hash(message_hash, signature)

    @classmethod
    def recover_msg_hash(cls, message_hash, signature):
        return cls.get_backend().ecdsa_recover(message_hash, signature)

    def verify_msg(self, message, signature):
        message_hash = keccak(message)
        return self.verify_msg_hash(message_hash, signature)

    def verify_msg_hash(self, message_hash, signature):
        return self.backend.ecdsa_verify(message_hash, signature, self)

    #
    # Ethereum address conversions
    #
    def to_checksum_address(self):
        return to_checksum_address(public_key_bytes_to_address(bytes(self)))

    def to_address(self):
        return to_normalized_address(public_key_bytes_to_address(bytes(self)))

    def to_canonical_address(self):
        return public_key_bytes_to_address(bytes(self))


class PrivateKey(BaseKey, BackendProxied):
    public_key = None

    def __init__(self, private_key_bytes):
        validate_private_key_bytes(private_key_bytes)

        self._raw_key = private_key_bytes

        self.public_key = self.backend.private_key_to_public_key(self)

    def sign(self, message):
        message_hash = keccak(message)
        return self.sign_hash(message_hash)

    def sign_hash(self, message_hash):
        return self.backend.ecdsa_sign(message_hash, self)


class Signature(ByteString, BackendProxied):
    _backend = None
    _v = None
    _r = None
    _s = None

    def __init__(self, signature_bytes=None, vrs=None):
        if bool(signature_bytes) is bool(vrs):
            raise TypeError("You must provide one of `signature_bytes` or `vrs`")
        elif signature_bytes:
            validate_signature_bytes(signature_bytes)
            try:
                self.r = big_endian_to_int(signature_bytes[0:32])
                self.s = big_endian_to_int(signature_bytes[32:64])
                self.v = ord(signature_bytes[64:65]) + 27
            except ValidationError as err:
                raise BadSignature(str(err))
        elif vrs:
            v, r, s, = vrs
            try:
                self.v = v
                self.r = r
                self.s = s
            except ValidationError as err:
                raise BadSignature(str(err))
        else:
            raise TypeError("Invariant: unreachable code path")

    #
    # v
    #
    @property
    def v(self):
        return self._v

    @v.setter
    def v(self, value):
        validate_integer(value)
        validate_gte(value, minimum=27)
        validate_lte(value, maximum=28)

        self._v = value

    #
    # r
    #
    @property
    def r(self):
        return self._r

    @r.setter
    def r(self, value):
        validate_integer(value)
        validate_gte(value, 0)
        validate_lt_secpk1n(value)

        self._r = value

    #
    # s
    #
    @property
    def s(self):
        return self._s

    @s.setter
    def s(self, value):
        validate_integer(value)
        validate_gte(value, 0)
        validate_lt_secpk1n(value)
        validate_lt_secpk1n2(value)

        self._s = value

    @property
    def vrs(self):
        return (self.v, self.r, self.s)

    def _to_hex(self):
        return '0x' + codecs.decode(codecs.encode(bytes(self), 'hex'), 'ascii')

    def __hash__(self):
        return big_endian_to_int(keccak(bytes(self)))

    def __bytes__(self):
        vb = int_to_byte(self.v - 27)
        rb = pad32(int_to_big_endian(self.r))
        sb = pad32(int_to_big_endian(self.s))
        return b''.join((rb, sb, vb))

    def __str__(self):
        if sys.version_info.major == 2:
            return self.__bytes__()
        else:
            return self._to_hex()

    def __unicode__(self):
        return self.__str__()

    def __len__(self):
        return 65

    def __getitem__(self, index):
        return bytes(self)[index]

    def __repr__(self):
        return "'{0}'".format(self._to_hex())

    def verify_msg(self, message, public_key):
        message_hash = keccak(message)
        return self.verify_msg_hash(message_hash, public_key)

    def verify_msg_hash(self, message_hash, public_key):
        return self.backend.ecdsa_verify(message_hash, self, public_key)

    def recover_msg(self, message):
        message_hash = keccak(message)
        return self.recover_msg_hash(message_hash)

    def recover_msg_hash(self, message_hash):
        return self.backend.ecdsa_recover(message_hash, self)

    def __index__(self):
        return self.__int__()

    def __hex__(self):
        if sys.version_info.major == 2:
            return codecs.encode(self._to_hex(), 'ascii')
        else:
            return self._to_hex()

    def __int__(self):
        return big_endian_to_int(bytes(self))
