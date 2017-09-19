import codecs
import collections

from cytoolz import (
    partial,
)

from eth_utils import (
    pad_left,
)

from eth_keys import (
    get_backend,
)

from eth_keys.utils.numeric import (
    big_endian_to_int,
    int_to_big_endian,
    int_to_byte,
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


pad32 = partial(pad_left, to_size=32, pad_with=b'\x00')


class BaseKey(collections.abc.ByteString):
    _backend = None
    _raw_key = None

    @property
    def backend(self):
        if self._backend is None:
            return get_backend()
        else:
            return self._backend

    def __bytes__(self):
        return self._raw_key

    def __str__(self):
        return '0x' + codecs.decode(codecs.encode(self._raw_key, 'hex'), 'ascii')

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


class PublicKey(BaseKey):
    def __init__(self, public_key_bytes):
        validate_public_key_bytes(public_key_bytes)

        self._raw_key = public_key_bytes

    @classmethod
    def from_private(self, private_key):
        pass

    @classmethod
    def recover(self, signature):
        # return instantiated public key
        raise NotImplementedError("Not yet implemented")

    def verify(self, signature):
        raise NotImplementedError("Not yet implemented")


class PrivateKey(BaseKey):
    public_key = None

    def __init__(self, private_key_bytes):
        validate_private_key_bytes(private_key_bytes)

        self._raw_key = private_key_bytes

        self.public_key = self.backend.private_key_to_public_key(self)

    def sign(self, message):
        raise NotImplementedError("Not yet implemented")


class Signature(collections.abc.ByteString):
    _backend = None
    _v = None
    _r = None
    _s = None

    def __init__(self, signature_bytes=None, vrs=None):
        if bool(signature_bytes) is bool(vrs):
            raise TypeError("You must provide one of `signature_bytes` or `vrs`")
        elif signature_bytes:
            validate_signature_bytes(signature_bytes)
            self.r = big_endian_to_int(signature_bytes[0:32])
            self.s = big_endian_to_int(signature_bytes[32:64])
            self.v = signature_bytes[64] + 27
        elif vrs:
            v, r, s, = vrs
            self.v = v
            self.r = r
            self.s = s
        else:
            raise TypeError("Invariant: unreachable code path")

    @property
    def backend(self):
        if self._backend is None:
            return get_backend()
        else:
            return self._backend

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

    def __bytes__(self):
        vb = int_to_byte(self.v - 27)
        rb = pad32(int_to_big_endian(self.r))
        sb = pad32(int_to_big_endian(self.s))
        return b''.join((rb, sb, vb))

    def __str__(self):
        return '0x' + codecs.decode(codecs.encode(bytes(self), 'hex'), 'ascii')

    def __unicode__(self):
        return self.__str__()

    def __len__(self):
        return 65

    def __getitem__(self, index):
        return bytes(self)[index]
