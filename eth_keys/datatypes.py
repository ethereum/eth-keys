from __future__ import absolute_import

import codecs
import collections
import sys
from typing import (    # noqa: F401
    Any,
    Tuple,
    Union,
    Type,
    TYPE_CHECKING,
)

from eth_utils import (
    big_endian_to_int,
    int_to_big_endian,
    is_bytes,
    is_string,
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
    BadSignature,
    ValidationError,
)
from eth_keys.validation import (
    validate_gte,
    validate_integer,
    validate_lt_secpk1n,
    validate_lte,
    validate_private_key_bytes,
    validate_public_key_bytes,
    validate_signature_bytes,
)

if TYPE_CHECKING:
    from eth_keys.backends.base import BaseECCBackend  # noqa: F401


# Must compare against version_info[0] and not version_info.major to please mypy.
if sys.version_info[0] == 2:
    ByteString = type(
        b'BaseString',
        (collections.Sequence, basestring),  # noqa: F821
        {},
    )  # type: Any
else:
    ByteString = collections.abc.ByteString


class LazyBackend:
    def __init__(self,
                 backend: 'Union[BaseECCBackend, Type[BaseECCBackend], str, None]' = None,
                 ) -> None:
        from eth_keys.backends.base import (  # noqa: F811
            BaseECCBackend,
        )

        if backend is None:
            pass
        elif isinstance(backend, BaseECCBackend):
            pass
        elif isinstance(backend, type) and issubclass(backend, BaseECCBackend):
            backend = backend()
        elif is_string(backend):
            backend = self.get_backend(backend)
        else:
            raise ValueError(
                "Unsupported format for ECC backend.  Must be an instance or "
                "subclass of `eth_keys.backends.BaseECCBackend` or a string of "
                "the dot-separated import path for the desired backend class"
            )

        self.backend = backend

    _backend = None  # type: BaseECCBackend

    @property
    def backend(self) -> 'BaseECCBackend':
        if self._backend is None:
            return self.get_backend()
        else:
            return self._backend

    @backend.setter
    def backend(self, value: 'BaseECCBackend') -> None:
        self._backend = value

    @classmethod
    def get_backend(cls, *args: Any, **kwargs: Any) -> 'BaseECCBackend':
        from eth_keys.backends import get_backend
        return get_backend(*args, **kwargs)


class BaseKey(ByteString, collections.Hashable):
    _raw_key = None  # type: bytes

    def to_hex(self) -> str:
        # Need the 'type: ignore' comment below because of
        # https://github.com/python/typeshed/issues/300
        return '0x' + codecs.decode(codecs.encode(self._raw_key, 'hex'), 'ascii')  # type: ignore

    def to_bytes(self) -> bytes:
        return self._raw_key

    def __hash__(self) -> int:
        return big_endian_to_int(keccak(self.to_bytes()))

    def __str__(self) -> str:
        return self.to_hex()

    def __int__(self) -> int:
        return big_endian_to_int(self._raw_key)

    def __len__(self) -> int:
        # TODO: this seems wrong.
        return 64

    # Must be typed with `ignore` due to
    # https://github.com/python/mypy/issues/1237
    def __getitem__(self, index: int) -> int:  # type: ignore
        return self._raw_key[index]

    def __eq__(self, other: Any) -> bool:
        if hasattr(other, 'to_bytes'):
            return self.to_bytes() == other.to_bytes()
        elif is_bytes(other):
            return self.to_bytes() == other
        else:
            return False

    def __repr__(self) -> str:
        return "'{0}'".format(self.to_hex())

    def __index__(self) -> int:
        return self.__int__()

    def __hex__(self) -> str:
        if sys.version_info[0] == 2:
            return codecs.encode(self.to_hex(), 'ascii')
        else:
            return self.to_hex()


class PublicKey(BaseKey, LazyBackend):
    def __init__(self,
                 public_key_bytes: bytes,
                 backend: 'Union[BaseECCBackend, Type[BaseECCBackend], str, None]' = None,
                 ) -> None:
        validate_public_key_bytes(public_key_bytes)

        self._raw_key = public_key_bytes
        super().__init__(backend=backend)

    @classmethod
    def from_private(cls,
                     private_key: 'PrivateKey',
                     backend: 'BaseECCBackend' = None,
                     ) -> 'PublicKey':
        if backend is None:
            backend = cls.get_backend()
        return backend.private_key_to_public_key(private_key)

    @classmethod
    def recover_from_msg(cls,
                         message: bytes,
                         signature: 'Signature',
                         backend: 'BaseECCBackend' = None,
                         ) -> 'PublicKey':
        message_hash = keccak(message)
        return cls.recover_from_msg_hash(message_hash, signature, backend)

    @classmethod
    def recover_from_msg_hash(cls,
                              message_hash: bytes,
                              signature: 'Signature',
                              backend: 'BaseECCBackend' = None,
                              ) -> 'PublicKey':
        if backend is None:
            backend = cls.get_backend()
        return backend.ecdsa_recover(message_hash, signature)

    def verify_msg(self,
                   message: bytes,
                   signature: 'Signature',
                   ) -> bool:
        message_hash = keccak(message)
        return self.verify_msg_hash(message_hash, signature)

    def verify_msg_hash(self,
                        message_hash: bytes,
                        signature: 'Signature',
                        ) -> bool:
        return self.backend.ecdsa_verify(message_hash, signature, self)

    #
    # Ethereum address conversions
    #
    def to_checksum_address(self) -> bytes:
        return to_checksum_address(public_key_bytes_to_address(self.to_bytes()))

    def to_address(self) -> str:
        return to_normalized_address(public_key_bytes_to_address(self.to_bytes()))

    def to_canonical_address(self) -> bytes:
        return public_key_bytes_to_address(self.to_bytes())


class PrivateKey(BaseKey, LazyBackend):
    public_key = None  # type: PublicKey

    def __init__(self,
                 private_key_bytes: bytes,
                 backend: 'Union[BaseECCBackend, Type[BaseECCBackend], str, None]' = None,
                 ) -> None:
        validate_private_key_bytes(private_key_bytes)

        self._raw_key = private_key_bytes

        self.public_key = self.backend.private_key_to_public_key(self)
        super().__init__(backend=backend)

    def sign_msg(self, message: bytes) -> 'Signature':
        message_hash = keccak(message)
        return self.sign_msg_hash(message_hash)

    def sign_msg_hash(self, message_hash: bytes) -> 'Signature':
        return self.backend.ecdsa_sign(message_hash, self)


class Signature(ByteString, LazyBackend):
    _v = None  # type: int
    _r = None  # type: int
    _s = None  # type: int

    def __init__(self,
                 signature_bytes: bytes = None,
                 vrs: Tuple[int, int, int] = None,
                 backend: 'Union[BaseECCBackend, Type[BaseECCBackend], str, None]' = None,
                 ) -> None:
        if bool(signature_bytes) is bool(vrs):
            raise TypeError("You must provide one of `signature_bytes` or `vrs`")
        elif signature_bytes:
            validate_signature_bytes(signature_bytes)
            try:
                self.r = big_endian_to_int(signature_bytes[0:32])
                self.s = big_endian_to_int(signature_bytes[32:64])
                self.v = ord(signature_bytes[64:65])
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

        super().__init__(backend=backend)

    #
    # v
    #
    @property
    def v(self) -> int:
        return self._v

    @v.setter
    def v(self, value: int) -> None:
        validate_integer(value)
        validate_gte(value, minimum=0)
        validate_lte(value, maximum=1)

        self._v = value

    #
    # r
    #
    @property
    def r(self) -> int:
        return self._r

    @r.setter
    def r(self, value: int) -> None:
        validate_integer(value)
        validate_gte(value, 0)
        validate_lt_secpk1n(value)

        self._r = value

    #
    # s
    #
    @property
    def s(self) -> int:
        return self._s

    @s.setter
    def s(self, value: int) -> None:
        validate_integer(value)
        validate_gte(value, 0)
        validate_lt_secpk1n(value)

        self._s = value

    @property
    def vrs(self) -> Tuple[int, int, int]:
        return (self.v, self.r, self.s)

    def to_hex(self) -> str:
        # Need the 'type: ignore' comment below because of
        # https://github.com/python/typeshed/issues/300
        return '0x' + codecs.decode(codecs.encode(self.to_bytes(), 'hex'), 'ascii')  # type: ignore

    def to_bytes(self) -> bytes:
        return self.__bytes__()

    def __hash__(self) -> int:
        return big_endian_to_int(keccak(self.to_bytes()))

    def __bytes__(self) -> bytes:
        vb = int_to_byte(self.v)
        rb = pad32(int_to_big_endian(self.r))
        sb = pad32(int_to_big_endian(self.s))
        return b''.join((rb, sb, vb))

    def __str__(self) -> str:
        return self.to_hex()

    def __len__(self) -> int:
        return 65

    def __eq__(self, other: Any) -> bool:
        if hasattr(other, 'to_bytes'):
            return self.to_bytes() == other.to_bytes()
        elif is_bytes(other):
            return self.to_bytes() == other
        else:
            return False

    # Must be typed with `ignore` due to
    # https://github.com/python/mypy/issues/1237
    def __getitem__(self, index: int) -> int:  # type: ignore
        return self.to_bytes()[index]

    def __repr__(self) -> str:
        return "'{0}'".format(self.to_hex())

    def verify_msg(self,
                   message: bytes,
                   public_key: PublicKey) -> bool:
        message_hash = keccak(message)
        return self.verify_msg_hash(message_hash, public_key)

    def verify_msg_hash(self,
                        message_hash: bytes,
                        public_key: PublicKey) -> bool:
        return self.backend.ecdsa_verify(message_hash, self, public_key)

    def recover_public_key_from_msg(self, message: bytes) -> PublicKey:
        message_hash = keccak(message)
        return self.recover_public_key_from_msg_hash(message_hash)

    def recover_public_key_from_msg_hash(self, message_hash: bytes) -> PublicKey:
        return self.backend.ecdsa_recover(message_hash, self)

    def __index__(self) -> int:
        return self.__int__()

    def __hex__(self) -> str:
        if sys.version_info[0] == 2:
            return codecs.encode(self.to_hex(), 'ascii')
        else:
            return self.to_hex()

    def __int__(self) -> int:
        return big_endian_to_int(self.to_bytes())
