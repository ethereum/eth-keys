from cytoolz import (
    curry,
)

from eth_utils import (
    is_bytes,
    is_integer,
)

from eth_keys.constants import (
    SECPK1_N,
)
from eth_keys.exceptions import (
    ValidationError,
)


def validate_integer(value):
    if not is_integer(value) or isinstance(value, bool):
        raise ValidationError("Value must be a an integer.  Got: {0}".format(type(value)))


def validate_bytes(value):
    if not is_bytes(value):
        raise ValidationError("Value must be a byte string.  Got: {0}".format(type(value)))


@curry
def validate_gte(value, minimum):
    validate_integer(value)
    if value < minimum:
        raise ValidationError(
            "Value {0} is not greater than or equal to {1}".format(
                value, minimum,
            )
        )


@curry
def validate_lte(value, maximum):
    validate_integer(value)
    if value > maximum:
        raise ValidationError(
            "Value {0} is not less than or equal to {1}".format(
                value, maximum,
            )
        )


validate_lt_secpk1n = validate_lte(maximum=SECPK1_N - 1)
validate_lt_secpk1n2 = validate_lte(maximum=SECPK1_N // 2 - 1)


def validate_message_hash(value):
    validate_bytes(value)
    if len(value) != 32:
        raise ValidationError("Unexpected signature format.  Must be length 65 byte string")


def validate_public_key_bytes(value):
    validate_bytes(value)
    if len(value) != 64:
        raise ValidationError("Unexpected public key format.  Must be length 64 byte string")


def validate_private_key_bytes(value):
    validate_bytes(value)
    if len(value) != 32:
        raise ValidationError("Unexpected private key format.  Must be length 32 byte string")


def validate_signature_bytes(value):
    validate_bytes(value)
    if len(value) != 65:
        raise ValidationError("Unexpected signature format.  Must be length 65 byte string")
