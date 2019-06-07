from eth_keys.constants import (
    SECPK1_N,
)


def int_to_byte(value: int) -> bytes:
    return bytes([value])


def coerce_low_s(value: int) -> int:
    return min(value, -value % SECPK1_N)
