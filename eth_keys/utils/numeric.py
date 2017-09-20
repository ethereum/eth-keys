import sys


if sys.version_info.major == 2:
    import struct
    import codecs
    import binascii

    def int_to_big_endian(value):
        if value == 0:
            return b'\x00'

        value_as_hex = (hex(value)[2:]).rstrip('L')

        if len(value_as_hex) % 2:
            return binascii.unhexlify('0' + value_as_hex)
        else:
            return binascii.unhexlify(value_as_hex)

    def big_endian_to_int(value):
        if len(value) == 1:
            return ord(value)
        elif len(value) <= 8:
            return struct.unpack('>Q', value.rjust(8, '\x00'))[0]
        else:
            return int(codecs.encode(value, 'hex'), 16)

    int_to_byte = chr
else:
    import math

    def int_to_big_endian(value):
        byte_length = math.ceil(value.bit_length() / 8)
        return (value).to_bytes(byte_length, byteorder='big')

    def big_endian_to_int(value):
        return int.from_bytes(value, byteorder='big')

    def int_to_byte(value):
        return bytes([value])
