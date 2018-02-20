def pad32(bytes_val):
    return bytes_val.rjust(32, b'\x00')
