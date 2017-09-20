import codecs

from eth_utils import decode_hex

from eth_keys.keyfile import decode_keyfile_json


def test_decoding_keyfile(keyfile_data):
    password = codecs.encode(keyfile_data['password'], 'utf8')
    keyfile_json = keyfile_data['json']
    private_key = keyfile_data['priv']

    derived_private_key = decode_keyfile_json(keyfile_json, password)
    assert decode_hex(private_key) == derived_private_key
