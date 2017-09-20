import json

import pytest

from eth_utils import decode_hex

from eth_keys.keyfile import (
    create_keyfile_json,
    load_keyfile,
    extract_key_from_keyfile,
)


PRIVATE_KEY = decode_hex('7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d')
PASSWORD = b'foo'

@pytest.fixture(params=['pbkdf2', 'scrypt'])
def keyfile_json(request):
    _keyfile_json = create_keyfile_json(PRIVATE_KEY, PASSWORD, kdf=request.param, iterations=2)
    return _keyfile_json

@pytest.fixture()
def keyfile_path(tmpdir, keyfile_json):
    _keyfile_path = tmpdir.join("keyfile.json")
    _keyfile_path.write(json.dumps(keyfile_json))
    return str(_keyfile_path)


def test_load_keyfile_with_file_obj(keyfile_path, keyfile_json):
    with open(keyfile_path) as keyfile_file:
        loaded_keyfile_json = load_keyfile(keyfile_file)

    assert loaded_keyfile_json == keyfile_json


def test_load_keyfile_with_path(keyfile_path, keyfile_json):
    loaded_keyfile_json = load_keyfile(keyfile_path)

    assert loaded_keyfile_json == keyfile_json


def test_extract_key_from_keyfile_with_file_obj(keyfile_path):
    with open(keyfile_path) as keyfile_file:
        private_key = extract_key_from_keyfile(keyfile_file, PASSWORD)

    assert private_key == PRIVATE_KEY


def test_extract_key_from_keyfile_with_path(keyfile_path):
    private_key = extract_key_from_keyfile(keyfile_path, PASSWORD)

    assert private_key == PRIVATE_KEY
