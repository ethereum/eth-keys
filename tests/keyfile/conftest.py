import json
import os

import pytest

import eth_keys


FIXTURES_FILE_PATH = os.path.join(
    os.path.dirname(os.path.dirname((eth_keys.__file__))),
    'fixtures',
    'KeyStoreTests',
    'basic_tests.json',
)



with open(FIXTURES_FILE_PATH) as fixtures_file:
    KEYFILE_FIXTURES = json.load(fixtures_file)


@pytest.fixture(params=KEYFILE_FIXTURES.keys())
def keyfile_data(request):
    return KEYFILE_FIXTURES[request.param]
