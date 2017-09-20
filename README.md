# Ethereum Keys


A common API for Ethereum key operations with pluggable backends.


## Installation

```sh
pip install ethereum-keys
```


## Documentation

### Keyfiles

#### `eth_keys.load_keyfile(path_or_file_obj) --> keyfile_json`

Takes either a filesystem path represented as a string or a file object and
returns the parsed keyfile json as a python dictionary.

```python
>>> from eth_keys import load_keyfile
>>> load_keyfile('path/to-my-keystore/keystore.json')
{
    "crypto" : {
        "cipher" : "aes-128-ctr",
        "cipherparams" : {
            "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
        },
        "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
        "kdf" : "pbkdf2",
        "kdfparams" : {
            "c" : 262144,
            "dklen" : 32,
            "prf" : "hmac-sha256",
            "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
        },
        "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
    },
    "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "version" : 3
}
```


#### `eth_keys.create_keyfile_json(private_key, password, kdf="pbkdf2", work_factor=None) --> keyfile_json`

Takes the following parameters:

* `private_key`: A bytestring of length 32
* `password`: A bytestring which will be the password that can be used to decrypt the resulting keyfile.
* `kdf`: The key derivation function.  Allowed values are `pbkdf2` and `scrypt`.  By default, `pbkdf2` will be used.
* `work_factor`: The work factor which will be used for the given key derivation function.  By default `1000000` will be used for `pbkdf2` and `262144` for `scrypt`.

Returns the keyfile json as a python dictionary.

```python
>>> private_key = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
>>> create_keyfile_json(private_key, b'foo')
{
    "crypto" : {
        "cipher" : "aes-128-ctr",
        "cipherparams" : {
            "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
        },
        "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
        "kdf" : "pbkdf2",
        "kdfparams" : {
            "c" : 262144,
            "dklen" : 32,
            "prf" : "hmac-sha256",
            "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
        },
        "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
    },
    "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "version" : 3
}
```

#### `eth_keys.decode_keyfile_json(keyfile_json, password) --> private_key`

Takes the keyfile json as a python dictionary and the password for the keyfile,
returning the decoded private key.

```python
>>> keyfile_json = {
...     "crypto" : {
...         "cipher" : "aes-128-ctr",
...         "cipherparams" : {
...             "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
...         },
...         "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
...         "kdf" : "pbkdf2",
...         "kdfparams" : {
...             "c" : 262144,
...             "dklen" : 32,
...             "prf" : "hmac-sha256",
...             "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
...         },
...         "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
...     },
...     "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
...     "version" : 3
... }
>>> decode_keyfile_json(keyfile_json, b'foo')
b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
```

#### `eth_keys.extract_key_from_keyfile(path_or_file_obj, password) --> private_key`

Takes a filesystem path represented by a string or a file object and the
password for the keyfile.  Returns the private key as a bytestring.

```python
>>> extract_key_from_keyfile('path/to-my-keystore/keyfile.json', b'foo')
b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
```
