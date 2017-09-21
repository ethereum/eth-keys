# Ethereum Keys


A common API for Ethereum key operations with pluggable backends.


## Installation

```sh
pip install ethereum-keys
```

## QuickStart

```python
>>> from eth_keys import KeyAPI
>>> keys = KeyAPI()
>>> pk = keys.PrivateKey(b'\x01' * 32)
>>> signature = pk.sign(b'a message')
>>> pk
'0x0101010101010101010101010101010101010101010101010101010101010101'
>>> pk.public_key
'0x1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1'
>>> signature
'0xccda990dba7864b79dc49158fea269338a1cf5747bc4c4bf1b96823e31a0997e7d1e65c06c5bf128b7109e1b4b9ba8d1305dc33f32f624695b2fa8e02c12c1e000'
>>> pk.public_key.to_address()
'0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1'
>>> signature.verify_msg(b'a message', pk.public_key)
True
>>> signature.recover_msg(b'a message') == pk.public_key
True
```


## Documentation

### `KeyAPI(backend=None)`

The `KeyAPI` object is the primary API for interacting with the `ethereum-keys` libary.  The object takes a single optional argument in it's constructor which designates what backend will be used for eliptical curve cryptography operations.  The built-in backends are:

* `eth_keys.backends.NativeECCBackend` (**default**): A pure python implementation of the ECC operations.
* `eth_keys.backends.CoinCurveECCBackend`: Uses the [`coincurve`](https://github.com/ofek/coincurve) library for ECC operations.

> Note: The `coincurve` library is not automatically installed with `ethereum-keys` and must be installed separately.

The `backend` argument can be given in any of the following forms.

* Instance of the backend class
* The backend class
* String with the dot-separated import path for the backend class.

```python
>>> from eth_keys import KeyAPI
>>> from eth_keys.backends import NativeECCBackend
# These are all the same
>>> keys = KeyAPI(NativeECCBackend)
>>> keys = KeyAPI(NativeECCBackend())
>>> keys = KeyAPI('eth_keys.backends.NativeECCBackend')
# Or for the coincurve base backend
>>> keys = KeyAPI('eth_keys.backends.CoinCurveECCBackend')
```

### `KeyAPI.PublicKey(public_key_bytes)`

The `PublicKey` class takes a single argument which must be a bytes string with length 64.

> Note that some libraries prefix the byte serialized public key with a leading `\x04` byte which must be removed before use with the `PublicKey` object.

The following methods are available:


#### `PublicKey.from_private(private_key) -> PublicKey`

This `classmethod` returns a new `PublicKey` instance computed from the
given `private_key`.  

* `private_key` may either be a byte string of length 32 or an instance of the `KeyAPI.PrivateKey` class.


#### `PublicKey.recover_msg(message, signature) -> PublicKey`

This `classmethod` returns a new `PublicKey` instance computed from the
provided `message` and `signature`.

* `message` **must** be a byte string
* `signature` **must** be an instance of `KeyAPI.Signature`


#### `PublicKey.recover_msg_hash(message_hash, signature) -> PublicKey`

Same as `PublicKey.recover_msg` except that `message_hash` should be the Keccak
hash of the `message`.


#### `PublicKey.verify_msg(message, signature) -> bool`

This method returns `True` or `False` based on whether the signature is a valid
for the given message.


#### `PublicKey.verify_msg_hash(message_hash, signature) -> bool`

Same as `PublicKey.verify_msg` except that `message_hash` should be the Keccak
hash of the `message`.


#### `PublicKey.to_address() -> text`

Returns the ERC55 checksum formatted ethereum address for this public key.
