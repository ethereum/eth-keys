eth-keys v0.7.0 (2025-04-07)
----------------------------

Breaking Changes
~~~~~~~~~~~~~~~~

- Move ``tools`` folder into ``tests`` as that's the only place it's used. (`#105 <https://github.com/ethereum/eth-keys/issues/105>`__)
- Drops support for ``coincurve<=16``, adds support for ``coincurve==21``. (`#108 <https://github.com/ethereum/eth-keys/issues/108>`__)


Bugfixes
~~~~~~~~

- Modulo reduce the message digest before passing it to the HMAC function (`#101 <https://github.com/ethereum/eth-keys/issues/101>`__)
- Makes ``PrivateKey.public_key`` explicitly an instance member instead of looking like it's a class member. (`#106 <https://github.com/ethereum/eth-keys/issues/106>`__)


eth-keys v0.6.1 (2025-01-14)
----------------------------

Features
~~~~~~~~

- Merge template, adding ``py313`` and ``coincurve v20`` support, replace ``bumpversion`` with ``bump-my-version``. (`#103 <https://github.com/ethereum/eth-keys/issues/103>`__)


eth-keys v0.6.0 (2024-10-21)
----------------------------

Breaking Changes
~~~~~~~~~~~~~~~~

- Set ``ecdsa_raw_recover`` to accept ``v`` values of 0 or 1 (`#100 <https://github.com/ethereum/eth-keys/issues/100>`__)


eth-keys v0.5.1 (2024-04-23)
----------------------------

Internal Changes - for eth-keys Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Merge template updates, notably adding python 3.12 support. Fix docs CI build. (`#99 <https://github.com/ethereum/eth-keys/issues/99>`__)


eth-keys v0.5.0 (2024-01-10)
----------------------------

Breaking Changes
~~~~~~~~~~~~~~~~

- Drop python 3.6 and 3.7 support (`#96 <https://github.com/ethereum/eth-keys/issues/96>`__)


Features
~~~~~~~~

- Add python 3.11 support (`#96 <https://github.com/ethereum/eth-keys/issues/96>`__)


Internal Changes - for eth-keys Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Merge template updates, notably using ``pre-commit`` for linting and change the name of the ``master`` branch to ``main`` (`#96 <https://github.com/ethereum/eth-keys/issues/96>`__)


v0.4.0
------

Released Dec 9, 2021

- Remove support for python 3.5
  https://github.com/ethereum/eth-keys/pull/82
- Add support for python 3.9 and 3.10
  https://github.com/ethereum/eth-keys/pull/82
- Updated eth-utils and eth-typing version requirements
  https://github.com/ethereum/eth-keys/pull/81
- Raise BadSignature error if ecrecover returns a point at infinity
  https://github.com/ethereum/eth-keys/pull/76

v0.3.3
------

Released Apr 22, 2020

- Bugfix for backwards-incompatible ValidationError disappearance
  https://github.com/ethereum/eth-keys/pull/70

v0.3.2
------

Released Apr 22, 2020

- Remove deprecated eth_utils typing
  https://github.com/ethereum/eth-keys/pull/65

- Remove duplicate ValidationError
  https://github.com/ethereum/eth-keys/pull/68

0.1.0
-----

Initial release
