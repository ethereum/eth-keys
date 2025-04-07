#!/usr/bin/env python
from setuptools import (
    find_packages,
    setup,
)

extras_require = {
    "coincurve": [
        "coincurve>=17.0.0",
    ],
    "dev": [
        "build>=0.9.0",
        "bump_my_version>=0.19.0",
        "ipython",
        "mypy==1.10.0",
        "pre-commit>=3.4.0",
        "tox>=4.0.0",
        "twine",
        "wheel",
    ],
    "docs": [
        "towncrier>=24,<25",
    ],
    "test": [
        "pytest>=7.0.0",
        "asn1tools>=0.146.2",
        "factory-boy>=3.0.1",
        "pyasn1>=0.4.5",
        "hypothesis>=5.10.3",
        "eth-hash[pysha3]",
    ],
}

extras_require["dev"] = (
    extras_require["coincurve"]
    + extras_require["dev"]
    + extras_require["docs"]
    + extras_require["test"]
)


with open("./README.md") as readme:
    long_description = readme.read()


setup(
    name="eth-keys",
    # *IMPORTANT*: Don't manually change the version here. Use `make bump`, as described in readme
    version="0.7.0",
    description="""eth-keys: Common API for Ethereum key operations""",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="The Ethereum Foundation",
    author_email="snakecharmers@ethereum.org",
    url="https://github.com/ethereum/eth-keys",
    include_package_data=True,
    install_requires=[
        "eth-utils>=2",
        "eth-typing>=3",
    ],
    python_requires=">=3.8, <4",
    extras_require=extras_require,
    py_modules=["eth_keys"],
    license="MIT",
    zip_safe=False,
    keywords="ethereum",
    packages=find_packages(exclude=["scripts", "scripts.*", "tests", "tests.*"]),
    package_data={"eth_keys": ["py.typed"]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
)
