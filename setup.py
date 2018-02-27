#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import (
    setup,
    find_packages,
)


setup(
    name='eth-keys',
    # *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
    version='0.2.0-beta.3',
    description="""Common API for Ethereum key operations.""",
    long_description_markdown_filename='README.md',
    author='Piper Merriam',
    author_email='pipermerriam@gmail.com',
    url='https://github.com/ethereum/eth-keys',
    include_package_data=True,
    setup_requires=['setuptools-markdown'],
    install_requires=[
        "eth-utils>=1.0.0-beta.2,<2.0.0",
        "cytoolz>=0.9.0,<1.0.0",
    ],
    py_modules=['eth_keys'],
    license="MIT",
    zip_safe=False,
    keywords='ethereum',
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)
