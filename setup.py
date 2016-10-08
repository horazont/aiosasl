#!/usr/bin/env python3
import os.path

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

import aiosasl

setup(
    name="aiosasl",
    version=aiosasl.__version__,
    description="Pure-python, protocol agnostic SASL library for asyncio",
    long_description=long_description,
    url="https://github.com/horazont/aiosasl",
    author="Jonas Wielicki",
    author_email="jonas@wielicki.name",
    license="GPL",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
    ],
    keywords="asyncio sasl library",
    packages=find_packages(exclude=["tests*"])
)
