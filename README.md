# pyserpent

[![PyPI version](https://img.shields.io/pypi/v/pyserpent.svg)](https://pypi.org/project/pyserpent/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/pyserpent?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/pyserpent)

Pure Python implementation of the Serpent block cipher with ECB, CBC mode and PKCS#7 padding.

## Install

```bash
pip install pyserpent
```

## Quick Start - ECB
```python
from pyserpent import Serpent

key = Serpent.generate_key()
serpent = Serpent(key)
plaintext = b"Hello, Serpent!!"

ciphertext = serpent.encrypt(plaintext)
decrypted = serpent.decrypt(ciphertext)

print(decrypted.decode())
```

## Example Serpent CBC Mode

```python
from pyserpent import Serpent, serpent_cbc_encrypt, serpent_cbc_decrypt

key = Serpent.generate_key()
iv = Serpent.generateIV()
plaintext = "Hello, Serpent!!"

ciphertext = serpent_cbc_encrypt(key, plaintext, iv)
decrypted = serpent_cbc_decrypt(key, ciphertext, iv)

print(decrypted.decode())
```
