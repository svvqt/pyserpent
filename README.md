# pyserpent

[![PyPI version](https://img.shields.io/pypi/v/pyserpent.svg)](https://pypi.org/project/pyserpent/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/pyserpent?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/pyserpent)

> [!CAUTION]
> Version 1.2.0 introduces a BREAKING CHANGE in CBC mode.
> The IV is now automatically prepended to the ciphertext.
> Data encrypted with v1.1.0 and earlier will not be compatible
> with the new decrypt function unless migrated. See below.

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
decrypted = serpent_cbc_decrypt(key, ciphertext)

print(decrypted.decode())
```

## Migration from v1.1.0 to v1.2.0
To decrypt data created with version 1.1.0, you need to manually prepend the 16-byte IV to your ciphertext so the new version can recognize it.

If you used the default (zero) IV in v1.1.0:

```python
# v1.1.0 used 16 zero bytes as default IV
old_iv = b'\x00' * 16
# Prepend it to your old ciphertext
prepared_ciphertext = old_iv + old_ciphertext

# Now it's compatible with v1.2.0 decrypt
plaintext = serpent_cbc_decrypt(key, prepared_ciphertext)
```

If you provided a custom IV in v1.1.0:

```python
# Just prepend your IV to the ciphertext
prepared_ciphertext = your_old_iv + old_ciphertext
plaintext = serpent_cbc_decrypt(key, prepared_ciphertext)
```