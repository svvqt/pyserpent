import pytest
from pyserpent import serpent as srp


@pytest.mark.parametrize("key, plaintext, expectedtext", [
    (b"0000000000000000", "Hello, Serpent!", "5715ca193542a5bb3653d5248748614b"),
    (b'0000000000000000', "1234567890", "7d743e2f665fae91da5827b6fd1ea507"),
    (b"0000000000000000", "00000000000000040", "5d0299a2d7c46e7e79d722d0470a94c5b12bc90db990de2cd1e6f66203aeff8e"),
    (b"0000000000000000", "aaaeerggdddaswr1234", "51461abc1dec583235db9c9e6648fdaa73d993d5595cd72cb7a8d21b41f6eaa0"),
    
])
def test_vectors_KAT(key, plaintext, expectedtext):
    ciphertext = srp.serpent_cbc_encrypt(key, plaintext)
    decryptedtext = srp.serpent_cbc_decrypt(key, ciphertext)
    #ciphertext_bytes = srp.encrypt(key, ciphertext)
    assert ciphertext.hex() == expectedtext
    assert decryptedtext.decode() == plaintext
