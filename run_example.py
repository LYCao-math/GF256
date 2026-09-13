from src.aes import AES_encrypt, AES_decrypt, pkcs7_unpad

key = bytes(range(16))
plaintext = b"mathematical science"

cipher = AES_encrypt(plaintext, key)
print("Ciphertext (hex):", cipher.hex())

recovered = AES_decrypt(cipher, key)
print("Recovered plaintext:", bytes(pkcs7_unpad(recovered)))

assert bytes(pkcs7_unpad(recovered)) == plaintext
