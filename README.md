# AES_Cipher
Simple AES Cipher made in python for educational purposes. 

# How To Use 
Import the AES class with: 
```
from AES_cipher import AES
```
Create an instance of the class with 128 bit (16 characters) key: 
```
cipher = AES(key)
```

Encrypt / Decrypt your strings with:
```
cipher_text = cipher.encrypt(plain_text)
plain_text = cipher.decrypt(cipher_text)
```
