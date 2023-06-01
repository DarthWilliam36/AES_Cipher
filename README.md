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

# Introduction
Note: Everything is explained using an AES cipher with a 128 bit key. With larger keys, each step might look a little different but the fundamental concept is the same. 

AES is a “block cipher” meaning that it begins by splitting up the input data into 128 bit blocks. The 128 bits can be displayed as 16 bytes (8 bits each) in a 4x4 matrix.

AES is also a symmetric block cipher. “Symmetric” means that the same key is used to both encrypt and decrypt the data.

The main encryption loop for AES with a 128 bit key iterates over each block (called the state array) 10 times with the same actions performed on that block each iteration with the exception of the last. These iterations consist of the same four functions: ```sub_bytes()```, ```shift_rows()```, ```mix_col()``` and ```add_round_key()```. These are the only functions that actually permutate the state array, we will call them the permutable functions.

# Permutable Functions
## sub_bytes()
This function begins by iterating over each byte in the 4x4 block. The goal of this function is to add non-linearity to the cipher that is also reversible. It achieves this by using a lookup table called the ```s_box``` (substitution box). The creation of this s_box is complicated and involves finding the multiplicative inverse of a number in GF(2^8). This creation process is not necessary to understand. Also note that the s_box is the same for every AES encryption cipher and does not change at all. Just think of the s_box like a mapping of one number to another, the ```inv_s_box``` does the same but with the numbers swapped. This function finds the byte it wants to replace and uses this s_box to find the corresponding byte and replaces it in the given block. After each iteration, the function is finished. 

## shift_rows()
This is easily the simplest function and is also very easy to understand. This transformation consists of not shifting the first row of the input block, circularly rotate the second row of the block by one byte to the left, circularly shift the third row by two bytes to the left, and finally circularly shift the last row three bytes to the left. This transformation is best summed up by this image:

## mix_col()
This function establishes a relationship between the value of one byte and the remaining bytes within the same column. You can think of this like mixing a rubix cube. With a solved cube, you can twist each face on the same axis as many times as you want but the cube will always stay very easy to solve. Once you start twisting the cube on another axis, the cube becomes exponentially harder to solve. You can use the ```shift_rows()``` function as many times as you want and the matrix will never really be mixed. Once you combine the ```mix_col``` and ```shift_rows()``` functions, the matrix becomes very hard to unmix. This function works by multiplying the input block by a special matrix that looks like this: 
```
[2, 3, 1, 1]
[1, 2, 3, 1]
[1, 1, 2, 3]
[3, 1, 1, 2]
```
it multiplies these two matrices in GF(2^8) and instead of adding the numbers, you XOR them. 

## add_round_key()
The AES cipher is completely transparent to the public. If you were to rely solely on the other three permutable operations to encrypt your plaintext, it would be very easy to decipher because these operations are widely understood. This function is very simple but is the most important as it distinguishes your cipher from someone else's. All it does is use a bitwise XOR operation on the input block and the key block. 

These functions are the backbone of any type of AES cipher and are crucial to fully understand how AES functions. To read more about AES, here are some good sources:  
https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf  
https://en.wikipedia.org/wiki/Advanced_Encryption_Standard  
https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf  

# Encryption Algorithm
As seen in the ```encrypt()``` function in the AES class. The algorithm starts by using the ```add_round_key()``` on the state array (block). This is followed by nine rounds of ```sub_bytes(), shift_rows(), mix_col(), add_round_key() ```. The tenth and final round is the exact same but without the ```mix_col()``` step. And boom! You have successfully encrypted your plain text. 

# Decryption Algorithm
The decryption algorithm is the exact opposite of the encryption algorithm. You do the same steps but in reverse with the inverse of each function. It begins with ```add_round_key(), inv_shift_rows() and inv_sub_bytes()```. This is followed by nine rounds of ```add_round_key(), inv_mix_col(), inv_shift_rows(), inv_sub_bytes()```. Finally the last round just uses the ```add_round_key()```. 
