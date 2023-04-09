This program is a command-line tool for encrypting and decrypting files
using the AES-256 block cipher in CBC mode with PKCS7 padding. The user is
prompted to provide the file path, a password, and the desired operation
mode (encrypt or decrypt). The password is used to derive a 256-bit key using
the SHA-256 hash function. The tool then reads the file content, performs
the chosen operation, and writes the result to a new file with the original
file name appended with the operation mode (e.g., "file.txt_encrypt" or "file.txt_decrypt")
