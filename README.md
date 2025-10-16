# Password Toolkit

A command line utility for various password related security tasks, including strength checking, secure storage, file encryption, and password cracking.

## Features

*   **Password Meter**: Evaluates the strength of a password based on its entropy and checks for common weaknesses like repeated characters, sequences, and common substrings.
*   **Secure Password Storage**: Creates new user credentials by hashing passwords with a unique salt using the **PBKDF2-HMAC-SHA256** algorithm.
*   **Bloom Filter Blacklist Check**: Builds and uses a Bloom filter to efficiently check if a password exists in a large blacklist of known compromised passwords.
*   **Simple Cracker Simulator**: Demonstrates the vulnerability of weak passwords by attempting to crack stored user credentials using a dictionary attack.
*   **Authenticated File Encryption**: Encrypts and decrypts files using **AES-GCM**. It uses the username as **Associated Authenticated Data (AAD)** to ensure that the file can only be decrypted by the intended user.

## Requirements

*   Python 3.x
*   `pycryptodome`
*   `rbloom`

You can install the required libraries using pip:
```bash
pip install -r requirements.txt
```
## Password Lists used


National Cyber Security Centre UK 100k most used passwords: https://gitlab.com/kalilinux/packages/seclists/-/blob/c762d09c287bfde4ba326d450b21796980e95781/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt

Weakpass 4 from weakpass.com: https://weakpass.com/download/2012/weakpass_4.txt.7z