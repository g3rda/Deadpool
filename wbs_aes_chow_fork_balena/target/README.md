Compilation
-----------

aes128.c: AES-128 in ECB mode (can encrypt only 16 bytes)

Usage
-----

1. Set your key in the Makefile (`AES128_KEY`).
2. Run `make`.

AES tables will be located in `aes-whitebox/aes_whitebox_tables.cc` file.

Then to encrypt 16 bytes run: 
`./aes128 bytes_to_encrypt_in_hex`

Example
-----

```bash
./aes128 000102030405060708090a0b0c0d0e0f
50fe67cc996d32b6da0937e99bafec60
```

Solution
--------

```bash
echo 50fe67cc996d32b6da0937e99bafec60|xxd -r -p|openssl enc -d -aes-128-ecb -K 2b7e151628aed2a6abf7158809cf4f3c -nopad|xxd -p
000102030405060708090a0b0c0d0e0f
```
