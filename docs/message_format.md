# Encrypted Message Format

The first 4 bytes contain version information

```
[VV][VV][DD][CC]
```

Where:

* `[VV][VV]` is the version of the library
* `[DD]` is specifies the driver and type (symmetric or asymmetric).
  * `{1000 0000}` The first bit determines asymmetric
  * `{0111 1111}` The last 7 bits determine the driver ID
* `[CC]` is a checksum `[VV] ^ [VV] ^ [DD]` (where `^` means XOR)

# Asymmetric-Key Cryptographic Messages

TODO, but generally:

1. Message type (seal, sign, or encrypt)
2. Any public keys involved (if applicable)
3. Ciphertext
4. MAC / other Authentication Tag (if applicable)

# Symmetric-Key Cryptographic Messages

TODO, but generally: 

1. IV / Nonce
2. Ciphertext
3. MAC / other Authentication Tag