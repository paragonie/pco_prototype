# Encrypted Message Format

The first 4 bytes contain version information

```
[VV][VV][DD][CC]
```

Where:

* `[VV][VV]` is the version of the library
* `[DD]` is specifies the driver and type (symmetric or asymmetric).
  * `{1000 0000}` The first bit determines asymmetric (seal), which basically means "a public key is attached too"
  * `{0111 1111}` The last 7 bits determine the driver ID
* `[CC]` is a checksum `[VV] ^ [VV] ^ [DD]` (where `^` means XOR)

# Symmetric-Key Cryptographic Messages

## Symmetric::encrypt()

The output format will be:

* The header (with the first bit of `[DD]` not set)
* A random salt for HKDF (size depending on driver, typically 32 bytes)
* A random nonce (for the stream cipher, typically 24 or 32 bytes)
* The ciphertext itself
* A message authentication code (typically 32 bytes)

# Asymmetric-Key Cryptographic Messages

## Asymmetric::encrypt()

The output format is identical to Symmetric::encrypt(), except the key used was a shared secret between a secret key
and your participant's public key.

## Asymmetric::seal()

The output format will be:

* The header (with the first bit of `[DD]` set)
* An ephemeral public key
* A random salt for HKDF (size depending on driver, typically 32 bytes)
* A random nonce (for the stream cipher, typically 24 or 32 bytes)
* The ciphertext itself
* A message authentication code (typically 32 bytes)