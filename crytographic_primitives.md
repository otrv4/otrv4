# Cryptographic primitives

----
### Symmetric Encription: AES-256

AES-256 is a 128-bit block cipher with a key size of 256 bits. This means that this algorithm is capable of using a cryptographic key of 256 bits to encrypt and decrypt data in blocks of 128 bits, as defined [here](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf). Because of the length of the key and the number of hashes (14) of this 'flavor' of AES, it takes a long time to perform an attack.

----
### Hash: SHA256 256 bits:

SHA256 (a member of SHA-2 family of hashes) is a hash function used for comparing the computed "hash" (the output from execution of the function) to a known and expected hash value so a person can determine the data's integrity. It was introduced to provide security level against collision search attack, as defined [here] (http://link.springer.com/chapter/10.1007/978-3-540-24654-1_13).
SHA-256 algorithm generates an almost-unique, fixed size 256-bit (32-byte) hash. 

----
### Group: ed25519 128-bit:

ED25519 is a curve part of the family of Edwards-curve Digital Signature Algorithms (EdDSA), which is a digital signature scheme that uses a variant of Schnorr signature based on Twisted Edwards curves. Ed25519 is a *2^55 -19* field twisted edwards curve with a 128-bit security level. It was designed to attain several 'attractive' features, as defined [here] (http://ed25519.cr.yp.to/ed25519-20110926.pdf): 

* fast single-signature verification 
* even faster batch verification
* very fast signing
* fast key generation
* high security level
* foolproof session keys
* collision resilience
* no secret array indices
* no secret branch conditions
* small signatures and small keys

----
### Group: ed448 223-bit:

A 448-bit field edwards curve with a 223-bit conjectured security level, as defined [here] (https://eprint.iacr.org/2015/625.pdf). It was designed for [spinal tap grade security] (https://silentcircle.wordpress.com/tag/spinal-tap/). 
