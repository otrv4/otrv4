## ADR 1: Security Level

### Context

Designing a new version of OTR is an opportunity to:

- increase its security by using cryptographic primitives with a higher
security level.
- use elliptic curve cryptography for faster computations with the same
security level.
- replace current cryptographic primitives with modern alternatives.

The security level of the protocol can be roughly estimated as the smallest
security level among all the cryptographic primitives in use, and in general,
there's an inverse relation between security level and speed.

For this reason, the cryptographic primitives should be chosen to have roughly
the same security level close to the target security level.

Because OTRv4 is an open standard, we want to use crypto primitives with no
intellectual-property claims.

Finally, we want to make the protocol easy to implement. Therefore, we favor
the use of cryptographic primitives with implementations in various programming
languages.

In this context, two options were evaluated:

- ~128-bit security
- ~224-bit security

### Decision

We will design OTRv4 with a target security level of ~224-bits.

After evaluating both security levels, the main decision is whether to use curve
25519 or curve 448. Although curve 448 doesn't have as much published
cryptanalysis as curve 25519, it is built using the same methodology as 25519.

We will use ed448 as ECDH group for the extra security it provides.

We will use SHA3-512 as the cryptographic hash function. Since the security
level of a hash is, in general, half the size of the output (because of the
birthday paradox), this gives us an expected level of 256.

We will use XSalsa as the stream cipher because it has a block size of 512 bits
compared to AES' 128 block size. It is also faster than AES, immune to
timing attacks, and its nonce is safely generated at random (since it's
significantly larger). XSalsa will be used with the following parameters: 20
rounds, 192-bits nonces and 256-bit keys.

We will use Poly-1305 for message authentication inside the Dual Receiver
Encryption.

We will use SHA3-512 as a key derivation function. We use the construct
SHA3-512(key || secret) when a keyed cryptographic hash function is expected,
and use the construct SHA3-512(counter || secret) to provide cryptographic
domain separation every time multiple keys need to be derived from the same
secret.

We will use the SHA3-512 hash function for generating fingerprints for
long-lived public keys.

### Consequences

One may see the choice of cryptographic primitives as a consequence of the
decision of targeting ~224-bit security.