## ADR 1: Security Level

### Context

Designing a new version of OTR is an opportunity to:

- increase its security level by using cryptographic primitives with a higher
security.
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

In this context, two security levels were evaluated:

- ~128-bit security
- ~224-bit security

### Decision

We will design OTRv4 with a target security level of ~224-bits using elliptic
curve cryptography. In the case that elliptic curves are broken, data message
transcripts of OTRv4 will have classic Diffie Hellman ~128-bit security.

To achieve ~224-bit elliptic curve security, we chose the curve Ed448 for the
generation of ECDH. In addition, in relation to secrets generated with ECDH, we
use SHA3-512 and SHAKE256 as hash functions since both give individually 256
bit security. Although Ed448 does not have as much published cryptanalysis as
Curve25519, it is built using the same methodology as 25519.

To achieve classic Diffie Hellman ~128-bt security we use a mix key, which is
described in the ADR file
[005-mix-key.md](https://github.com/twstrike/otrv4/blob/master/architecture-decisions/005-mix-key.md).
We also use SHA3-256 in relation to mix key situations because it has an
expected security of 128.

We will use XSalsa as our stream cipher because it has a block size of 512 bits
compared to AES' 128 block size. It is also faster than AES, immune to
timing attacks, and its nonce is safely generated at random (since it is
significantly larger). XSalsa will be used with the following parameters: 20
rounds, 192-bits nonces and 256-bit keys.

To save space in the creation of the last message in the non-interactive DAKE,
the nonce will be the first 192 bits of the value `c` that is generated in the
Auth function. In all other data message circumstances, the nonce is generated
from randomness.

The following KDFs are defined:
```
KDF_1(x) = SHA3-256("OTR4" || x)
KDF_2(x) = SHA3-512("OTR4" || x)
```

When a keyed cryptographic hash function is expected `x = key || secret`. To
provide cryptographic domain separation when multiple values need to be derived
the same secret, we set `x = counter || secret`, where the counter changes for
each situation.

We also use the SHA3-512 hash function for generating fingerprints for
long-lived public keys because we wish to keep the security level at ~228-bits.

### Consequences

These decisions have made a big impact on the spec. Choosing Ed448 requires
implementations of Ed448 curve equations, and SMP primitives have changed to Ed448.
