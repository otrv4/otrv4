## ADR 1: Security Level

**Status**: proposed

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

For this reason, the cryptographic primitives must be chosen to have roughly
the same security level above the target security level.

Because OTRv4 is an open standard, we want to use crypto primitives with no
intellectual-property claims.

Finally, we want to make the protocol easy to implement and we favor having
a small number of cryptographic primitives with implementations in various
programming languages.

In this context, two options were evaluated:

- ~128-bit security (ed25519)
- ~224-bit security (ed448)

### Decision

We will design OTRv4 with a target security level of ~224-bits.

After evaluating both security levels, the main decision is wheter to use curve
25519 or curve 448. Although curve 448 doesn't have as much published
cryptanalysis as curve 25519, it is built using the same methodology as 25519.

We will use ed448 as DH group for the extra security it provides.

We will use SHA3-512 as cryptographic hash function.

We will use XSalsa as stream cipher because it is faster than AES, is immune to
timing attacks, it's safe to randomly generate its longer nonce. XSalsa will be
used with the following parameters: 20 rounds, 192-bits nonce, and 256-bit key.

We will use Poly-1305 for message authentication.

We will use SHA3-512 as key derivation function, and use the construct
SHA3-512(prefix || secret) every time multiple keys need to be derived from the
same secret.

### Consequences

One may see the choice of cryptographic primitives as a consequence of the
decision of targeting ~224-bit security. In this case, move all the previous
paragraphs about individual crypto primitives to this section.

