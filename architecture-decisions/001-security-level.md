## ADR 1: Security Level

### Context

The security level of the protocol can be roughly estimated as the smallest
security level amongst all the cryptographic primitives in use. In general,
there is an inverse relation between security level and speed. For this reason,
the cryptographic primitives should be chosen to have roughly the same security
level as the target security level.

Designing a new version of OTR is an opportunity to improve its security by
using cryptographic primitives with a higher security level. Also, it is an
opportunity to use elliptic curve cryptography for faster computations with
the same security level.

OTRv4 is an open standard, so we want to use crypto primitives with no
intellectual-property claims.

We want the protocol specification to be ready for implementation now.
Therefore, we favor using cryptographic primitives with existing
implementations in various programming languages.

We evaluated two security levels in this context: 128-bit and 224-bit.

### Decision

We will design OTRv4 with a target security level of ~224 bits using elliptic
curve cryptography. In the case that elliptic curves are broken, data message
transcripts of OTRv4 will have classic Diffie-Hellman ~128-bit security.

To achieve ~224-bit elliptic curve security, we chose curve Ed448
("Goldilocks") for ECDH. We use SHAKE-256 as the hash function during the
generation of secret keys, since it gives give 256-bit security if the
output is 64 bytes and 128 if the output is 32 bytes. Although
Ed448 does not have as much published cryptanalysis as Curve25519, it can be
safely used as Curve25519 [\[1\]](#references).

To achieve classic Diffie-Hellman ~128-bit security, we use a brace key, which
is described in
[ADR 5](https://github.com/otrv4/otrv4/blob/master/architecture-decisions/005-brace-key.md).
We only use SHAKE-256 with an output of 32 bytes when we use the brace key
because it has a security level of 128 bits.

We will use XSalsa20 as our stream cipher because it has a block size of 512
bits compared to AES' block size of 128 bits. XSalsa20 is faster than AES and
immune to timing attacks. Since its nonce is significantly larger, it is safe
randomly generate it. It takes 2<sup>249</sup> simple operations against
XSalsa20 reduced to 8 rounds to break the cipher.

XSalsa20 will be used with the following parameters: 20 rounds, 192-bits
nonces, and 256-bit keys.

The following key derivation functions are used:

```
KDF_1(usageID || m, output_size) = SHAKE-256("OTRv4" || usageID || m, size)
```

The `size` first bytes of the SHAKE-256 output for input
`"OTRv4" || usageID || m`

```
KDF_2(values, size) = SHAKE-256(values, size)
```

The `size` first bytes of the SHAKE-256 output for input `values`. This KDF is
used when referred to RFC 8032.

To provide cryptographic domain separation, we set
`x = OTRv4_domain || usageID || secret`, where the usageID changes for each
situation.

In OTRv4, long-lived key authentication can happen by using SMP or comparing
fingerprints. We take the first 56 bytes of the SHAKE-256 hash function for
generating fingerprints from the long-lived public keys. This results in a long
448-bit (56 byte) fingerprint. The full length fingerprint will be used for SMP
authentication.

### Consequences

Choosing Ed448 requires implementations of it, and chaging SMP cryptographic
primitives.

The size of fingerprints is increased to 56 bytes.

### References

1. https://tools.ietf.org/html/rfc7748 "A. Langley, M. Hamburg,
and S. Turner: Elliptic Curves for Security.” Internet Engineering Task Force; RFC 7748 (Informational); IETF, Jan-2016"