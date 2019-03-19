## ADR 1: Security Level

### Context

The security level of a protocol can be roughly estimated as the smallest
security level amongst all the cryptographic primitives in use in that protocol.
In general, there is an inverse relation between security level and speed of
execution. For this reason, the cryptographic primitives should be chosen to
have roughly the same security level as the target security level, while taking
into account their speed.

Designing a new version of OTR is an opportunity to improve its overall security
level by using cryptographic primitives with a higher security level. It is also
an opportunity to start using elliptic curve cryptography, which gives faster
computations for the same security level as using an equivalent Diffie-Hellman
group.

As OTRv4 is an open standard, the protocol should only use cryptographic
primitives that have no intellectual-property claims.

Furthermore, the OTRv4 protocol specification should be ready for implementation
now. Therefore, using cryptographic primitives with existing implementations in
various programming languages should be favored.

These are the considerations to be taken into account while defining a
target overall protocol security level: individual algorithm security level,
speed, license requirements, and availability.

Because of this, two security levels were evaluated: 128-bit and 224-bit.

### Decision

OTRv4 design have a target security level of ~224-bit. It uses elliptic curve
cryptography. In case that elliptic curves can broken, data message
transcripts of OTRv4 will have classic Diffie-Hellman ~128-bit security.

To achieve the ~224-bit in regards to the choice of elliptic curve cryptography,
curve Ed448 ("Goldilocks") was chosen, as it has a ~224-bit security level (note
that on RFC 7748, Curve448 is said to have a ~224-bit security level
[\[1\]](#references); on Ed448-Goldilocks library, Ed448 has a ~223-bit security
level [\[2\]](#references)). Although Ed448 does not have as much published
cryptanalysis when compared with Curve25519, it can be safely
used [\[1\]](#references): it hedges against some amount of analytical advance
against elliptic curves.

To achieve classic Diffie-Hellman ~128-bit security, we use a brace key of
3072-bit, which is described in
[ADR 5](https://github.com/otrv4/otrv4/blob/master/architecture-decisions/005-brace-keys.md).

We use XSalsa20 as the encryption stream cipher because it has a block size of
512 bits compared to AES' block size of 128 bits. XSalsa20 is faster than AES
and immune to timing attacks. Since its nonce is significantly larger, it is
safe randomly generate it. It takes 2<sup>249</sup> simple operations against
XSalsa20 reduced to 8 rounds to break it. In OTRv4, XSalsa20 is used with the
following parameters: 20 rounds, 192-bits nonce, and 256-bit key.

The protocol uses SHAKE-256 as the hash function, as it gives a 256-bit security
if the output is 64 bytes, and 128 if the output is 32 bytes. We only use
SHAKE-256 with an output of 32 bytes for generation of the brace key (when it is
not the *n* ratchet) as it has a security level of 128 bits. It is also use for
generation of Message Authentication Codes (MAC).

SHAKE-256 is defined as a key derivation function in the protocol. Two functions
are used:

```
KDF_1(usageID || m, output_size) = SHAKE-256("OTRv4" || usageID || m, size)
```

In `KDF_1`, the `size` first bytes of the SHAKE-256 output for input
`"OTRv4" || usageID || m` are returned.

The only different KDF function used in this specification is the one used when
referring to RFC 8032. As defined in that document:

```
SHAKE-256(x, y) = The 'y' first bytes of SHAKE-256 output for input 'x'
```

Unlike the SHAKE standard, notice that the output size here is defined in bytes.

In OTRv4, long-term key verification can be done by using the Socialist
Millionaires Protocol (SMP) or by doing a manual fingerprint comparison. The
public key fingerprint is calculated by taking the SHAKE-256 hash of the
byte-level representation of the public key and the byte-level representation of
the forging public key. The result is a long 448-bit (56 byte) array.

### Consequences

The choice of Ed448 as the elliptic curve requires the development of
implementations of it.

In OTRv4, the size of fingerprint is increased to 56 bytes, compared with 20
bytes in OTRv3.

### References

1. Hamburg, M., Langley, A. and Turner, S. (2016). *Elliptic Curves for
   Security*, Internet Engineering Task Force, RFC 7748. Available at:
   http://www.ietf.org/rfc/rfc7748.txt
2. Hamburg, M. *Ed448-Goldilocks*. Available at:
   https://sourceforge.net/p/ed448goldilocks/wiki/Home/