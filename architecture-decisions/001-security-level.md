## ADR 1: Security Level

### Context

The security level of a protocol can be roughly estimated as the smallest
security level amongst all the cryptographic primitives in use in a protocol.
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

Furthermore, the OTRv4 protocol specification should be ready for current
implementations. Therefore, using cryptographic primitives with existing already
implementations in various programming languages should be favored.

These are the considerations to be taken into account while defining a
target overall protocol security level: individual algorithm security level,
speed, license requirements, and availability.

Because of this, two security levels are evaluated: 128-bit and 224-bit.

### Decision

OTRv4 design have a target security level of ~224-bit. This is so as it is
reasonable to choose ~224-bit primitives because the ~128-bit primitives could
not really provide the ~128-bit security.

OTRv4 uses elliptic curve cryptography. In case that elliptic curves can broken,
data message transcripts of OTRv4 will have a classic Diffie-Hellman ~128-bit
security.

To achieve the ~224-bit in regards to the choice of elliptic curve cryptography,
curve Ed448 ("Goldilocks") was chosen, as it has a ~224-bit security level (note
that on RFC 7748, Curve448 is said to have a ~224-bit security level
[\[1\]](#references); on Ed448-Goldilocks library, Ed448 has a ~223-bit security
level [\[2\]](#references)). Although Ed448 does not have as much published
cryptanalysis when compared with Curve25519, it can be safely
used [\[1\]](#references): it hedges against some amount of analytical advance
against elliptic curves.

To achieve classic Diffie-Hellman ~128-bit security, we use a 3072-bit brace
key, as described in
[ADR 5](https://github.com/otrv4/otrv4/blob/master/architecture-decisions/005-brace-keys.md).

We use ChaCha20 as the encryption stream cipher because it is faster than AES
in software-only implementations, it is not sensitive to timing attacks and has
undergone rigorous analysis ([\[3\]](#references), [\[4\]](#references)
and [\[5\]](#references)). We chose this over AES as future advances in
cryptanalysis might uncover security issues with it, its performance on
platforms that lack dedicated hardware is slow, and many AES implementations are
vulnerable to cache-collision timing attacks [\[6]\](#references). This is all
defined in [\[7\]](#references).

We chose to use the modified version of ChaCha20 as defined
in [\[7\]](#references) because it is more widely adopted. In OTRv4, therefore,
we used the following parameters: 20 rounds, a 256-bit key, a 96-bit nonce and
a 32-bit block count, in comparison with the original ChaCha20 that has a 64-bit
nonce and a 64-bit block count. As we are using a unique message key for each
encrypted message, we can use a constant nonce of 96-bit set to 0. With this, it
will remain true that `nonce, key` pairs are never reused for different
messages. The ChaCha20 cipher is designed to provide a 256-bit security level.

The protocol uses SHAKE-256 as the hash function, as it gives a 256-bit security
if the output is 64 bytes, and 128 if the output is 32 bytes. We only use
SHAKE-256 with an output of 32 bytes for generation of the brace key (when it is
not the third ratchet) as it has a security level of 128 bits.

SHAKE-256 is used for the key derivation, hash and MAC function in the protocol.
The functions are:

```
  KDF(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)
  HWC(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)
  HCMAC(usage_ID || values, size) = SHAKE-256("OTRv4" || usage_ID || values, size)
```

The `size` first bytes of the SHAKE-256 output for input
`"OTRv4" || usage_ID || m` are returned in all three functions. Unlike the SHAKE
standard, notice that the output size here is defined in bytes.

The only different KDF function used in this specification is the one used when
referring to RFC 8032. As defined in that document:

```
SHAKE-256(x, y) = The 'y' first bytes of SHAKE-256 output for input 'x'
```

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
3. Aumasson, J., Fischer, S., Khazaei, S., Meier, W., and C. Rechberger. (2007)
   *New Features of Latin Dances: Analysis of Salsa, ChaCha, and Rumba*.
   Available at:
   http://cr.yp.to/rumba20/newfeatures-20071218.pdf.
4. Ishiguro, T., Kiyomoto, S., and Y. Miyake. (2012). *Modified version of
   'Latin Dances Revisited: New Analytic Results of Salsa20 and ChaCha'*.
   KDDI R&D Laboratories Inc. Available at:
   https://eprint.iacr.org/2012/065.pdf.
5. Zhenqing, S., Bin, Z., Dengguo, F., and W. Wenling. (2012). *Improved Key
   Recovery Attacks on Reduced-Round Salsa20 and ChaCha*. Available at:
   https://link.springer.com/chapter/10.1007/978-3-642-37682-5_24
6. Bonneau, J. and I. Mironov. (2006). *Cache-Collision Timing Attacks Against
   AES*, Cryptographic Hardware and Embedded Systems, CHES 2006. Available at:
   http://research.microsoft.com/pubs/64024/aes-timing.pdf.
7. Nir, Y. and Langley, A. (2015). *ChaCha20 and Poly1305 for IETF Protocols*,
   Internet Research Task Force (IRTF), RFC 7539. Available at:
   https://tools.ietf.org/html/rfc7539