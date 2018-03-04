## ADR 15: Point Encoding

// TODO: include clamping and cofactor

### Context

The OTRv4 operations use several different elliptic curve specific data types.
Five data types are employed: three types associated with elliptic curve
arithmetic — integers, field elements, and elliptic curve points — as well as
byte arrays which are used to communicate and store information, and bit
strings which are used by some of the primitives.

Frequently it is necessary to convert one of the data types into another, for
example to represent an elliptic curve point as a byte array.

The encoding of a bit string to byte array can be defined as:

Pad the bit string with 0’s on the left to make its length a multiple of 8, then
chop the result up into bytes.

The encoding of a byte array to a bit string can be defined as:

Simply view the byte array as a bit string instead.

For elliptic curve operations, an encoding of points is needed. This encoding
can be defined as:

For sets `S` and `T`, and encoding from `S` to `T` is an efficient
function `enc : S → T` with efficient left-inverse `dec : T → SU{⊥}`, which
fails by returning `⊥` on every element of `T\enc[S]`. We are interested in an
encoding from an elliptic curve `E` over the field `F` to a binary set
`{0, 1}^n` for some fixed `n`. We assume that the implementer has already chosen
an encoding from `F` to binary.

This process translates a point into a format that can be stored (for example,
in a file or memory buffer) or transmitted (for example, across a network) and
reconstructed later (possibly in a different computer environment).  When the
resulting series of bits is reread according to the encoding format, it can be
used to create a semantically identical clone of the original point.

This is usually done depending of point compression. Informally, if point
compression is being used, the idea is that the compressed y-coordinate is
placed in the leftmost octet of the octet string along with an indication that
point compression is on, and the x-coordinate is placed in the remainder of the
octet string; otherwise if point compression is off, the leftmost octet
indicates that point compression is off, and the remainder of the octet string
contains the x-coordinate followed by the y-coordinate.

Usually, every specification defines a way of doing point encoding. As OTRv4
uses EDDSA for signature generation and verification, as well as for generation
of private and public keys, EDDSA encoding for ed448 is used.

### Decision

OTRv4 uses little and big-endian format. For operations related to elliptic
curve arithmetic, little-endian is used. For everything else, big-endian is
used. This is done because OTRv4 uses EDDSA. As the specification of EDDSA uses
little-endian, OTRv4 keeps that for elliptic curve arithmetic and encoding.

The byte array to bit string and viceversa encoding (with little-endian) is,
therefore, defined as:

Bit strings are converted to byte arrays by taking bits from left to right,
packing those from the least significant bit of each byte to the most
significant bit, and moving to the next byte when each one fills up. The
conversion from byte array to bit string is the reverse of this process; for
example, the 16-bit bit string:

```
    b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15
```

is converted into two bytes `x0` and `x1` (in this order) as:

```
    x0 = b7*128 + b6*64 + b5*32 + b4*16 + b3*8 + b2*4 + b1*2 + b0
    x1 = b15*128 + b14*64 + b13*32 + b12*16 + b11*8 + b10*4 + b9*2 + b8
```

Little-endian encoding into bits places bits from left to right and from least
significant to most significant.  If combined with bit-string-to-byte-array
conversion defined above, this results in little-endian encoding into bytes (if
length is not a multiple of 8, the most significant bits of the last octet
remain unused).

// TODO: add big-endian

ed448-EDDSA encoding for elliptic curve related data types is defined as:

Integers and field elements:

An integer `i` (`0 < i < q - 1`) is encoded in little-endian form as a 455-bit
string.

Points:

The encoding is used to define the "negative" elements: specifically, the `x`
coordinate is negative if the 455-bit encoding of `x` is lexicographically
larger than the 455-bit encoding of `-x`.

It defines the 455-bit encoding of each element `(x, y)` as a 456-bit string,
namely the  455-bit encoding of `y` followed by a sign bit; the sign bit is 1 if
and only if `x` is negative.

A parser recovers `(x, y)` from a 455-bit string, while also verifying the
element `(x, y)`, as follows: parse the first 455 bits as `y`; compute
`xx = (y^2 - 1)/(d(y^2) - a); compute `x = +- sqrt(xx)`, where the `+-` is
chosen so that the sign of `x` matches the 456 bit of the string. If `xx` is not
a square then the parsing fails.

This follows the understanding that valid `y` coordinates must satisfy a
quadratic equation for any given `x` coordinate, such that any `y` data may be
represented by its corresponding `x` coordinate and a single additional byte or
bit.

### Consequences

OTRv4 will use little and big-endian.

// TODO: define why 57/455

### References

https://patents.google.com/patent/US6252960
https://eprint.iacr.org/2015/677.pdf
http://www.secg.org/sec1-v2.pdf
