## ADR 15: Point Encoding

In order to transmit public keys or to store them, a way to encode points is
needed.

Encoding can be defined as:

For sets `S` and `T`, and encoding from `S` to `T` is an efficient
function `enc : S → T` with efficient left-inverse `dec : T → SU{⊥}`, which
fails by returning `⊥` on every element of `T\enc[S]`. We are interested in an
encoding from an elliptic curve `E` over the field `F` to a binary set
`{0, 1}^n` for some fixed `n`. We assume that the implementer has already chosen
an encoding from `F` to binary.

This process translates a point into a format that can be stored (for example,
in a file or memory buffer) or transmitted (for example, across a network
connection link) and reconstructed later (possibly in a different computer
environment).  When the resulting series of bits is reread according to the
encoding format, it can be used to create a semantically identical clone of the
original point.

### Context

### Decision

### Consequences

### References
