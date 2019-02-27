## ADR 6: No Postquantum Primitives

### Context

With the coming of quantum computers (QC), the community have started discussing
around the use of quantum resistant algorithms in privacy enhancing
technologies.

### Decision

OTRv4 does not take advantage of quantum resistant algorithms for the following
reasons:

Firstly, OTRv4 aims to be possible and easy to implement in today's environments
in a reasonable time frame. OTRv4 only aims to lay the foundation for future
changes by adding version rollback protection, DAKEs, upgrade of primitives, and
non-interactive conversations.

Secondly, current quantum resistant algorithms and their respective libraries
are not ready for incorporation. Production level libraries may take up to 6-18
months to be ready. Future versions of the protocol may incorporate these
libraries and algorithms when they come into place.

### Consequences

OTRv4 does not use any algorithms which aim to provide effective resistance to
attacks done in quantum computers. If elliptic curve cryptography and 3072-bit
Diffie-Hellman can be attacked by quantum computers in the next upcoming years,
OTRv4's primitives will become unsafe and unusable. However, the use of a
3072-bit Diffie-Hellman "brace key" is used partly due to the potential of
quantum computers arriving earlier than predicted. When fault-tolerant quantum
computers break Ed448-Goldilocks keys, it will take some years beyond that point
to break 3072-bit Diffie-Hellman keys. Notice, though, that the 3072-bit Diffie
Hellman keys does not provide any kind of post-quantum confidentiality. We use
them because, in theory, the Elliptic Curve Discrete Logarithm Problem (ECDLP)
will be broken faster than the Discrete Logarithm Problem (DLP). According to
[\[1\]](#references)), it will be needed 4060 qubits for breaking Ed448 and 6146
for breaking 3072-bit Diffie Hellman.

### References

1. Roetteler, M., Naehri, M., Krysta M., and Lauter K. (2017).
   *Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms*.
   Available at: https://eprint.iacr.org/2017/598.pdf