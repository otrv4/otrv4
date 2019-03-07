## ADR 4: OTRv4 SMP

### Context

The Socialist Millionaires Protocol (SMP) in OTRv3 uses Diffie Hellman with a
1536-bit group, which gives an estimated security level of 128 bits. In order to
reach OTRv4's target security level (~224bits), this algorithm needs to be
updated.

SMP Message 1 and SMP Message 1Q are very similar except for the 'Question'
field. In OTRv3, if the user does not define an SMP question, message 1 is
sent; if they do, message 1Q is sent. These two messages can be combined into
one by making the 'Question' field optional.

### Decision

SMP in OTRv4 uses elliptic curves to upgrade its security level to ~224. It uses
the same curve used for the rest of OTRv4: Ed448-Goldilocks.

SMP in OTRv4 combines SMP Message 1 and SMP Message 1Q into one (SMP Message 1),
by making the 'Question' field optional.

### Consequences

The security level of SMP is upgraded in accordance with the whole protocol's
target security level.

Implementers will only need to support one TLV type (SMP Message 1) for SMP
initialization, by making the 'Question' field optional (for when a user
asks for a question and when they do not).

This version of the SMP is, thereby, referred as, SMPv2.
