## ADR 2: Key Management and Revealing MAC Keys

### Context

Previous versions of the OTR protocol use a mechanism called the DH ratchet to
ratchet key material when messages are exchanged. This three step, DH ratchet
works as follows:

1. Alice sends an encrypted message to Bob, and "advertises" her next Diffie-
   Hellman key `pubA`.
2. Bob sends an encrypted message to Alice, and "acknowledges" her next Diffie-
   Hellman key and advertises his next Diffie-Hellman key `pubB`.
3. Alice sends a message to Bob using her advertised key `privA` and
   acknowledged key `pubB`.

There are other key exchange algorithms to consider, like The Double Ratchet
Algorithm, which is designed to give us per-message forward secrecy and work
with out-of-order messages [\[1\]](#references).

We consider using the Double Ratchet Algorithm while maintaining the same
security properties of prior OTR versions, such as message deniability.
Message deniability is achieved through revealing MAC keys.

OTR version 2 contains a vulnerability related to message integrity when
revealing MAC keys is done immediately by both participants in a conversation
[\[2\]](#references). Two potential solutions are possible:

1. Only the receiver can reveal MAC keys, which gives weaker deniability as
   it puts full trust in receiver
2. Both the sender and receiver can reveal MAC keys, but the sender must reveal
   only after two ratchet generations

OTRv3 made the decision to only allow the receiver to reveal MAC keys.

Therefore, to reveal MAC keys in the Double Ratchet, we have two options:

1. Reveal one MAC key per message
2. Reveal MAC keys per ratchet

### Decision

For OTRv4, we decided to use the Double Ratchet Algorithm for key management.
Even though our network model assumes in-order message delivery, we can
benefit from the per-message forward secrecy that the Double Ratchet
algorithm provides.

Although the Double Ratchet allows us to receive out-of-order messages, we do
not support this: messages that are received later than expected will be
ignored. Other reasons for this decision are described in
[the ADR for the Non-Interactive DAKE](https://github.com/otrv4/otrv4/blob/master/architecture-decisions/009-non-interactive-dake.md).

We decided that only the receiver will reveal MAC keys on the first message
sent of every ratchet.

### Consequences

This heavily changes the data exchange implementation from previous
versions. We achieve improved forward secrecy, but key management and ratcheting
processes become more complex because of the many types of keys involved.

### References

1. https://whispersystems.org/blog/advanced-ratcheting/ "Advanced cryptographic ratcheting"
2. http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.165.7945&rep=rep1&type=pdf "Finite-State Security Analysis of OTR Version 2"