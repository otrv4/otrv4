## ADR 2: Double Ratchet & revealing MAC key

### Context

In previous versions of the protocol, the rotation of the keys used to encrypt
messages exchanged was done through the following three steps mechanism:

1. Alice sends an encrypted message to Bob, and "advertises" her next Diffie-
   Hellamn key `pubA`.
2. Bob sends an encrypted message to Alice, and "acknowledges" her next Diffie-
   Hellman key and advertises his next Diffie-Hellman key `pubB`.
3. Alice sends a message to Bob using her advertised key `privA` and
   acknowledged key `pubB`.

Double Ratchet Algorithm [\[1\]](#references) is introduced, which allows:

1. out-of-order messages
2. per-message forward secrecy

We consider adding this new algorithm into OTRv4 while maintaining the same
security properties of prior OTR versions, such as message deniability
(achieved by revealing MAC keys).

A vulnerability was found in message integrity of OTR version 2 [\[2\]](#references), where
revealing MAC keys is done immediately by both sides. Two potential solutions
are possible:

1. only the receiver can reveal MAC keys, which gives weaker deniability as
   it puts full trust in receiver
2. both sender and receiver can reveal, but the sender must reveal MAC keys only
   after two ratchet generations.

OTRv3 made the decision to reveal MAC keys only by the receiver per ratchet.
If we want to use Double Ratcheting, the revealing MAC key can be done in
this way immediately after receiving each message.

One difference between revealing MAC keys in the three-step ratchet and in the
Double Ratchet is that in the first one MAC key is used for each ratchet,
whereas in the second one MAC key is used for each message.

Therefore, to reveal MAC keys in the Double Ratchet, we have two options:

1. reveal one MAC key per message
2. reveal a MAC keys per ratchet.

### Decision

For OTRv4, we decided to use the Double Ratchet algorithm for key management.
Even though our network model is in-order, we can benefit from the per-message
forward secrecy that the Double Ratchet algorithm provides.

We decided that only the receiver will reveal MAC keys every ratchet.

### Consequences

This changes the data exchange implementation for OTRv4 from previous versions.

We achieve improved forward secrecy, as well as move from three steps to two
steps when ratcheting.

However, key management and ratcheting process become more complex because of
the different types of keys involved.

### References

1. https://whispersystems.org/blog/advanced-ratcheting/ "Advanced cryptographic ratcheting"
2. http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.165.7945&rep=rep1&type=pdf "Finite-State Security Analysis of OTR Version 2"