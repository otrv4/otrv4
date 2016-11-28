## ADR 2: Double Ratchet & revealing MAC key

### Context

In older OTR versions, in data message exchange, the key management is controlled
by a "three step ratchet" which behaves as:
(TODO: the sentence above could be smoother)

1. Alice sends an encrypted message to Bob, and "advertises" her next Diffie-Hellamn
   key pubA.
2. Bob sends an encrypted message to Alice, and "acknowledges" her next Diffie-Hellman
   key, and advertises his next Diffie-Hellman key pubB.
3. Alice sends a message to Bob, using her advertised key privA, and acknowledged
   key pubB.

In [1], the Double Ratchet Algorithm is introduced, which allows for:

1. out-of-order messages
2. per-message forward secrecy.

We consider adding this new algorithm into OTRv4, but we also need to maintain
the same security properties of prior OTR versions, such as message deniability
that is achieved by revealing MAC keys.

In [2], a vulnerability was found in Message Integrity for OTR version 2, where
revealing MAC keys is done immediately by both sides. Two potential solutions are
possible:

1. only the receiver can reveal MAC keys, which still has weaken deniability as it
puts full trust in receiver
2. both sender and receiver can reveal, but the sender must reveal MAC keys only
after two ratchet generations.

OTRv3 made the decision to reveal MAC keys only by the receiver per ratchet.
If we want to use Double Ratcheting, the Revealing MAC Key can be done
this way as well, immediately after receiving each message.

One difference between revealing MAC keys for the three-step ratchet and the
Double Ratchet is that in the three-step ratchet, one MAC key is used for
each ratchet, whereas for the Double Ratchet, one MAC key used for each message.

Therefore, in revealing MAC keys in the Double Ratchet, we have two options:

1. to reveal one MAC key per message
2. to reveal a key that can be used to derive all the MAC keys in that ratchet.

### Decision

For OTRv4, we decided to use the Double Ratchet Algorithm for key management. Even
though our network model is in-order, we can benefit from the per-message forward
secrecy that the Double Ratchet algorithm provides.

We decided that only the receiver will reveal MAC keys per message for simplicity.

### Consequences

This changes the data exchange implementation for OTRv4 from previous versions.

With this change, we achieve improved forward secrecy, as well as move from three
steps to two steps when ratcheting.

However, key management and ratcheting process become more complex because more
types of keys are involved.


[1](https://whispersystems.org/blog/advanced-ratcheting/)
[2](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.165.7945&rep=rep1&type=pdf)
