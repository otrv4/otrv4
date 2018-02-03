## ADR 2: Key Management and Revealing MAC Keys

### Context

Previous versions of the OTR protocol use a mechanism called the Diffie-Hellman
ratchet (DH Ratchet) to ratchet key material when messages are exchanged. This
ratcheting approach consists of attaching new DH contributions to messages.
With each sent message, the sender advertises a new DH value. Message keys are
then computed from the latest acknowledged DH values.

// TODO: clarify this

This three step DH Ratchet works as follows:

1. Alice sends an encrypted message to Bob, and "advertises" her next Diffie-
   Hellman key `pubA`.
2. Bob sends an encrypted message to Alice, "acknowledges" her next
   Diffie-Hellman key and advertises his next Diffie-Hellman key `pubB`.
3. Alice sends a message to Bob using the private part of her advertised key
   `privA` and the acknowledged key from Bob `pubB`.

This design introduces backward secrecy within conversations since a
compromised key will regularly be replaced with new key material. A
disadvantage of this DH Ratchet is that session keys might not be renewed for
every message (forward secrecy is, therefore, only partially provided). It also
lacks out-of-order resilience: if a message arrives after a newly advertised
key is accepted, then the necessary decryption key will be already deleted.

In order to improve the forward secrecy of the DH Ratchet, both ratchet
approaches can be combined: session keys produced by DH ratchets are used to
seed per-participant KDF ratchets. Messages are then encrypted using
keys produced by the KDF ratchets, frequently refreshed by the DH Ratchet on
message responses. This resulting double ratchet (called the "Double Ratchet
Algorithm" [\[1\]](#references)) provides forward secrecy across messages due
to the KDF ratchets, but also backward secrecy since compromised KDF keys will
eventually be replaced by new seeds. To achieve out-of-order resilience, the
double ratchet makes use of a second derivation function within its KDF
ratchets. While the KDF ratchets are advanced normally, the KDF keys are passed
through a second distinct derivation function before being used for encryption.

We consider using the Double Ratchet Algorithm to improve forward secrecy,
while maintaining the same security properties of prior OTR versions, such as
message deniability. This is achieved since messages are authenticated with
shared MAC keys rather than being signed with long-term keys. OTR, also,
publishes MAC and uses malleable encryption, to expand the set of possible
message forgers.

// TODO: this might change

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
versions. We achieve improved forward secrecy, but key management and
ratcheting processes become more complex because of the many types of keys
involved.

### References

1. https://whispersystems.org/blog/advanced-ratcheting/ "Advanced cryptographic ratcheting"
2. http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.165.7945&rep=rep1&type=pdf "Finite-State Security Analysis of OTR Version 2"
3. http://cacr.uwaterloo.ca/techreports/2015/cacr2015-02.pdf "SoK: Secure Messaging"