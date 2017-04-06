## ADR 8: Non-interactive DAKE

### Braindump of questions

- Should OTRv4 provide a non-interactive AKE?
- How should pre-keys be published and retrieved? How many? For how long?
- How to associate pre-keys with instance tags? What about user profiles?
- Should the protocol specify HOW to use interactive and non-interactive in
  a hybrid mode and how to automatically fallback from one to another?

### Context

OTRv3 only provides an interactive AKE and adding support to non-interactive
AKE is an usability feature.

A non-interactive DAKE starts by the receiver (R) requesting a pre-key for the
initiator (I) from a untrusted server. I's long-term public key must be known by R.

The receiver then generates their ephemeral keys and derives a shared secret
(and initial root and chain keys) which can be used to send an encrypted data
message together with his final message on the non-interactive DAKE.

The receiver can continue sending data messages even without receiving a reply
from the initiator, and forward secrecy is preserved by ratcheting the chain
key.

An OTRv4 pre-key may contain:
- one ephemeral ECDH key.
- one ephemeral DH key.
- user profile.
- instance tag.

#### Publishing pre-keys

The initiator (I) should:

1. Authenticate itself with the server by running an interactive DAKE.
2. Include a ZKPK to prove they control the ephemeral secret key in the pre-key.
3. Send the pre-key.
4. Store the pre-key for future use.

The server should:

1. Verify the ZKPK.
2. Associate the received pre-key with the long-term public key used in the DAKE.

#### Retrieving pre-keys

The receiver (R) should:

1. Request from the server a pre-key for I's long-term public key.

The server should:

1. Reply with the pre-key if there's any, and remove from its storage.
2. Reply with a special message if it could not find.

#### Problem 1: Multiple clients

OTR uses instance tags to distinguish between different clients. This can be
solved by associating recipient long-term public keys with instance tags and
preventing multiple client to share the same long-term public key. A client
must distinguish between when a new long-term public key represents
a new device or the retirement of the previous key.

#### Problem 2: Multiple OTR wire protocol versions

Should pre-keys also contain information about which OTR wire protocol they
belong to? Otherwise, how would we in the future allow OTRv4 and OTRv5 pre-keys?
Should servers be required to provide an API to allow asking for pre-keys for
specific OTR versions? Is this something possible to implement using only XEPs
for the case of XMMP, for example?

#### Problem 3: Multiple DAKEs for multiple settings

Having different DAKEs for interactive and non-interactive increases complexity:
should we have 2 DAKEs state machines? What should happen when you
receive a non-interactive DAKE message while waiting for an interactive DAKE
message (and vice-versa)? Should we keep two sets of key materials? Is it worth
the additional amount of code?

#### Problem 4: What to do when the server runs out of pre-keys?

How other protocols solve this? Does it preserve partial participation
deniability?

### Decision

We decided to postpone the decision to when we have the interactive.

### Consequences

TODO
