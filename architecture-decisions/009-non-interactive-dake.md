## ADR 8: Non-interactive DAKE

### Braindump of questions

- Should OTRv4 provide a non-interactive AKE?
- How should pre-keys be published and retrieved? How many? For how long?
- How to associate pre-keys with instance tags? What about user profiles?
- Should the protocol specify HOW to use interactive and non-intractive in
  a hybrid mode and how to automatically fallback from one to another?

### Context

OTRv3 only provides an interactive AKE and adding support to non-interactive
AKE is an usability feature.

A non-interactive DAKE starts by the receiver (R) requesting a pre-key for the
initiator (I) from a untrusted server.

The receiver then generates their ephemeral keys and derives a shared secret
(and initial root and chain keys) which can be used to send an encrypted data
message together with his final message on the DAKE.

The receiver can continue sending data mesages even without receiving a reply
from the initiator, and forward secrecy is preserved by ratcheting the chain
key.

When the initiator receives the final message in the DAKE, they should verify
if the pre-key

An OTRv4 pre-key may contain:
- one ephemeral ECDH key.
- one ephemeral DH key.
- user profile.
- instance tag.

The initiator generates a set of pre-keys and publishes them to an untrusted
server.

#### Problem 1: Multiple clients

OTR works in protocols that allow an user/account to be concurrently online in
the network using multiple clients (or devices). This means messages addressed
to client A may be received by client B and/or A with no guarantee or order.

OTR makes use of instance tag to avoid problems in such networks, so a message
is addressed to a particular OTR client if it's sent to the account that
controls that device AND it contains the client's instance tag.

Since pre-keys are ephemeral keys stored in a particular OTR client, messages
in a non-interactive conversation have the risk of being completely lost if
they are received by a client with a different instance tag and there's no
guarantee that the underlying network protocol will ever deliver these messages
to the corrrect client.

Should we be specific in saying how this could possibly work in XMPP? Should we
recommend that a client receiving offline messages from XMPP should keep them
there if they are not addressed to this client's instance tags?

#### Problem 2: Multiple OTR wire protocol versions

Should pre-keys also contain information about which OTR wire protocol they
belong to? Otherwise, how would we in the future allow OTRv4 and OTRv5 pre-keys?
Should servers be required to provide an API to allow asking for pre-keys for
specific OTR versions? Is this something possible to implement using only XEPs
for the case of XMMP, for example?

#### Problem 3: Multiple DAKEs for multiple settings

Having different DAKEs for interactive and non-interactive may increase
complexity: should we have 2 DAKEs state machines? What should happen when you
receive a non-interactive DAKE message while waiting for an interactive DAKE
message (and vice-versa)? Should we keep two sets of key materials? Is it worth
the additional ammout of code?

### Decision

We decided to postpone the decision to when we have the interactive.

### Consequences

TODO
