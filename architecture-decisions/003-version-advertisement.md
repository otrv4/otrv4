## ADR 3: Version Advertisement - preventing version rollback

**Status**: proposed

### Context

Currently, OTRv3 supports its previous versions by allowing the user to configure
their version policy to tell the protocol if they allow previous versions or not.
When a user want to have a conversation with someone, they should send a query
message telling which versions they support. This message is sent as plaintext
at the beginning of the protocol and can be intercepted and changed by a MITM.

With this attack, how can OTR ensure that participants will talk in the highest
version? OTR4 seeks to solve this problem.

Since we are updating OTR to upgrade the cryptographic primitives with higher
security and to provide more deniability, at same time OTRv4 also tries to
address backwards compatibility. So how do we provide cryptographic agility
without to put user in a sensible position?

### Decision

We will keep  the use of query message for OTRv3 compability and also to work as
kind of ping message.

We introduce the concept of a Version Advertisement, which contains the versions
supported by your client, the expiration date of the advertisement, a signature of
the supported versions and the expiration date, and the public keys used to establish
trust with the signature.

We recommend publishing this version advertisement for two reasons, one is so when
a person wants to chat with someone using OTR, they can double check the peer's
compatibility and version support. Two, having this signed information public will
provide participation deniability for both parties despite the usage of signed messages
in the OTR conversation.

We will prioritise high versions, so in the case when user receives 2 different
version advertisement from server, the conversation should initalize in the
higer version supported by both.

Since the query message does not have any data to validate if the version advertised
belongs to the person that sends it, we are going to have a signature of the version
advertisement and expiration attached to DAKE messages (field one and field
two), so users can validate if this version and expiration were signed by a key they trust.

To provide revocation and to prevent people from using obsolete versions, we will
have a minimum (6 months) expiration date attached to each version advertisement.
Clients and user may redefine the version expiration if desired.

Requesting version advertisements from the server is not mandatory for all conversations,
but is the only way to try to verify whether a user only supports version 3 or not.

And also the goal is to protect the user from version downgrade and not to prove
identification, if a user is going to engage in a conversation and they receive
an advertisement that does not belong to a key they trust but its suuport the same
version, we will not abort the conversation.

To reduce downgrade possibility, if the user receives a query message requesting
a conversation in version 3, we should check the peer's version support by requesting
a version advertisement from the server.

### Consequences

As OTRv4 upgrades is not to fix any security issue on OTRv3, is acceptable for
users to chat using version 3, but is preferable to use 4 if both support it.

We will support a conversation on version 3 if we don't find any version
advertisement and user allow it in its policy.

