## ADR 3: Version Advertisement - preventing version rollback

**Status**: proposed

### Context

Currently, OTRv3 support its previous versions, user should configure their
policy to tell the protocol if they wanna to support previous versions or not.
When a user wanna to have a conversation with someone, its should send a query
message telling which versions its support. This message is send as plaintext
and can be intercepted and changed without the user been notified.

As we are updating OTR to provide cryptographic primitives with a higher security
level and to provide more deniability, at same time we don't wanna to foce all
users to upgrade now so if two parties are stabilishing a conversation and both
of them support versions 3 and 4, how OTR can ensure that they are going to
talk in the highest version? How to provide cryptographic agility without leave
user in a sensible position?

### Decision

We will keep  the use of query message for OTRv3 compability and also to work as
kind of ping message.

We will use this version advertisement in two ways, one is publishing it in a
public server so when a person wanna to chat with someone using OTR, they can
check peer's compability and version support. Also, we should have this
information public to provide initiator's participation deniability.

We will prioritise high versions, so in the case when user receives 2 different
version advertisement from server, the conversation should initalize in the
higer version supported by both.

As query message does not have any data to validate if the version advertised
is true and belongs to the person that sends it, we are going to have ZKPK
signed version advertisement attached to DAKE messages (field one and field
two), so users can validate if this version was signed by the person
who belongs to.

To provide revogation and to prevent people from using obsolete versions, we will
have a medium (6 months) expiration date attached to each version advertisement.
Clients and user also are able to define the expiration if they wanna.

To request version advertisement is not mandatory for all conversations but is
the only way to have an idea about what the other peer supports.

And alse as the idea is to protect user from version downgrade and not to provide
identification, if a user is going to engage in a conversation and its receive
an advertisemente where does not belong to it but its suuport the same version,
we will not abort the conversation.

To reduce downgrade possibility, if user receives query message requesting
conversation in version 3, we should checks peer compability by requesting
version advertisement to server.

### Consequences

As OTRv4 upgrades is not to fix any security issue on OTRv3, is acceptable for
users to chat using version 3, but is preferable to use 4 if both support it.


If for some reason, he didn't find any advertisement for Alice and he allow 3
in his policy, the conversation will be established as OTR3. Otherwise, just
ignore.

