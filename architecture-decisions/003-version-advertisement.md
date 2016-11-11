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

Since we are updating OTR to upgrade the cryptographic primitives with higher security
and to provide more deniability, at same time we want version 4 to be compatible with
version 3. So how do we provide cryptographic agility and leave user in a sensible
position? OTR4 also tries to address backwards compatibility.

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

We will support a conversation on version 3 if we don't find any version
advertisement and user allow it in its policy.

