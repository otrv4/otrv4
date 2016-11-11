## ADR 3: Version Advertisement - preventing version rollback

**Status**: proposed

### Context
### Decision
### Consequences

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


The problem with query message is that Eve can intercept it and change the
version value without Alice and Bob realizing it. The only way Alice could
control which version is going to be used in this conversation is to have a
restrict policy, disallowing any other previous version.

To prevent version rollback on OTR4, Alice and Bob will create a public,
verified advertisement of the versions they support and publish them on a
publicly available server. This advertisement includes the supported versions
and an expiration date, both of which are signed with the participant's long
term private key.


Alice wants to tell Bob which version she uses but without compromising her
repudiation participation in this conversation. She should have her supported
versions signed and published on a pre-key server, so when she invites Bob
to a conversation, Bob will be able to request Alice's supported version to
the server and to check if this was signed by her long term key or not.


As version advertisement is public information, Alice is not able to delete it
from public servers. To facilitate versions revocation, they should have a
short expiration date. By default, each advertisement will expires in 6 (six)
months but users and clients are able to personalise it, changing OTR policy.


As OTRv4 upgrades the current primitives and provides extra deniability, but as
it not develop to fix security issue on OTRv3, is acceptable for Alice to talk
with Bob on version 3, but is preferable to use 4 if both support it.


High versions have priority, so in the case where Bob receives multiples
supported versions for Alice, OTR will chose the highest version supported by
both.


To request version advertisement is not mandatory for all conversations but is
the only way to have idea about what the other peer support.


As Alice can use OTR4 in more than one device, probably she is going to have
different version advertisement signed by different long term keys.
So, in this case Bob probably is going to receive more than one advertisement,
they can have or not the same version number, they can have or not the same
expiration.

Highest non-expired version supported by Bob will have a priority.

As this version wasn't generated in this device, but its supports exactly this
version, instead of abort this conversation, Alice replies back as normal.

As query message is sent as plaintext and can be changed without peers realise,
this can be changed to any other version.
So, to reduce the possibility to downgrade OTR4 to OTR3, Bob should confirm if
he can find out Alice's version advertisement. If yes, he can keep the
conversation in the version he found.

If for some reason, he didn't find any advertisement for Alice and he allow 3
in his policy, the conversation will be established as OTR3. Otherwise, just
ignore.

