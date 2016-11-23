## ADR 3: User Profile

**Status**: proposed

### Context

Currently, OTRv3 supports its previous versions by allowing the user to configure
their version policy to tell the protocol if they allow previous versions or not.
When a user wants to have a conversation with someone, they should send a query
message telling which versions they support. This message is sent as plaintext
at the beginning of the protocol and can be intercepted and changed by a MITM in
a rollback attack.

With this attack, how can OTR ensure that participants will talk in the highest
version? OTR4 seeks to solve this problem.

To address version rollback attacks on OTR, it was important for both parties to
exchange verified version information without compromising their participation
deniability and while keeping backwards compatibility with OTR3.

### Decision

We will keep  the use of query message for OTRv3 compatibility and also to work
as a kind of ping message.

We will also introduce a user profile to OTR4 that includes:

1. Versions supported in the form of a Query Message string
2. Expiration date of the User Profile
3. Public key used for verifying a profile signature. Users must check whether
   they trust this key.
4. Profile signature of the above 3 parts

The user profile must be published publicly and updated before it expires. The main
reason to do this is that the publication allows two parties to send the signed User
Profile during the DAKE. Since this signed profile is public information, it does not
damage the participation deniability in the conversation. As a side affect, it is possible
for the receiver of a Query Message that contains versions lower than four to check
for a User Profile and thus detect a downgrade attack for older versions.
Requesting user profile from the server is not mandatory for all conversations,
but is the only way to try to verify whether a user only supports version 3 or not.

Although it is possible to check for a version publication, this does not stop an
attacker from spoofing responses about whether the profile exists. So in the case
where an attacker spoofs the Query Message to contain versions lower than four and
the response to a request for a User Profile, a version downgrade attack is possible.
On the other hand, the user profile will protect against version rollback attacks in
OTR versions four and up.

We will prioritise high versions, so in the case when user receives 2 different
user profile from server, the conversation should initialize in the
higher version supported by both.

To provide revocation and to prevent people from using obsolete versions, we will
have a minimum (6 months) expiration date attached to each user profile.
Clients and user may redefine the version expiration if desired.

And also the goal is to protect the user from version downgrade and not to prove
identification, if a user is going to engage in a conversation and they receive
an user profile that does not belong to a key they trust but its support the same
version, aborting the conversation is not necessary.

To reduce downgrade possibility, if the user receives a query message requesting
a conversation in version 3, we should check the peer's version support by requesting
a user profile from the server.

In the spec, we mention using the Cramer-Shoup secret value "z" and corresponding
public value with Mike Hamburg's Ed448 signature algorithm as detailed in his [paper]
(https://mikehamburg.com/papers/goldilocks/goldilocks.pdf).

We chose this because it follows our theme of using Ed448 encryption security, and two
implementations exist. One is the C version by Mike Hamburg, and the second is in Golang
here: https://github.com/twstrike/ed448.

### Consequences

As OTRv4 upgrades are not to fix any security issue on OTRv3, is acceptable for
users to chat using version 3, but is preferable to use 4 if both support it.

We will support a conversation on version 3 if we don't find any user profile
and user allow it in its policy.

Because of the decision to use the Ed448 signature algorithm, OTRv4 will use the "z"
value for the NIZKPK (Auth())in the DAKE and for the Ed448 signature. We would appreciate
feedback about whether this is safe to do, and if not, what other options do you recommend.
