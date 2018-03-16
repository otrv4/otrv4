## ADR 3: User Profile

### Context

Currently, OTRv3 supports previous versions by allowing the user to configure
their version policy to allow previous versions or not: when a user wants to
have a conversation with someone, they should send a query message telling
which versions they support.

OTRv4 seeks to protect future versions of OTR against rollback attacks when
backward compatibility is kept.

Furthermore, as both DAKEs in OTRv4 (interactive and non-interactive) require
an implementation-defined identifier for both parties, we are using the User
Profile as that identifier. For this, a copy of the generated user profile
should be published in a public place to achieve deniability properties. This
procedure allows two parties to send and verify each other's signed User Profile
during the DAKE without damaging participation deniability for the conversation,
since the signed profile is public information.

### Decision

To address version rollback attacks and to keep deniability in OTR, both parties
must exchange verified version information without compromising their
participation deniability while keeping backwards compatibility with OTRv3.

We keep the use of query message for OTRv3 compatibility but it will work as a
ping message.

We introduce a user profile in OTRv4, which includes:

1. Public key used for verifying a profile signature. Users must check whether
   they trust this key or not.
2. Supported versions in the form of a Query Message string.
3. Expiration date of the User Profile.
4. Public Shared Prekey which is required for the [Non-Interactive
   DAKE](https://github.com/otrv4/otrv4/blob/master/architecture-decisions/009-non-interactive-dake.md).
6. Transitional Signature (optional): A signature of the profile excluding
   the Profile Signature and itself. It is signed by the user's OTRv3 DSA key.
5. Profile signature of the above parts (including the Transitional Signature if
   present).

Note that a user profile is generated per client and device basis. Users are not
expected to manage user profiles (theirs or from others) in a client. As a
consequence, clients are discouraged to allow importing or exporting of user
profiles. Also, if a user has multiple clients concurrently in use, it is
expected that they have multiple user profiles simultaneously published and
non-expired.

The user profile must be published publicly and updated before it expires. The
main reason for doing this is that the publication allows two parties to send
the signed User Profile during the DAKE. Since this signed profile is public
information, it does not damage participation deniability for the conversation.
As a side affect, it is possible for the receiver of a Query Message that
contains versions lower than four to check for a User Profile and thus detect a
rollback attack for older versions. Requesting a user profile from the server
is not necessary for online conversations using OTRv4. It's important to note
that the absence of a user profile is not proof that a user doesn't support
OTRv4.

Although it is possible to check for a version publication, this does not stop
an attacker from spoofing responses about whether the profile exists or not. So
in the case where an attacker spoofs the Query Message to contain versions
lower than four and the response to a request for a User Profile, a version
rollback attack is possible. On the other hand, the user profile will protect
against version rollback attacks for OTRv4 and higher.

If more than one valid user profile is available from the server defined by the
client, the one with the latest expiry will take priority.

The signature should be generated as defined in RFC 8032 according to the
EdDSA scheme. We chose this scheme because we are using Ed448 for the rest of
OTRv4.

### Consequences

As OTRv4 upgrades do not fix any known security issue on OTRv3, it is
acceptable for users to chat using version 3, but is preferable to use 4 if
both parties support it.

We will support a conversation using version 3 if we don't find any published
user profile.
