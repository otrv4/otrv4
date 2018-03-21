## ADR 3: User Profile

### Context

Currently, OTRv3 supports previous versions by allowing the user to configure
their version policy to allow previous versions or not: when a user wants to
have a conversation with someone, they should send a query message telling
which versions they support. This message is sent as plaintext at the beginning
of the protocol and can be intercepted and changed by a MITM in a rollback
attack.

In a version rollback attack a query message is intercepted and changed by
a MITM to enforce the lowest version advertised, and the protocol is unable to
really determine if participants are using the highest version they both
support.

OTRv4 seeks to protect future versions of OTR against these rollback attacks
while providing backward compatibility.

Furthermore, as both DAKEs in OTRv4 (interactive and non-interactive) require
an implementation-defined identifier for both parties, we are using the User
Profile as that identifier. For this, a copy of the generated User Profile
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

We introduce a User Profile in OTRv4, which includes:

1. Public key used for verifying a profile signature. Users must check whether
   they trust this key or not.
2. Supported versions in the form of a Query Message string.
3. Expiration date of the User Profile.
4. Transitional Signature (optional): A signature of the profile excluding
   the Profile Signature and itself. It is signed by the user's OTRv3 DSA key.
5. Profile signature of the above parts (including the Transitional Signature if
   present).

Note that a User Profile is generated per client and device basis. Users are not
expected to manage user profiles (theirs or from others) in a client. As a
consequence, clients are discouraged to allow importing or exporting of user
profiles. Also, if a user has multiple clients concurrently in use, it is
expected that they have multiple user profiles simultaneously published and
non-expired.

The User Profile must be published publicly and updated before it expires. The
main reason for doing this is that the publication allows two parties to send
the signed User Profile during the DAKE. Since this signed profile is public
information, it does not damage participation deniability for the conversation.
As a side affect, it is possible for the receiver of a Query Message that
contains versions lower than four to check for a User Profile and thus detect a
rollback attack for older versions. Requesting a User Profile from the server
is not necessary for online conversations using OTRv4. It's important to note
that the absence of a User Profile is not proof that a user doesn't support
OTRv4.

Although it is possible to check for a version publication, this does not stop
an attacker from spoofing responses about whether the profile exists or not. So
in the case where an attacker spoofs the Query Message to contain versions
lower than four and the response to a request for a User Profile, a version
rollback attack is possible. On the other hand, the User Profile will protect
against version rollback attacks for OTRv4 and higher.

If more than one valid User Profile is available from the server defined by the
client, the one with the latest expiry will take priority.

The signature should be generated as defined in RFC 8032 according to the
EdDSA scheme. We chose this scheme because we are using Ed448 for the rest of
OTRv4.

#### Protecting from rollback in OTRv4

Rollback from v4 protocol to v3 protocol can't be detected by OTRv4. Bob's
DH-Commit message does not contain a User Profile. After the AKE finishes,
Alice could contact the Profiles server and ask for Bob's User Profile to
validate if Bob really does not support 4, but this puts the trust on the
server.

```
Alice                        Malory                         Bob
 ?OTRv43  ---------------->  ?OTRv3  --------------------->
          <------------------------------------------------ DH-Commit (v3)
 The OTRv3 AKE continues.
```

Rollback from vX (released after 4) protocol to v4 protocol can be
detected by OTRv4:

- For OTRvX (released after OTRv4), the known state machine versions are:
  X, ..., 4.
- After receiving a User Profile, an OTRvX client may cryptographically
  verify that OTRvX is supported and enforce using that version.

```
Alice                               Malory                                Bob
 ?OTRvX4  ----------------------->  ?OTRv4  ---------------------------->
          <-------------------------------------------------------------  Identity Message (v4)
                                                                          + User Profile (versions "X4")
 Detects the rollback and notifies the user. Should also abort the DAKE.
```

Notice the following case is not a rollback because "X" is not a known version
from Alice's perspective. Also notice that the list of known versions for OTRv4
is (4, 3) - and 3 does not support User Profiles. In this case, the only check
you need to perform in OTRv4 is making sure "4" is in the received User Profile.

```
Alice                               Malory                                Bob
 ?OTRv43  ----------------------->  ?OTRv4  ---------------------------->
          <-------------------------------------------------------------  Identity Message (v4)
                                                                          + User Profile (versions "X43")
 The DAKE continues.
```

### Consequences

Although it is possible to check for a version statement publication, this does
not stop an attacker from spoofing responses about whether the version statement
(or a User Profile) exists or not. In this case an attacker can spoof the Query
Message to contain version "3" and also spoof the response to a request for a
version statement, making a rollback attack possible when the victims support
OTRv3.

As OTRv4 upgrades do not fix any known security issue on OTRv3, it is
acceptable for users to chat using version 3, but is preferable to use 4 if
both parties support it.

We will support a conversation using version 3 if we don't find any published
User Profile.
