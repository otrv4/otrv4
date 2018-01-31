## ADR 014: Version Rollback

### Context

OTRv3 is backward compatible with other versions, and a user can configure their
version policy to choose whether previous versions should be allowed.

When a user wants to have a conversation with someone, they should request a
conversation by sending a Query Message that includes the versions they would
like to use. Alternatively, a Whitespace Tag can be used to indicate willingness
of using OTR at specific versions.

In a version rollback attack, a Query Message is intercepted and changed by
a MiTM to enforce the lowest version advertised, and the protocol is unable to
determine if participants are using the highest version they both support. The
same applies to a Whitespace Tag.

By exchanging authenticated version information, OTRv4 introduces a strategy that
future versions of OTR can use to protect from version rollback attacks without
compromising participation deniability.

### Decision

A user MUST publish a statement of the versions they support. The version
statement is a string with the same format and same meaning as OTR Query
Message's "version string" (see OTR3, section "OTR Query Messages").

This makes it possible for the receiver of a Query Message that contains
versions lower than OTRv4 to check for a version statement and thus detect a
attempted rollback to older versions.

In order to preserve participation deniability, the version statement MUST be
published publicly and updated before it expires.

In order to obtain version statements for a participant, a user MUST obtain the
participant's User Profile and verify its authenticity as described in ADR 003.

#### Protecting from rollback in OTRv4

Rollback from v4 protocol to v3 protocol can't be detected by OTRv4. Bob's
DH-Commit message does not contain a verified version information (in a User
Profile). Alice could obtain this information after the AKE finishes (through
the encrypted channel), and ask a server for Bob's published User Profile to
validate if Bob really does not support 4, but this puts the trust on the server.

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
OTR3.

As OTRv4 upgrades do not fix any known security issue on OTRv3, it is
acceptable for users to chat using version 3, but is preferable to use 4 if
both parties support it.

We will support a conversation using version 3 if we don't find any user
profile and the client allows it.

