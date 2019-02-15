## ADR 3: Client Profile

### Context

Currently, OTRv3 supports previous OTR versions by allowing the user to configure
their version policy to allow previous versions or not: when a user wants to
have a conversation with someone, they send a query message which states
which versions are supported. This message is sent as plaintext at the beginning
of the protocol and, therefore, can be intercepted and changed by a MITM for a
rollback attack.

In a version rollback attack, a query message is intercepted and changed by
a MITM to enforce the lowest version advertised, and the protocol is unable to
really determine if participants are using the highest version both participants
support.

OTRv4 seeks to protect future versions of OTR against these rollback attacks
while still providing backwards compatibility. The mechanism used for this is the
usage of signed published Client Profiles.

As both DAKEs in OTRv4 (interactive and non-interactive) require an
implementation-defined identifier for both parties, the Client Profile is also
used as that identifier. To achieve this, a copy of the generated Client Profile
should be published in a public place to maintain the deniability properties of
the overall protocol. This procedure allows two parties to send and verify each
other's signed Client Profile during the DAKE without damaging participation
deniability for the conversation, since the signed Client Profile is public
information, and anyone could have published it.

A Client Profile has an expiration date as this helps to revoke any past value
stated on a previous profile. If a user's client, for example, changes its
long-term public key, only the valid non-expired Client Profile is the one used
for attesting that this is indeed the valid long-term public key. Any expired
Client Profile with old long-term public keys is invalid. Moreover, as
version advertisement is public information (it is stated in the published
Client Profile), a participant will not be able to delete this information from
public servers (if the Client Profile is published in them). To facilitate
versions revocation or any of the other values revocation, the Client Profile
can be regenerated and published once the older Client Profile expires. This is
the reason why we recommend a short expiration date, so values can be easily
revoked.

Furthermore, notice that the lifetime of the long-term public key is exactly the
same as the lifetime of the Client Profile. If you have no valid Client Profile
available for a specific long-term public key, that long-term public key should
be treated as invalid. Nevertheless, a long-term public key can live for longer
than a Client Profile as long-term public keys are not generated every time a
Client Profile is renewed.

A Client Profile also includes an instance tag. This value is used for locally
storing and retrieving the Client Profile during the non-interactive DAKE. This
instance tag has to match the sender instance tag of any DAKE message the Client
Profile is included in.

### Decision

To address version rollback attacks and to keep deniability in OTRv4, both parties
must exchange verified version information, without compromising their
participation deniability while keeping backwards compatibility with OTRv3.

On OTRv4, we still use query messages (for OTRv3 compatibility) but it's usage
is more like a ping message.

We introduce a Client Profile in OTRv4, which includes:

1. The long-term public key of the participant. It is used for verifying the
   Client Profile signature and to be exchanged during the DAKE. Participants
   must  check whether they trust this key or not by doing manual fingerprint
   verification or executing the Socialist Millionaries Protocol.
2. Supported versions in the form of a string.
3. Expiration date of the Client Profile.
4. OTRv3 DSA long-term public key used for verifying the transitional signature.
   Users must check whether they trust this key or not. This value is optional.
5. A Transitional Signature, which is a signature of the Client Profile
   excluding the Client Profile Signature and itself. It is signed by the
   user's OTRv3 DSA long-term key. This value is optional.
6. Client Profile signature of the above parts (including the Transitional
   Signature and the OTRv3 DSA long-term public key if present).

Note that a Client Profile is generated per client basis (hence, the name).
Users are not expected to manage Client Profiles (theirs or from others). As a
consequence, clients are discouraged to allow importing or exporting of Client
Profiles. Also, if a user has multiple clients concurrently in use, it is
expected that they have multiple Client Profiles simultaneously published and
non-expired.

The Client Profile must be published publicly and updated before it expires. The
main reason for doing this is that the publication allows two parties to send
the signed Client Profile during the DAKE. Since this signed Client profile is
public information, it does not damage participation deniability for the
conversation. As a side affect, it is possible for the receiver of a Query
Message that contains versions lower than four to check for a Client Profile
and be able to detect a version rollback attack. Requesting a Client Profile
from the server is not necessary for online conversations using OTRv4. It's
important to note that the absence of a Client Profile is not proof that a user
doesn't support OTRv4.

Although it is possible to check for a version on a published Client Profile,
this does not stop an attacker from spoofing responses about whether a Client
Profile exists or not. In the case where an attacker spoofs the Query Message to
contain a lower version (less than four) and the response to a request for a
Client Profile, a version rollback attack is still possible. On the other hand,
the Client Profile will protect against version rollback attacks for OTRv4 and
higher.

If more than one valid Client Profile is available from the server defined by
the client, the one with the latest expiry will take priority.

The signature should be generated as defined in RFC 8032 according to the
EdDSA scheme. We chose this scheme because we are using Ed448 for the rest of
OTRv4.

#### Protecting from rollback in OTRv4

Rollback from v4 protocol to v3 protocol cannot be fully detected by OTRv4, as
Bob's DH-Commit message (from OTRv3) does not contain a Client Profile. After
the AKE finishes, Alice could potentially contact the place where the Client
Profile is published and ask for Bob's Client Profile to validate if Bob really
does not support 4. This mechanism assumes that the place where the Client
Profile is published is trusted.

```
Alice                        Malory                         Bob
 ?OTRv43? --------------->   ?OTRv3?  --------------------->
          <------------------------------------------------ DH-Commit (v3)
 The OTRv3 AKE continues.
```

Rollback from vX (released after 4) protocol to v4 protocol can be fully
detected by OTRv4:

- For OTRvX (released after OTRv4), the known state machine versions are:
  X, ..., 4.
- After receiving a Client Profile, an OTRvX client may cryptographically
  verify that OTRvX is supported and enforce using that version.

```
Alice                               Malory                                Bob
 ?OTRvX4  ----------------------->  ?OTRv4  ---------------------------->
          <-------------------------------------------------------------  Identity Message (v4)
                                                                          + Client Profile (versions "X4")
 Detects the rollback and notifies the user. Should also abort the DAKE.
```

Notice the following case is not a rollback because "X" is not a known version
from Alice's perspective. Also notice that the list of known versions for OTRv4
is (4, 3) - and 3 does not support Client Profiles. In this case, the only check
you need to perform in OTRv4 is making sure "4" is in the received Client
Profile.

```
Alice                               Malory                                Bob
 ?OTRv43  ----------------------->  ?OTRvX4  ---------------------------->
          <-------------------------------------------------------------  Identity Message (v4)
                                                                          + Client Profile (versions "43")
 The DAKE continues.
```

### Consequences

Although it is possible to check for a version statement publication, this does
not stop an attacker from spoofing responses about whether the version statement
(or a Client Profile) exists or not. In this case an attacker can spoof the
Query Message to contain version "3" and also spoof the response to a request
for a Client Profile, making a rollback attack possible when the victims
support OTRv3.

As OTRv4 do not fix any known security issue on OTRv3 in regards to rollback
attacks, it is acceptable for users to chat using version 3, but is preferable
to use 4 if both parties support it.

We will support a conversation using version 3 if a Query message advertises it
and if we don't find any published Client Profile.
