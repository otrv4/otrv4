## ADR 3: Client Profile

### Context

Currently, OTRv3 supports previous OTR versions by letting the user configure
their version policy to allow or not previous versions: when a user wants to
have a conversation with someone, they send a query message or whitespace tag
which advertises which versions are supported, depending on the defined policy.
This messages (the query message or the whitespace tag) are sent in plaintext at
the beginning of the protocol and, therefore, can be intercepted and changed by
a Man-in-the-middle (MitM) attack to advertise an older/previous version. This
is what will be known as a "version" rollback attack.

In a version rollback attack, a query message or whitespace tag is intercepted
and changed by a MitM to enforce a lower version. At this instance, the protocol
is unable to determine if the highest OTR version both participants support is
been used.

OTRv4 seeks to protect future versions of OTR against these rollback attacks
while still providing backwards compatibility with previous OTR versions. The
mechanism used for this is the usage of signed published Client Profiles. A
Client Profile is a profile that advertises some information (long-term public
keys, versions supported, etc.) related to an user using an specific
client/device. It is published in an untrusted place and transmitted over the
appropriate DAKEs.

Notice that using Client Profiles pertain some considerations: how can values
be revoked, if an user changes any of them?; how is deniability maintained?;
how are Client Profiles associated with devices/clients?

### Decision

To avoid version rollback attacks in OTRv4, both parties must exchange
verified version information, without compromising the deniability properties.
They must do so while maintaining backwards compatibility with OTRv3.

In OTRv4, we still use query messages and whitespace tags from OTRv3, depending
on the mode in which OTRv4 is defined. These messages are mainly used as ping
messages.

As stated, we introduce a Client Profile in OTRv4, which includes:

1. A Client Profile instance tag: an instance tag that defines the client/device
   this profile was generated from.
1. Ed448 public key: the long-term public key associated with an user in
   relationship with its client/device. It is used to verify the signature of
   the Client Profile and to be exchanged during the DAKE. Participants must
   check whether they trust this key and the next one by doing a manual
   fingerprint verification or by executing the Socialist Millionaires Protocol.
1. Ed448 public forging key: the long-term forging public key associated with an
   user in relationship with its client/device. It is used to preserve online
   deniability, while somewhat preventing Key Compromise Impersonation (KCI)
   attacks. Participants must check whether they trust this key and the previous
   one by doing a manual fingerprint verification or executing the Socialist
   Millionaires Protocol.
1. Versions: A string listing the supported versions for a client/device defined
   by the instance tag.
1. Client Profile Expiration: the expiration date of the Client Profile.
1. OTRv3 public authentication DSA key: The OTRv3 DSA long-term public key used
   for verifying the transitional signature. Users must check whether they trust
   this key or not. This value is optional.
1. Transitional Signature: a Transitional Signature, which is a signature of the
   Client Profile excluding the Client Profile Signature and itself. It is
   signed by the Client Profile's OTRv3 DSA long-term key. This value is
   optional.
1. Client Profile Signature: A signature of the above fields (including the
   Transitional Signature and the OTRv3 DSA long-term public key, if present).
   The signature should be generated as defined in RFC 8032,[\[2\]](#references),
   according to the EdDSA scheme. This scheme was chosen as we are using
   Ed448 in OTRv4.

Note that a Client Profile is generated per client/device basis (hence, the
name). Users are not expected to manage Client Profiles (theirs or from others).
As a consequence, clients are discouraged to allow importing or exporting of
Client Profiles. Therefore, if an user has multiple clients concurrently in use,
it is expected that they have multiple Client Profiles simultaneously published
and non-expired.

As both DAKEs in OTRv4 (interactive and non-interactive) require an
implementation-defined identifier for both parties (as defined
in [\[1\]](#references)), the Client Profile is used as that identifier. In
order to maintain the deniability properties of the overall OTRv4 protocol, a
copy of the Client Profile should be published, as stated, in a public untrusted
place. This procedure allows two parties to send and verify each other's signed
Client Profile during the DAKE without damaging the deniability properties of
the conversation: the signed Client Profile is public information, so anyone
could have published it.

The Client Profile must be published in a public place, and updated before it
expires or when one of its values changes. This makes it possible for a
participant that receives a Query Message or a whitespace tag that advertises
versions lower than 4, to check for the published Client Profile from the other
participant and detect a "version" rollback attack. Note that requesting a
Client Profile is not necessary for online conversations (unless checking for
a version rollback attack is needed); but it is necessary for offline
conversations, as it is cached as prekey material in the Prekey server. It's
important to note that the absence of a Client Profile is not proof
that a user doesn't support OTRv4.

Although it is possible to check for a version on a published Client Profile,
this does not stop an attacker from spoofing responses about whether a Client
Profile exists in a public place or not. In the case where an attacker spoofs
the Query Message to contain a lower version (less than 4) and the response
to a request for a Client Profile to advertise that there is no published Client
Profile, a "version" rollback attack is still possible. Nevertheless,
the Client Profile will protect against version rollback attacks for OTRv4 and
higher, as those versions will always require the existence of Client Profiles,
and they will be included on DAKE messages.

A Client Profile has an expiration date to help revoke any past value advertised
in a previous profile. If a user, for example, changes its long-term public key
associated to a client/device, they will publish a new Client Profile and only
this new valid non-expired Client Profile is the one used for attesting that
this is indeed the valid long-term public key. Any expired Client Profile with
old long-term public keys is invalid. Moreover, as version advertisement is
public information (it is stated in the published Client Profile), a participant
will not be able to delete this information from public servers (if the
Client Profile is published in them). To facilitate version revocation or any of
the other values revocation, the Client Profile can be regenerated and
republished once the older Client Profile expires. A short expiration date is
recommended for this reason: it is easier, therefore, to revoke values.

If more than one valid Client Profile is available in the public place defined
by the client, the one with the latest expiry will take priority.

Notice that the lifetime of the validity of the long-term public key is exactly
the same as the lifetime of the Client Profile. If you have no valid Client
Profile available for a specific long-term public key, and you receive a
long-term public key, that long-term public key should be treated as invalid.
Nevertheless, a long-term public key can live for a longer period of time than
the Client Profile, as long-term public keys are not regenerated every time a
Client Profile is renewed.

A Client Profile includes an instance tag, as well. This value is used for
locally storing and retrieving the Client Profile during the non-interactive
DAKE, as it is associated with a device/client. This instance tag has to match
the sender instance tag of any DAKE message the Client Profile is included in.

#### Protecting from rollback in OTRv4

Rollback from v4 protocol to v3 protocol cannot be fully detected by OTRv4, as
Bob's DH-Commit message (from OTRv3) does not contain a Client Profile. After
the OTRv3 AKE finishes, Alice can potentially contact the place where the
Client Profile is published and check for Bob's Client Profile to validate if
Bob really does not support version 4. Note that this mechanism puts trust on
the place where the Client Profile is published.

A MitM attack that generates a "version" rollback attack looks like this:

```
Alice                        Malory                         Bob
 ?OTRv43? --------------->   ?OTRv3?  --------------------->
          <------------------------------------------------ DH-Commit (v3)
 The OTRv3 AKE continues.
```

Rollback from vX (defined after version 4) protocol to v4 protocol can be fully
detected by OTRv4:

- For OTRvX (released after OTRv4), the known protocol versions are:
  X, ..., 4.
- After receiving a Client Profile, an OTRvX client will verify that OTRvX is
  supported and enforce using the "X" version.

```
Alice                               Malory                                Bob
 ?OTRvX4  ----------------------->  ?OTRv4  ---------------------------->
          <-------------------------------------------------------------  Identity Message (v4)
                                                                          + Client Profile (versions "X4")
 Alice's client detects the "version" rollback attack and notifies Alice. It should also abort the DAKE.
```

Consider that the following case is not a "version" rollback attack because "X"
is not a known version from Alice's perspective. Also take into account that the
list of known versions for OTRv4 is (4, 3), and version 3 does not support
Client Profiles. For this reason, the only check to be performed in OTRv4 is
making sure that "4" is in the version field of the received Client Profile.

```
Alice                               Malory                                Bob
 ?OTRv43  ----------------------->  ?OTRvX4  ---------------------------->
          <-------------------------------------------------------------  Identity Message (v4)
                                                                          + Client Profile (versions "43")
 The DAKE continues.
```

### Consequences

OTRv4 makes uses of Client Profiles and mandates them to be published in an
untrusted place. Client Profiles are needed to: advertise verified information
(supported versions, long-term public keys, and instance tags); start offline
conversations; and easily revoke values. They need to be published to: maintain
the deniability properties, revoke past values and prevent "version" rollback
attacks.

Note that, although, it is possible to check for a published version statement
(in the published Client Profile), this does not stop an attacker from spoofing
responses about whether the Client Profile exists or not. As stated, in this
case, an attacker can spoof the Query Message to contain version "3" and also
spoof the response to a request for a Client Profile. This causes a "version"
rollback attack possible when a participant supports version 3.

As OTRv4 does not fix any known security issues in OTRv3 in regards to rollback
attacks, it is acceptable for users to chat using version 3; but it is always
preferable to use version 4 if both participants support it. OTR version 3 will
be supported in a conversation if a Query message or whitespace tag advertises
that version and there can't be found any published Client Profile.

### References

1. Goldberg, I. and Unger, N. (2016). *Improved Strongly Deniable Authenticated
   Key Exchanges for Secure Messaging*, Waterloo, Canada: University of
   Waterloo. Available at:
   http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
2. Josefsson, S. and Liusvaara, I. (2017). *Edwards-curve Digital Signature
   Algorithm (EdDSA)*, Internet Engineering Task Force, RFC 8032. Available at:
   https://tools.ietf.org/html/rfc8032
