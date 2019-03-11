## ADR 9: Non-interactive DAKE

### Context

The non-interactive DAKE below is based on the XZDH protocol. It starts when the
Responder requests the Initiator's Prekey Ensemble from an untrusted Prekey
Server. The Initiator's long-term public key should be verified by the
Responder. The Responder then generates their ephemeral keys and derives a Mixed
shared secret. These are used to start the Double Ratchet Algorithm and allow
for sending a data message directly after the DAKE. Subsequent encrypted
messages can be sent after this.

#### Long-lived secret ephemeral key material

In OTRv4, the window of key compromise is equivalent to how long it takes for
the double ratchet to refresh the ephemeral key material (2 ratchets, including
the first compromised ratchet) and how long a prekey message remains unused
before the Prekey Profile becomes expired. We recommend expiration of the Client
Profile and the Prekey Profile to be a week long, so the window of key
compromise will be one week. This is done as with offline conversations,
participants may not receive messages or reply to them for days, weeks, or
months at a time. As a result, the window of compromise for these kind of
conversations can be very long if no limitations are set. We set an expiration
date to reduce this window of compromise.

Primarily, there are two attacks that we want to mitigate:

1. An active adversary modifies the first flow from the Initiator to use an
   adversarially controlled prekey's ephemeral key, captures and drops the
   response from the Responder, and then compromises the Initiator's long-term
   secret key. The Initiator will never see the message, and the adversary will
   be able to decrypt it. Moreover, since long-term keys are usually meant to
   last for years, a long time may pass between the Responder sending the
   message and the adversary compromising the Initiator’s key. This attack
   requires a powerful adversary.

2. Initiator and Responder complete an exchange and engage in a conversation.
   At some point, the adversary captures and drops some messages to (for
   example) Initiator. Later, the adversary compromises Initiator's ephemeral
   secrets, revealing the message keys corresponding to the dropped messages.
   The adversary can now retroactively decrypt the captured messages.

The first attack is mitigated through the use of XZDH. XZDH uses signed shared
prekeys with a relatively short expiration time. As a result, an attacker would
need to compromise the secret part of the signed shared prekey before this
expiration time along with the long-term secret key in order to be able to
decrypt the message.

The second attack is mitigated in two ways. Keys for dropped messages or
skipped messages are kept for a period of time. If Alice, for example, receives
only message 3 from Bob, but she has not received message 1 and 2, Alice will
derive the keys to validate and decrypt message 3. If the message is valid, all
chain keys used for derivation are deleted but the message keys are kept.
In this case, chain keys for message 1 and message 2 are deleted. The stored
message keys remain stored until an appropriate interval (defined by
implementers) triggers its deletion, which partially defends against the second
attack.

Second, to fully defend against attack 2, sessions are expired if no new ECDH
keys are generated within a certain amount of time. This encourages keys to be
removed often at the cost of lost messages whose MAC keys cannot be revealed.
For example, when Alice sets her session expiration time to be 2 hours, Bob
must reply within that time and Alice must create a response to his reply (thus
generating a new ECDH key) in order to reset the session expiration time for
Alice. If Alice does not generate a new ECDH key in two hours, Alice will
delete all keys associated with this session. If she receives a message from
Bob using the expired session, she cannot decrypt the message and thus she
cannot reveal the MAC key associated with it.

This session time is decided individually by each participant or by the client
they use so it is possible for Alice to have an expiration time of two hours
and Bob two weeks. In addition, for the first data message only, the receiver
will start their expiration timer once the message is received. The reason why
we use a timer and don't count events is that we are trying to determine
whether something has not happened within a certain time frame. Thus, the timer
can be compromised by clock errors. Some errors may cause the session to be
deleted too early and result in undecryptable messages being received. Other
errors may result in the clock not moving forward which would cause a session
to never expire. To mitigate this, implementers should use secure and reliable
clocks that cannot be manipulated by an attacker.

The OTRv4 spec will give implementers a guide to determine the amount of time
for session expiration. It is difficult to dictate a good general expiration
time since many secure messaging scenarios exist with different security
requirements. The session expiration is essentially an expiration on the last
message's readability and deniability. The time setter (either the implementer
or the user) should expect that replies are unreadable and undeniable after
this time. For example, if the time is set to 15 minutes, messages received
after 15 minutes are unreadable and undeniable, but an attacker must compromise
the local keys within 15 minutes in order to read and tamper with the last
message sent before that time passes. If the time is set to one month, this
allows the receiver to reply within one month. However, if the client is
compromised within one month, an attacker is able to read and tamper with the
last message sent.

Due to the usage of the Double Ratchet Algorithm in the protocol, a correct way
for initializing it after the non-interactive DAKE must be taken into
consideration. To preserve the security proofs of the DAKE [\[1\]](#references),
initial ephemeral keys (that are not used for the Ring Signature or the
derivation of the first Mixed Shared Secret) are used. These keys are attached
to the second non-interactive DAKE message (the Non-Interactive-Auth message).
These ratcheting ephemeral public keys should be included in the "Phi" value.

#### Message formats

Prekey messages have the format:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x55.

Prekey owner's instance tag (INT)
  The instance tag of the client that created the prekey.

Y Prekey owner's ECDH public key (POINT)
  First part of the one-time use prekey value.

B Prekey owner's DH public key (MPI)
  Second part of the one-time use prekey value. The ephemeral public DH key.
  Note that even though this is in uppercase, this is NOT a POINT.
```

These prekey messages are uploaded to the untrusted Prekey Server along with
a Client Profile and a Prekey Profile. These three values create what is defined
as a Prekey Ensemble.

The public part of the Shared Prekey and its signature, which are essential to
implementing XZDH, will be included in the published Prekey Profile. The
signature of the Shared Prekey must be published in order to be deniable as it
is created using the participant's long term keys.

A Non-interactive Auth Message has the format:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x8D.

Sender's instance tag (INT)
  The instance tag of the person sending this message.

Receiver's instance tag (INT)
  The instance tag of the intended recipient.

Sender's Client Profile (CLIENT-PROF)
  As described in the section "Creating a Client Profile".

X (POINT)
  The ephemeral public ECDH key.

A (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase, this
  is NOT a POINT.

Sigma (RING-SIG)
  The 'RING-SIG' proof of authentication value.

Prekey Message Identifier (INT)
  The 'Prekey Message Identifier' from the Prekey message that was retrieved
  from the untrusted Prekey Server, as part of the Prekey Ensemble.

Auth MAC (MAC)
  The MAC with the appropriate MAC key (see above) of the message (t) for the
  Ring Signature (RING-SIG).

our_ecdh_first.public
  The ephemeral public ECDH key that will be used for the intialization of
  the double ratchet algorithm.

our_dh_first.public
  The ephemeral public DH key that will be used for the intialization of
  the double ratchet algorithm.
```

#### Multiple OTR protocol versions

Prekey messages contain version information. Each client is expected to upload
one prekey per supported version of OTR which uses non-interactive
communication. This is only relevant for OTRv4 and subsequent versions.

#### Publishing and retrieving prekey emsembles from a prekey server

Describing the details of interactions between OTRv4 clients and a Prekey
Server are outside the scope of this specification. Implementers are expected
to create their own policy dictating how often their clients upload Prekey
ensembles to the prekey server. Nevertheless, clients are expected to upload
Client Profile and Prekey Profile when the old ones are expired. Thus, new
Client Profiles and Prekey Profiles should be published to the untrusted Prekey
Server before they expire to keep valid values for the Prekey Ensemble
available.

A Client Profile and Prekey Profile should be published for every long-term
public key that belongs to a user for this client. This means that if Bob has a
client which only supports OTRv4 and he uploads three long term keys for OTRv4
to his client, Bob's client must publish 3 Client Profiles and 3 Prekey
Profiles. Also, if Bob uploads two long term keys for OTRv4 and two long term
keys for OTRvX (a future version of OTR) which also implements the
non-interactive DAKE, Bob will upload 4 profiles respectively.

#### Requesting prekey ensembles from a Prekey Server

When a client requests prekey ensembles from a Prekey Server, many prekey
ensembles may be returned. For example, when Alice requests prekey ensembles for
Bob, any of the following may happen:

1. Alice receives two prekey ensembles for Bob because Bob uses two OTRv4
   clients, one for his phone and one for his laptop. Each client maintains
   their own set of prekey ensembles on the same Prekey Server. These two prekey
   ensembles will be different by instance tag (meaning there will be two Client
   Profiles, two Prekey Profiles and two prekey messages with different instance
   tags). This scenario can, therefore, follow different paths:

    1. The two prekey ensembles may have Client Profiles created with different
       long-term keys and two Prekey Profiles signed by those different keys
       respectively. At this point, if Alice trusts only one key, she may decide
       to send a message only to the client with the key she trusts. If Alice
       trusts both keys, she may decide to send a message to one or both. If
       Alice does not trust either key, she may decide not to send a message
       or she may send messages without validating the keys.
    2. The two prekey ensembles may have Client Profiles created with the same
       long-term key and Prekey Profiles signed by the same key. If this key is
       trusted, Alice may decide to send a message to both client instances. Or
       Alice may decide to send a message only to the first Prekey Ensemble
       received. If Alice does not trust the key, she may decide not to send a
       message or send an message to both instances without validating the keys.

2. Alice receives two prekey ensembles from Bob with different Client Profiles
   but the same instance tag (the Prekey Profiles are signed with the
   corresponding long-term key stated in the Client profiles). This can only
   validly happen if Bob's client supports two different versions of OTR that
   use Prekey Ensembles or if the long-term public key used in each ensemble's
   Client Profile is different.

    1. If the versions and the long-term keys used in the Client Profiles
       and prekey messages are the same, and they are compatible with Alice's
       version, one of the prekey ensembles must be invalid, but Alice cannot
       know which. She should not send a message using either prekey ensemble.
    2. If the prekey ensemble versions are the same and the version is supported
       by Alice, but the long-term keys are different from each other, Alice
       should look at whether she trusts the keys. If she trusts both, she may
       send a message to both. If she trusts only one, she may decide to only
       send one message or she may send a message to the untrusted key as well.
       If she trusts neither, she may not send any messages or she may decide
       to send a message to one or both, despite the risks.
    3. If the prekey ensemble versions are different and Alice supports both
       versions, Alice may choose to send a message with both versions or only
       with one, depending on whether she trusts the long-term public key or
       keys associated with them.
    4. If the prekey ensemble versions are different and Alice supports only
       one, then she can only send a message with the prekey ensemble she
       supports. If the long-term public key associated with this message is
       untrusted, she may decide not to send a message. If it is trusted, she
       may send a message.

In the above example, these are the possible situations when only two prekey
ensembles are received. Of course, many more may be received.

To aid with this complexity, the specification includes a guide for filtering a
list of given prekey ensembles to remove invalid messages or identify invalid
situations. But the decision on what to do with the remaining messages is up to
the implementer.

Here is the guide:

To validate a prekey ensemble, use the following checks. If any of them fail,
ignore the message:

```
  1. Check that all the instance tags on the Prekey Ensemble's values are the
     same.
  2. Validate the Client Profile.
  3. Validate the Prekey Profile.
  4. Check that the Prekey Profile is signed by the same long-term public key
     stated on it and on the Client Profile.
  5. Verify the Prekey message as stated on its section.
  6. Check that the OTR version of the prekey message matches one of the
     versions signed in the Client Profile contained in the Prekey Ensemble.
  7. Check if the Client Profile's version is supported by the receiver.
```

If one Prekey Ensemble is received:

```
  If the prekey ensemble is valid, decide whether to send a Non-Interactive
  Auth message based on whether the long-term public key in the Client Profile
  is trusted or not.
```

If many prekey ensembles are received:

```
  1. Remove all invalid ensembles.
  2. Remove all duplicate prekey ensembles in the list.
  3. If one prekey message remains:
     a. Decide whether to send a message using this prekey ensemble based on
        whether the long-term public key within the use profile is trusted or
        not.
  4. If multiple valid prekey ensembles remain:
     a. If there are keys that are untrusted and trusted in the list of
        messages, decide whether to only use messages that contain trusted long
        term keys.
     b. If there are several instance tags in the list of prekey ensembles,
        decide which instance tags to send messages to.
     c. If there are multiple prekey ensembles per instance tag, decide whether
        to send multiple messages to the same instance tag.
```

#### Decreased participation deniability for the responder

OTRv4 will make it clear that non-interactive conversations have different,
lower participation deniability properties for the responder than in interactive
conversations. OTRv4 will also leave it up to the implementer to decide when it
is appropriate to use the non-interactive DAKE and how to convey this security
loss.

#### Multiple DAKEs in the OTR state machine

Currently we have decided on one state machine that can receive multiple DAKEs.
The machine has the following states:

* Start
* Waiting for Auth-R
* Waiting for Auth-I
* Encrypted Message
* Finished

All states, except the finished state, may receive the second message of a
non-interactive DAKE, called the Non-Interactive-Auth.

#### The prekey server runs out of prekey ensembles

When the server runs out of prekey ensembles (or one of its values), OTRv4
expects client implementations to wait until a prekey ensemble can be
retrieved before continuing with a non-interactive DAKE.

This is purposely different from what we expect from protocols like Signal. In
the Signal protocol, when a Prekey Server runs out of messages, a default
message is used until new messages are uploaded. The consequences to
participation deniability with this technique are currently undefined and thus
risky.

By waiting for the Prekey Server to send prekey ensembles, OTRv4 will be subject
to DoS attacks when a server is compromised or the network is undermined to
return a "No prekey message available" response from the server. This is
preferred over the possible compromise of multiple non-interactive DAKEs due to
the reuse of a prekey ensemble.
