## ADR 9: Non-interactive DAKE

### Context

The non-interactive DAKE below is based on the XZDH protocol. It starts when the
Receiver requests the Initiator's prekey from a untrusted server. The
Initiator's long-term public key should be verified by the Receiver. The
Receiver then generates their ephemeral keys and derives a shared secret. These
are used to start the double ratchet and send an encrypted data message with the
final message of the non-interactive DAKE, called the non-interactive auth
message.

#### Long-lived secret ephemeral key material

In OTRv4, the window of key compromise is equivalent to how long it takes for
the double ratchet to refresh the ephemeral key material (2 ratchets, including
the first compromised ratchet) and how long a prekey remains unused before the
user profile becomes expired. We recommend expiration of the user profile to be
a week long, so the window of key compromise will be one week. This is done as
with offline conversations, participants may not receive messages or reply to
them for days, weeks, or months at a time. As a result, the window of compromise
for these kind of conversations can be very long if no limitations are set. We
set an expiration date to reduce this window of compromise.

Primarily, there are two attacks that we want to mitigate:

1. Initiator uploads a prekey. Responder replies, but the adversary intercepts
   and drops the message. The adversary compromises Initiator's prekey secret,
   and Initiator's identity secret key. The adversary can now retroactively
   decrypt the captured initial message.

2. Initiator and Responder complete an exchange and engage in a conversation. At
   some point, the adversary captures and drops some messages to (for example)
   Initiator. Later, the adversary compromises Initiator's ephemeral secrets,
   revealing the message keys corresponding to the dropped messages. The
   adversary can now retroactively decrypt the captured messages.

The first attack is mitigated through the use of XZDH. XZDH uses signed prekeys
with a relatively short expiration time. As a result, an attacker would need to
compromise the secret part of the signed prekey before this expiration time
along with the identity secret key in order to gain access to the message.

The second attack is mitigated in two ways. First, since it cannot be known
whether a message was dropped by an attacker, keys for dropped messages are
never kept. Thus, if Alice receives message 3 from Bob, but she has not received
message 1 and 2, Alice will derive the keys to validate and decrypt message 3.
If the message is valid, all chain keys used for derivation are deleted. In this
case, chain keys for message 1 and message 2 are deleted. This is acceptable
since OTRv4 assumes in-order delivery of messages. As a result, messages
received out of order will be ignored.

Second, to fully defend against attack 2, sessions are expired if no new ECDH
keys are generated within a certain amount of time. This encourages keys to be
removed often at the cost of lost messages whose MAC keys cannot be revealed.
For example, when Alice sets her session expiration time to be 2 hours, Bob must
reply within that time and Alice must create a response to his reply (thus
generating a new ECDH key) in order to reset the session expiration time for
Alice. If Alice does not generate a new ECDH key in two hours, Alice will delete
all keys associated with this session. If she receives a message from Bob using
the expired session, she cannot decrypt the message and thus she cannot reveal
the MAC key associated with it.

This session time is decided individually by each participant or by the client
they use so it is possible for Alice to have an expiration time of two hours and
Bob two weeks. In addition, for the first data message only, the receiver will
start their expiration timer once the message is received. The reason why we use
a timer and don't count events is that we are trying to determine whether
something has not happened within a certain time frame. Thus, the timer can be
compromised by clock errors. Some errors may cause the session to be deleted too
early and result in undecryptable messages being received. Other errors may
result in the clock not moving forward which would cause a session to never
expire. To mitigate this, implementers should use secure and reliable clocks
that cannot be manipulated by an attacker.

The OTRv4 spec will give implementers a guide to determine the amount of time
for session expiration. It is difficult to dictate a good general expiration
time since many secure messaging scenarios exist with different security
requirements. The session expiration is essentially an expiration on the last
message's readability and deniability. The time setter (either the implementer
or the user) should expect that replies are unreadable and undeniable after this
time. For example, if the time is set to 15 minutes, messages received after 15
minutes are unreadable and undeniable, but an attacker must compromise the local
keys within 15 minutes in order to read and tamper with the last message sent
before that time passes. If the time is set to one month, this allows the
responder to reply within one month. However, if the device is compromised
within one month, an attacker is able to read and tamper with the last message
sent.

#### Message formats

Prekey messages have the format:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x55.

Prekey owner's instance tag (INT)
  The instance tag of the client that created the prekey.

Prekey owner's User Profile (USER-PROF)
  As described in the section 'Creating a User Profile'.

Y Prekey owner's ECDH public key (POINT)
  First part of the one-time use prekey value.

B Prekey owner's DH public key (MPI)
  Second part of the one-time use prekey value. The ephemeral public DH
  key. Note that even though this is in uppercase, this is NOT a POINT.
```

The public part of the shared prekey and its signature, which are essential to
implementing XZDH, will be included in the published User Profile. The signature
of the shared prekey must be published to be deniable because it is created
using the participant's long term keys. We consider the signature of the user
profile to be the signature of the shared prekey.

A Non-interactive Auth Message has the format:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x66.

Sender Instance tag (INT)
  The instance tag of the person sending this message.

Prekey Owner's Instance tag (INT)
  The instance tag of the intended recipient.

Y Prekey owner's ECDH public key (POINT)
  First one-time use prekey value.

B Prekey owner's DH public key (MPI)
  Second one-time use prekey value. The ephemeral public DH
  key. Note that even though this is in uppercase, this is NOT a POINT.

Sender's User Profile (USER-PROF)
  As described in the section 'Creating a User Profile'.

X Sender's ECDH Public Key (POINT)

A Sender's DH Public key (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase,
  this is NOT a POINT.

Auth MAC (MAC)
  The MAC with the appropriate MAC key (see above) of the message of the
  SNIZKPK.

Sigma (SNIZKPK)
  The SNIZKPK Auth value.

Encrypted message (DATA)
  Using the appropriate encryption key (see below) derived from the
  sender's and recipient's DH public keys (with the keyids given in this
  message), perform XSalsa20 encryption of the message. The nonce used for
  this operation is also included in the header of the data message
  packet.
```

#### Multiple OTR protocol versions

Prekey messages contain version information. Each client is expected to upload
one prekey per supported version of OTR which uses non-interactive
communication. This is only relevant for OTRv4 and subsequent versions.

#### Publishing and retrieving prekey messages from a prekey server

Describing the details of interactions between OTRv4 clients and a prekey server
are outside the scope of this specification. Implementers are expected to create
their own policy dictating how often their clients upload prekey messages to the
prekey server. Prekey messages expire when their user profile expires. Thus, new
prekey messages should be published to the prekey server before they expire to
keep valid prekey messages available.

A prekey should be published for every long term key that belongs to a user.
This means that if Bob has a client which only supports OTRv4 and he uploads
three long term keys for OTRv4 to his client, Bob's client must publish 3 prekey
messages. Also, if Bob uploads two long term keys for OTRv4 and two long term
keys for OTRvX (a future version of OTR) which also implements the non-
interactive DAKE, Bob will upload 4 keys.

#### Requesting prekey messages from a prekey server

When a client requests prekey messages from a prekey server, many prekey
messages may be returned. For example, when Alice requests prekey messages for
Bob, any of the following may happen:

1. Alice receives two prekey messages for Bob because Bob uses two OTRv4
   clients, one for his phone and one for his laptop. Each client maintains
   their own set of prekey messages on the same prekey server. These two prekey
   messages will be different by instance tag. This scenario can also follow
   different paths:

    1. The two prekey messages may have user profiles created with different
       long term keys. At this point, if Alice trusts only one key, she may
       decide to send a message only to the client with the key she trusts. If
       Alice trusts both keys, she may decide to send a message to one or both.
       If Alice does not trust either key, she may decide not to send a message
       or she may send messages without validating the keys.
    2. The two prekey messages may have user profiles created with the same long
       term key. If this key is trusted, Alice may decide to send a message to
       both client instances. Or Alice may decide to send a message only to the
       first prekey message received. If Alice does not trust the key, she may
       decide not to send a message or send an message to both instances without
       validating the keys.

2. Alice receives two prekey messages for Bob with different user profiles but
   the same instance tag. This can only validly happen if Bob's client supports
   two different versions of OTR that use prekey messages or if the long term
   key used in each message's user profile is different.

    1. If the versions and the long term keys used in the messages are the
       same, and they are compatible with Alice's version, one of the prekey
       messages must be invalid, but Alice cannot know which. She should not
       send a message using either prekey message.
    2. If the prekey message versions are the same and the version is supported
       by Alice, but the long term keys are different from each other, Alice
       should look at whether she trusts the keys. If she trusts both, she may
       send a message to both. If she trusts only one, she may decide to only
       send one message or she may send a message to the untrusted key as well.
       If she trusts neither, she may not send any messages or she may decide to
       send a message to one or both, despite the risks.
    3. If the prekey message versions are different and Alice supports both
       versions, Alice may choose to send a message with both versions or only
       with one, depending on whether she trusts the long term key or keys
       associated with them.
    4. If the prekey message versions are different and Alice supports only one,
       then she can only send a message with the prekey message she supports. If
       the long term key associated with this message is untrusted, she may
       decide not to send a message. If it is trusted, she may send a message.

In the above example, these are the possible situations when only two prekey
messages are received. Of course, many more may be received.

To aid with this complexity, the specification includes a guide for filtering a
list of given prekey messages to remove invalid messages or identify invalid
situations. But the decision on what to do with the remaining messages is up to
the implementer.

Here is the guide:

To validate a prekey message, use the following checks. If any of them fail, ignore the message:

    Check if the user profile is not expired
    Check if the OTR version of the prekey message matches one of the versions
    signed in the user profile contained in the prekey message
    Check if the user profile version is supported by the receiver

If one prekey message is received:

    If the prekey message is valid, decide whether to send a non-interactive
    auth message based on whether the long term key in the user profile is
    trusted or not.

If many prekey messages are received:

    Remove all invalid prekey messages.
    Remove all duplicate prekey messages in the list.
    If one prekey message remains:
        Decide whether to send a message using this prekey message based on
        whether the long term key within the use profile is trusted or not.
    If multiple valid prekey messages remain:
        If there are keys that are untrusted and trusted in the list of
        messages, decide whether to only use messages that contain trusted long
        term keys.
        If there are several instance tags in the list of prekey messages,
        decide which instance tags to send messages to.
        If there are multiple prekey messages per instance tag, decide whether
        to send multiple messages to the same instance tag.

#### Decreased participation deniability for the initiator

OTRv4 will make it clear that non-interactive conversations have different,
lower participation deniability properties for the initiator than interactive
conversations. OTRv4 will also leave it up to the implementer to decide when it
is appropriate to use the non-interactive DAKE and how to convey this security
loss.

#### Multiple DAKEs in the OTR state machine

Currently we have decided on one state machine that can receive multiple DAKEs.
The machine has the following states:

* Start
* Waiting for R Auth
* Waiting for I Auth
* Encrypted Message
* Finished

All states, except the finished state, may receive the second message of a non-
interactive DAKE, called the Non-Interactive-Auth.

#### The prekey server runs out of prekey messages

When the server runs out of prekey messages, OTRv4 expects client
implementations to wait until a prekey message can be transmitted before
continuing with a non-interactive DAKE.

This is purposely different from what we expect from protocols like Signal. In
Signal, when a prekey server runs out of messages, a default message is used
until new messages are uploaded. With this method, the consequences for
participation deniability are currently undefined and thus risky.

By waiting for the server to send prekey messages, OTRv4 will be subject to DoS
attacks when a server is compromised or the network is undermined to return a
"no prekey message available" response from the server. This is preferred over
the possible compromise of multiple non-interactive DAKEs due to the reuse of a
prekey message.