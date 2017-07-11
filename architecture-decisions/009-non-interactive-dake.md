## ADR 8: Non-interactive DAKE

### Context

OTRv3 only provides an interactive AKE and adding support for a non-interactive
AKE is a usability feature. The non-interactive DAKE below is based on the ZDH
protocol. It starts when the receiver (R) requests a prekey for the initiator
(I) from a untrusted server. I's long-term public key should be verified by R.

The receiver then generates their ephemeral keys and derives a shared secret
which is used to send an encrypted data message together with the final message
of the non-interactive DAKE. This second message is called the non-interactive
auth message.

In the non-interactive DAKE, only one data message can be sent per use of a
prekey. The reasons for this are in the section [Long-lived secret ephemeral key
material](#long-lived-secret-ephemeral-key-material). This means that ratchets
do not happen in the non-interactive case. Thus, one encryption key and one MAC
key are derived from the shared secret, and after the non-interactive auth
message is sent, all key material generated for this conversation is deleted.

#### Long-lived secret ephemeral key material

In OTR4, the window of key compromise is equivalent to how long it takes for the
double ratchet to refresh the ephemeral key material (2 ratchets, including the
first compromised ratchet) and how long a prekey remains unused before the user
profile inside becomes expired. We recommend expiration to be a week long, so
the window in that case is one week. In non-interactive conversations,
participants may not receive messages or reply to them for days, weeks, or
months at a time. As a result, the window of compromise for these kind of
conversations can be very long if no limitations are set. We would like to
reduce this window.

If the DH and ECDH secret ephemeral keys are compromised for a participant,
several things can happen. First, all messages sent encrypted with keys derived
from these compromised keys will be readable to the attacker. This includes
messages sent by the compromised participant and the following ratchet of
replies by the uncompromised participant. Second, all these readable messages
may be manipulated by an active attacker. This can result in a [key-compromise
impersonation
attack](https://whispersystems.org/docs/specifications/x3dh/#key-compromise),
where the active attacker impersonates other parties to the compromised
participant. Third, an active attacker can compromise further ratchets by
continuously substituting their keys to maintain the ability to eavesdrop on the
compromised session.

The [Sesame
protocol](https://whispersystems.org/docs/specifications/sesame/#session-expiration)
offers one solution to limit the window of compromise by creating a timestamp
for each new conversation. This timestamp is used to keep track of how long a
conversation has been going on and thus trigger the use of a new prekey after a
set time has past. The problem with this solution is that it trusts the server
to send the correct time difference. If time difference messages from the server
are manipulated, the timestamp cannot be relied upon. In addition, compromised
participants cannot send a timestamp themselves since that information can be
manipulated by the active attacker who has the private key material.

Another strategy is to limit the number of messages sent with these ephemeral
keys. In one solution, each sender must always create a new ratchet with a new
prekey when they want to send a non-interactive message. Additional messages
sent by the same initiator are encrypted using the shared secret derived from the
prekey. If the receiver would like to reply, they must retrieve a new prekey for the
initiator and start a new non-interactive DAKE. This would minimize the impact
of compromise to all of the sender's data messages in a ratchet. Replies by the
uncompromised party are no longer revealed and manipulatable.

In another similar solution, each non-interactive message must be created with a
new prekey. Thus each non-interactive DAKE results in an encrypted channel that
sends only one data message. As a result, ephemeral key material can be deleted
immediately after a non-interactive message is sent or received. This maximally
limits the effect of key compromise for both parties by revealing only one
message to the attacker at a time. This also eliminates continued MITM attacks
to impersonate a participant or continuously compromise the channel. Lastly,
this forces prekeys to be used often--thus requiring their frequent removal from
storage and resulting in a smaller window of compromise for prekeys.

The disadvantages of these two last solutions are that they require clients to
set up servers with a large number of prekeys per participant and processes that
require frequent replenishment of prekeys. Second, possession of participation
deniability will switch frequently between both participants. This is because
each reply results in participation deniability lost by the sender. So if Alice
and Bob send the following non-interactive messages, one right after the other:

```
Alice                            Bob
------------------------------------------------
1) Hi ---------------------------->
2)  <----------------------------- Hi
3) How's it going? --------------->
4)  <----------------------------- Good, you?
```

Alice loses participation deniability for message 1 and 3, and Bob loses
participation deniability for message 2 and 4.

With all of these considerations, OTR4 will expect each non-interactive message
to be created with a new prekey. This is the most effective means of minimizing
the window of compromise, despite its effect on participation deniability and
the increased usage of prekeys. This is a purposeful prioritization of data
message security.

#### Revealing MAC keys

MAC keys can only be revealed when the data messages are received. This is
because if the sender publishes them earlier, other parties can compromise the
message before it is read by the intended recipient. As a result, if the
receiver of a non-interactive message does not go online for days or weeks, the
MAC keys for this message cannot be revealed within that time. Thus, OTR4
expects implementations to immediately send a specific non-interactive reveal
message once they receive, validate, and successfully decrypt the
non-interactive auth message.

The non-interactive reveal message does not contain encrypted plaintext provided
by the user. Its purpose is to immediately reveal MAC keys to provide data
message deniability for the other party, much like a "heartbeat" message in
OTRv3. The format of this message is in the [message
formats](#message-formats) section.

#### Message formats

Prekeys have the format:

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

B Prekey owner's DH public key (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase,
  this is NOT a POINT.
```

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

Sender's User Profile (USER-PROF)
  As described in the section 'Creating a User Profile'.

X Sender's ECDH Public Key (POINT)

A Sender's DH Public key (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase,
  this is NOT a POINT.

Auth MAC (MAC)
  The SHA3 MAC with the appropriate MAC key (see above) for the message of the SNIZKPK.

Sigma (SNIZKPK)
  The SNIZKPK Auth value.

Nonce (NONCE)
  The nonce used with XSalsa20 to create the encrypted message contained
  in this packet.

Encrypted message (DATA)
  Using the appropriate encryption key (see below) derived from the
  sender's and recipient's DH public keys (with the keyids given in this
  message), perform XSalsa20 encryption of the message. The nonce used for
  this operation is also included in the header of the data message
  packet.

Data Message Authenticator (MAC)
  The SHA3 MAC with the appropriate MAC key (see above) for everything:
  from the protocol version to the end of the encrypted message.
```

Non-interactive Reveal MAC Key Message:
```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x77.

Old MAC key to be revealed (MAC)
```
#### Multiple OTR protocol versions

Prekeys contain version information, as detailed above. Each client is expected
to upload one prekey per supported version of OTR which uses non-interactive
communication. This is only relevant for versions of OTR from 4 and onward.

#### Publishing and retrieving prekeys from a prekey server

Describing the details of interactions between OTRv4 clients and a prekey server
are outside the scope of this specification. Implementers are expected to create
their own policy dictating how often their clients upload prekeys to the prekey
server. Prekeys expire when their user profile expires. Thus new prekeys should
be published to the prekey server before they expire to keep valid prekeys
available.

A prekey should be published for every long term key that belongs to a user.
This means that if Bob has a client which only supports OTRv4 and he uploads
three long term keys for OTRv4 to his client, Bob's client must publish 3
prekeys. Also, if Bob uploads two long term keys for OTRv4 and two long term
keys for OTRvX which also supports prekeys, Bob will upload 4 keys.

When a client requests prekeys from a prekey server, many prekeys may be
returned. For example, when Alice requests prekeys for Bob, any of the following
may happen:

1. Alice receives two prekeys for Bob because Bob uses two OTRv4 clients, one
   for his phone and one for his laptop. Each client maintains their own set of
   prekeys on the same prekey server. These two prekeys will be different by
   instance tag. This scenario can also follow different paths:
    1. The two prekeys may have user profiles created with different long term
       keys. At this point, if Alice trusts only one key, she may decide to send
       a message only to the client with the key she trusts. If Alice trusts
       both keys, she may decide to send a message to one or both. If Alice does
       not trust either key, she may decide not to send a message or she may
       send messages without validating the keys.
    1. The two prekeys may have user profiles created with the same long term
       key. If this key is trusted, Alice may decide to send a message to both
       client instances. Or Alice may decide to send a message only to the first
       prekey received. If Alice does not trust the key, she may decide not to
       send a message or send an message to both instances without validating
       the keys.
1. Alice receives two prekeys for Bob with different user profiles but the same
   instance tag. This can only validly happen if Bob's client supports two
   different versions of OTR that use prekeys or if the long term key used in
   each prekey's user profile is different.
    1. If the prekey versions and the long term keys used in the prekey are the
       same, and they are compatible with Alice's version, one of the prekeys
       must be invalid, but Alice cannot know which. She should not send a
       message using either prekey.
    1. If the prekey versions are the same and the version is supported by
       Alice, but the long term keys are different from each other, Alice should
       look at whether she trusts the keys. If she trusts both, she may send a
       message to both. If she trusts only one, she may decide to only send one
       message or she may send a message to the untrusted key as well. If she
       trusts neither, she may not send any messages or she may decide to send a
       message to one or both, despite the risks.
    1. If the prekey versions are different and Alice supports both versions,
       Alice may choose to send a message with both versions or only with one,
       depending on whether she trusts the long term key or keys associated with
       them.
    1. If the prekey versions are different and Alice supports only one, then
       she can only send a message with the prekey she supports. If the long
       term key associated with this prekey is untrusted, she may decide not to
       send a message. If it is trusted, she may send a message.

In the above example, these are the possible situations when only two prekeys
are received. Of course, many more may be received.

To aid with this complexity, OTRv4 will give guidance on how to filter a list of
given prekeys to remove invalid prekeys or identify invalid situations. But the
decision on what to do with the remaining prekeys is up to the implementer.

Here is the guide.

To validate a prekey, use the following checks. If any of them fail, ignore the prekey:

    Check if the user profile is not expired
    Check if the OTR version of the prekey message matches one of the versions
    signed in the user profile
    Check if the user profile version is supported by the receiver

If one prekey is received:

    If the prekey is valid, decide whether to send a message using this prekey
    based on whether the long term key within the use profile is trusted or not.

If many prekeys are received:

    Remove all invalid prekeys.
    Remove all duplicate prekeys in the list.
    If multiple valid prekeys remain, check for invalid prekey situations:
        If multiple prekeys exist with the same instance tag, the same version,
        and the same long term keys in the user profile, then one of the prekeys
        is invalid. The safest thing to do is to remove all the prekeys
        associated with this situation.
    If one prekey remains:
        Decide whether to send a message using this prekey based on whether the
        long term key within the use profile is trusted or not.
    If multiple valid prekeys remain:
        If there are keys that are untrusted and trusted in the list of
        prekeys, decide whether to only use prekeys that contain trusted long
        term keys.
        If there are several instance tags in the list of prekeys, decide
        whether to send one message per instance tag or to send a message
        only to one instance tag.
            If there are multiple prekeys per instance tag, decide whether to
            send multiple messages to the same instance tag.

#### Decreased participation deniability for the initiator

OTRv4 will make it clear that non-interactive conversations have different,
lower participation deniability properties for the initiator than interactive
conversations. OTRv4 will also leave it up to the implementer to decide when it
is appropriate to use the non-interactive DAKE and how to convey this security
loss.

In addition, implementers of OTRv4 may wish to support only interactive
conversations or only non-interactive conversations. This is allowed.

#### Multiple DAKEs in the OTR state machine

Currently we have decided on one state machine that can receive multiple DAKEs.
The machine has the following states:
* Start
* Waiting for R Auth
* Waiting for I Auth
* Encrypted Message
* Finished

All of these states except the finished state may receive the second message of
a non-interactive DAKE.

#### The prekey server runs out of prekeys

When the server runs out of prekeys, OTRv4 expects client implementations to
wait until a prekey can be transmitted before continuing with a non-interactive
DAKE.

This is purposely different from what we expect from protocols like Signal. In
Signal, when a prekey server runs out of prekeys, a default prekey is used until
new prekeys are uploaded. With this method, the consequences for participation
deniability are currently undefined and thus risky.

By waiting for the server to send prekeys, OTRv4 will be subject to DoS attacks
when a server is compromised or the network is undermined to return a "no prekey
exists" response from the server. This is preferred over the possible compromise
of multiple non-interactive DAKEs due to the reuse of a prekey.
q