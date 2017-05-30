## ADR 8: Non-interactive DAKE

### Context

OTRv3 only provides an interactive AKE and adding support to non-interactive
AKE is a usability feature.

A non-interactive DAKE starts by the receiver (R) requesting a prekey for the
initiator (I) from a untrusted server. I's long-term public key must be known by R.

The receiver then generates their ephemeral keys and derives a shared secret
(and initial root and chain keys) which can be used to send an encrypted data
message together with his final message on the non-interactive DAKE.

The receiver can continue sending data messages even without receiving a reply
from the initiator, and forward secrecy is preserved by ratcheting the chain
key.

#### Publishing and retrieving prekeys to a prekey server

Implementers are expected to create their own policy dictating how often their
clients upload prekeys to the prekey server. This should be often enough to
minimize instances of prekeys running out on the server. Ideally, participation
deniability for the user is preserved in this process.

Interactions between OTRv4 clients and a prekey server are defined in a separate
specification.

#### Multiple clients

OTR uses instance tags to distinguish between different clients. This can be
solved by associating recipient long-term public keys with instance tags and
preventing multiple client to share the same long-term public key. A client
must distinguish between when a new long-term public key represents
a new device or the retirement of the previous key.

The client may receive multiple prekeys from a prekey server. The client must
decide how to reply to them. Each prekey may have a different client associated
with it and a different version.

#### Multiple OTR protocol versions

Prekeys contain:

```
Protocol version (SHORT)
Message type (BYTE)
Sender instance tag (INT)
User Profile (USER-PROF)
I (POINT) ECDH public key
B (MPI) DH public key
  Note: Although this is capital, this is not a point.
```

Each client is expected to upload one prekey per version of OTR after version 4
they support.

#### Handling multiple DAKEs for multiple settings

Currently we have decided on one state machine that accounts for multiple DAKEs.
The machine has the following states:
* Start
* Waiting for R Auth
* Waiting for I Auth
* Encrypted Message
* Finished

All of these states except the finished state may react to receiving the second
message of a non-interactive DAKE by validating it, destroying the current key
material and creating a new shared secret with the new message.

When Alice and Bob send each other the second message of the non-interactive
DAKE at the same time, both will need to decide which set of keys will be used
for their shared secret. Alice and Bob will use the same tie-breaking method
described in the interactive DAKE to choose.

#### When the server runs out of prekeys

When the server runs out of prekeys, OTRv4 expects client implementations to
wait until a prekey is transmitted before continuing with a non-interactive
DAKE.

This is purposely different from what we expect from protocols like the Signal
Protocol. In Signal, when a prekey server runs out of prekeys, a default prekey
is used until new prekeys are uploaded. With this method, the consequences for
participation deniability are currently undefined, and we think this is risky.

By waiting for the server to send prekeys, OTRv4 will be subject to DoS
attacks when a server is compromised or the network is undermined to return a
"no prekey exists" response from the server. This is preferred over the possible
compromise of multiple non-interactive DAKEs due to the reuse of a prekey.

#### Long-lived secret ephemeral key material

In OTR4, the window of key compromise is equivalent to how long it takes for the
double ratchet to refresh the ephemeral key material (2 ratchets, including the
first compromised ratchet) and how long a prekey remains unused before the user
profile inside becomes expired. In non-interactive conversations, participants
may not receive messages or reply to them for days, weeks, or months at a time.
As a result, the window of compromise for these kind of conversations can be
very long if no limitations are set. We would like to reduce this window.

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
to send the correct time difference. If messages from the server containing the
time difference are manipulated, the timestamp cannot be relied upon. In
addition, compromised participants cannot send a timestamp themselves since that
information can be manipulated by the active attacker who has the private
key material.

Another strategy is to limit the number of messages sent within a ratchet. In
one solution, each sender must always create a new ratchet with a new prekey
when they want to send an offline message. Additional messages sent by the same
initiator are encrypted with using shared secret derived from the prekey. This would
minimize the impact of compromise to all of the sender's data messages in a
ratchet. Replies by the uncompromised party are no longer compromised. In
another solution, each non-interactive message must be created with a new
prekey. Thus each ratchet contains only one message, and ephemeral key material
can be deleted immediately after a non-interactive message is sent or received.
This maximally limits the effect of key compromise for both parties by revealing
only one message to the attacker at a time and forcing prekeys to be used
often--thus requiring frequent removal from storage and a smaller window of
compromise for prekeys.

The disadvantages of these two solutions are that they require clients to set up
servers with a large number of prekeys per participant and processes that
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
MAC keys for this message cannot be revealed within that time.

Thus, OTR4 expects implementers to immediately send a specific non-interactive
MAC key reveal message once they receive, validate, and successfully decrypt a
data message. This message does not contain encrypted plaintext provided by the
user. Its purpose is to immediately reveal MAC keys to provide data message
deniability for the other party, much like a "heartbeat" message in OTRv3.

#### Decreased participation deniability for the initiator

OTRv4 will make it clear that non-interactive conversations have different,
lower participation deniability properties for the initiator than interactive
conversations. In addition, OTRv4 will leave it up to the implementer to know
how to convey this information to the user and to know when it is appropriate to
use non-interactive messages.
