## ADR 012: Prekey server

### Context

In order to send an offline message, the Responder needs to obtain cryptographic
keys from the Initiator so they can engage in a non-interactive DAKE. These
cryptographic keys are distributed as prekey messages, which are made public in
a untrusted pre-key server.

A participant is identified by some identity in the underlying network (be it
alice@xmpp.org for the XMPP network, or +99 1234-5678 for the SMS network).
We assume this is everything each participant is required to know about who they
want to send a message to.

### Decision

Having in mind a client-server architecture, a prekey server instance MUST offer
the following services to its users:

- prekey message retrieval
- prekey message publication

To publish prekey messages, a participant deniably authenticates itself to the
server through a interactive DAKE, and sends prekeys to be stored and published
by the server. The server will associate the prekeys received to the identity
used by the sender to identify itself to the server.

To obtain prekey messages, a participant asks the server for prekey messages
from a particular identity, and the server delivers one prekey message for each
instance tag it knows about from that particular identity.

### Notation

We use the following notation to represent a prekey message stored on a server:

      (pre-key-msg, instance-tag, identity)

### How to serve a prekey message publication

1. The Initiator starts a interactive DAKE with the server.
2. The Initiator sends multiple prekey messages to be published by the server.
3. The server stores all valid (non-expired) prekey messages and associates them
   with the publisher's identity.

### Prekey message retrieval

#### SCENARIO 1

The server MUST deliver only ONE prekey message when multiple are available for
the same identity.

    GIVEN the server has the following prekey messages stored:

      (pre-key-msg1, instance-tag1, identity1)
      (pre-key-msg2, instance-tag1, identity1)

    WHEN I ask a prekey for identity1
    THEN the server should send me any ONE of the following prekey messages:

      pre-key-msg1
      pre-key-msg2


#### SCENARIO 2

The server MUST deliver additional prekey messages when multiple instance tags
are found for the same identity.

    GIVEN the server has the following prekey messages stored:

      (pre-key-msg1, instance-tag1, identity1)
      (pre-key-msg2, instance-tag1, identity1)
      (pre-key-msg3, instance-tag2, identity1)
      (pre-key-msg4, instance-tag2, identity1)

    WHEN I ask a prekey for identity1
    THEN the server should send me any ONE of the following prekey messages:

      pre-key-msg1
      pre-key-msg2

    AND the server should send me any ONE of the following prekey messages:

      pre-key-msg3
      pre-key-msg4

#### Receiving prekey messages

Clients should not trust the server will always return valid prekey messages,
and must validate them by themselves. If a client can find any usable prekey
messages from the server's response, it may perform additional requests.

#### Receiving multiple prekey messages

Clients should group all received prekey messages by instance tag, and choose
from each group only the one with the latest expiry time. This must be done to
avoid sending multiple offline messages to the same instance tag.

If there's still multiple prekey messages after filtering out duplicate
instance tags, the client needs to decide which client the offline message
should be sent to, or even send to all of them. Clients may need to inform
the user before sending the offline message to multiple instance tags, or ask
the user about which from the many possible actions should be taken.

If the client decides to send the same offline message to multiple instances
tags it also needs to decide to either keep multiple conversations established
with the INITIATOR (one for each received pre-key message) or always terminate
the conversation after the offline message is sent (which drains prekeys from
every group.

Another problem with the step is that once an attacker impersonates the identity
to the server (someone steals your XMPP password), they can simply publish a new
User Profile (with a new long-term key, with new prekey messages) and guarantee
they will receive encrypted copies of every "first" message the Responder sends.

### Consequences

The server may implement measures to prevent DoS attacks, for example, limit the
frequency of requests and/or the number of prekey messages accepted.

There is no protection when the server sends expired or already used prekey
messages or when it does not send prekey messages for every instance tag it
knows about.
