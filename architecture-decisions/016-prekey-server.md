## ADR 016: Prekey server

### Context

In order to send an offline message, the Responder needs to obtain
cryptographic keys from the Initiator so they can engage in a
non-interactive DAKE. These cryptographic keys are distributed as
prekey messages, who is made public in a untrusted pre-key server.

A participant is identified by some identity in the underlying network
(be it alice@xmpp.org for the XMPP network, or +99 1234-5678 for the
SMS network). We assume this is everything each participant is required
to know about who they want to send a message to.

To publish prekey messages, a participant deniably authenticates itself to
the server through a interactive DAKE, and sends prekeys to be stored and
published by the server. The server will associate the prekeys received to
the identity used by the sender to identify itself to the server (TODO: does
the user is required to authenticate its identity to the server? It should not
matter, if the server is not trusted - I guess).

To obtain prekey messages, a participant asks the server for prekey messages
from a particular identity, and the server delivers one prekey message for
every not-expired profile it knows about from that particular identity.

This document describes the pre-key server as a component in the OTRv4 protocol.

Having in mind a client-server architecture, a prekey server instance MUST
offer the following services to its users:

- user profile retrieval
- user profile publication
- prekey message retrieval
- prekey message publication

TODO: Should this be a requirement?
It is assumed that the server is able to receive messages from a
authenticated identity. By performing a DAKE with the server, a
authenticated identity binds itself to its long-term public-key,
and then publishes profiles and prekey messages.

(TODO: evaluate consequences of each service to the protocol)

### Constraints

- user profiles can not share the same pre-key. They are part of a user profile.

### Notation

We use the following notaiton to represent a prekey message stored on a server:

      (pre-key-msg, profile, long-term-key, identity)

We use this notation to make it easier to reason when comparing different
prekey messages, even though the profile is inside the prekey message, and the
long-term public key is inside the proifle.

### How to serve a prekey message retrieval

The server MUST deliver one prekey message when all of its stored prekey messages
for a particular identity have the same long-term key and profile.

#### SCENARIO 1

The server MUST deliver only ONE prekey message when multiple
are available for the same identity.

    GIVEN the server has the following prekey messages stored:

      (pre-key-msg1, profile1, long-term1, identity1)
      (pre-key-msg2, profile1, long-term1, identity1)

    WHEN I ask a prekey for identity1
    THEN the server should send me any ONE of the following prekey messages:

      pre-key-msg1
      pre-key-msg2


#### SCENARIO 2

The server MUST NOT deliver prekey messages for any other identity but the
requested, even if they share the same the same long-term key or profile.

    GIVEN the server has the following prekey messages stored:

      (pre-key-msg1, profile1, long-term1, identity1)
      (pre-key-msg2, profile1, long-term1, identity1)
      (pre-key-msg3, profile1, long-term1, identity2)
      (pre-key-msg4, profile1, long-term1, identity2)

    WHEN I ask a prekey for identity1
    THEN the server should send me any ONE of the following prekey messages:

      pre-key-msg1
      pre-key-msg2


We assume clients are allowed to export/import both the user profiles and their
associated long-term keypairs. In this case multiple identities (in different
clients or not) can share the same user profile AND long-term keypair.

#### SCENARIO 3

The server MUST deliver additional prekey messages when multiple
(profile, long-term key) are found for the same identity.

    GIVEN the server has the following prekey messages stored:

      (pre-key-msg1, profile1, long-term1, identity1)
      (pre-key-msg2, profile1, long-term1, identity1)
      (pre-key-msg3, profile1, long-term1, identity2)
      (pre-key-msg4, profile2, long-term1, identity1)
      (pre-key-msg5, profile2, long-term1, identity1)

    WHEN I ask a prekey for identity1
    THEN the server should send me any ONE of the following prekey messages:

      pre-key-msg1
      pre-key-msg2

    AND the server should send me any ONE of the following prekey messages:

      pre-key-msg4
      pre-key-msg5

Users are allowed to import/export their long-term key but are not expected
to manage (or even know about) profiles. In this case, if Alice wants to
preserve the same long-term key (and fingerprint) among multiple clients
she will always have multiple profiles for the same long-term key that can be
simultaneously active (not-expired). This is due the fact that profiles are
per-device and should not allowed to be exported/imported by clients.

Clients should group all received prekey messages, and choose from each
group only the one with the latest expiry time. This must be done to avoid
sending multiple offline messages to the same device. If there's still multiple
prekey messages after filtering out duplicate instance tags, the client needs to
decide which client the offline message should be sent to, or even send to all
of them. Clients may need to inform the user before sending the offline message
to multiple devices, or ask the user about which from the many possible actions
should be taken.


#### SCENARIO 4

    GIVEN the server has the following prekey messages stored:

      (pre-key-msg1, profile1, long-term1, identity1)
      (pre-key-msg2, profile1, long-term1, identity1)
      (pre-key-msg3, profile2, long-term2, identity1)
      (pre-key-msg4, profile2, long-term2, identity1)

    WHEN I ask a prekey for identity1
    THEN the server should send me any ONE of the following prekey messages:

      pre-key-msg1
      pre-key-msg2

    AND the server should send me any ONE of the following prekey messages:

      pre-key-msg3
      pre-key-msg4

Users are expected to have multiple long-term keys and profiles associated to
the same identity. For example, they may use multiple clients and/or devices
that do not share the same long-term key.

From the clients' perspective, this is the same scenario as the previous one,
and clients are required to behave similarly in regard to grouping received
perkey messages by instance tag, filtering out duplicates, and chosing which
devices to send the offline messages to.

#### Problems with receiving multiple prekey messages for a particular identity

In Scenarios 3 and 4, the RESPONDER needs to decide to either keep multiple
conversations established with the INITIATOR (one for each received pre-key
message) or always discard the conversation after the offline message is
sent (which drains prekeys from every group.

Another problem with the step is that once an attacker impersonates the
identity to the server (someone steals your XMPP password), they can simply
publish a new user profile (with a new long-term key, with new prekey
messages) and guarantee they will receive encrypted copies of every "first"
message the RESPONDER sends. Does it mean non-interactive is more fragile
in regard to this attack than OTRv3? Can we add recommendations to the spec
to make sure client implementations are extra careful with how they handle
fingerprints in the non-interactive case?


### Decision

A prekey server instance MUST offer the following operations:

- user profile retrieval
- user profile publication
- prekey message retrieval
- prekey message publication

### Consequences

TODO
