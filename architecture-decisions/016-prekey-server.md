## ADR 016: Prekey server

### Context

In order to send an offline message, the Responder needs to obtain
cryptographic keys from the Initiator. These cryptographic keys are
distributed through prekey messages, who are cryptographically bound
to a prekey and made public in a untrusted pre-key server.

A participant is identified by some identity in the underlying network
(be it alice@xmpp.org for the XMPP network, or +99 1234-5678 for the
SMS network). We assume this is everything each participant is required
to know about who they want to send a message to.

This document describes the pre-key server as a component in the OTRv4 protocol.

Having in mind a client-server architecture, a prekey server instance MUST
offer the following services to its users:

- user profile retrieval
- user profile publication
- prekey message retrieval
- prekey message publication

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
concurrently active (not-expired). This is due the fact that profiles are
per-device and should not allowed to be exported/imported by clients.

Clients needs to be aware of how to handle this, and may need to inform the user
before sending the offline message to multiple devices.

Clients could use the instance tag on the received prekey messages to determine
if the received prekey messages are from the same device. This could happen
if the INITIATOR's client decided to publish a new profile (and prekey messages)
in preparation to the expiry of the currently published profile.

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

#### Problems with receiving multiple prekey messages for a particular identity

In Scenarios 3 and 4, the RESPONDER needs to decide to either keep multiple
conversations established with the INITIATOR (one for each received pre-key
message) or always use one prekey per message in this case (which drains
prekeys from every group.

Another problem with the step is that once an attacker impersonates the
identity to the server (someone steals your XMPP password), they can simply
publish a new user profile (with a new long-term key, with new prekey
messages) and guarantee they will receive encrypted copies of every "first"
message the RESPONDER sends. Does it mean non-interactive is more fragile
in regard to this attack than OTRv3? Can we add recommendations to the spec
to make sure client implementations are extra careful with how they handle
fingerprints in the non-interactive case?

#### Things to consider

- All the previous scenarios but in the context of having prekey messages
  with different instance tags in each group of candidates to delivery.

   * What if there are prekey messages with the same instance tag on different groups?
   * What if there are prekey messages with different instance tags on the same group?

  In scenarios 3 and 4, if the pre-key messages received by the RESPONDER have
  the same instance tag, they may need to decide which of the prekeys to use.
  Otherwise multiple OTR conversations will be established with the same
  INITIATOR. It may be problematic to both.


### Decision

A prekey server instance MUST offer the following operations:

- user profile retrieval
- user profile publication
- prekey message retrieval
- prekey message publication

### Consequences

TODO
