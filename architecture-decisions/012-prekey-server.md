## ADR 012: Prekey server

### Context

In order to send an offline message, the Responder needs to obtain cryptographic
keys from the Initiator so they can engage in a non-interactive DAKE. These
cryptographic keys are distributed as prekey ensembles, which are made public in
a untrusted Prekey Server.

A participant is identified by some identity in the underlying network (like
alice@xmpp.org for the XMPP network, or +99 1234-5678 for the SMS network).
We assume this is everything each participant is required to know about who they
want to send a message to.

### Decision

Having in mind a client-server architecture, a prekey server instance MUST offer
the following services to its users:

- Receive user profiles, prekey profiles and a set of prekey messages, and store
  them. Inform that this operation have failed or has been successful.
- Deliver prekey ensembles previously stored.
- Inform the publisher about how many prekey messages are stored for them.
- Inform the retriever when there are no prekey ensembles (or any of its values)
  from an specific party.

To publish user profiles, prekey profiles and a set of prekey messages, a
participant deniably authenticates itself to the Prekey Server through a
interactive DAKE, and sends those values to be stored and published by the
Prekey Server. The Prekey Server will associate the prekeys received to the
identity used by the sender to identify itself to the Prekey Server.

To obtain prekey ensembles, a participant asks the Prekey Server for prekey
ensembles from a particular identity, and the server delivers one prekey ensemble
for each instance tag and long-term public key it knows about from that
particular identity.

### Notation

We use the following notation to represent a the three values stored on a
Prekey Server for an identity:

```
  (Identity || User Profile)
```

```
  (Identity || Prekey Profile)
```

```
  (Identity || prekey message)
```

### How to publish user profiles, prekey profiles and prekey messages

1. The Initiator starts a interactive DAKE with the Prekey Server.
2. The Initiator sends user profiles, prekey profiles and a set prekey messages
   to be published by the server.
3. The server stores all valid (non-expired) user profiles and prekey profiles,
   and all prekey messages, and associates them with the publisher's identity.

### Prekey message retrieval

#### SCENARIO 1

The server must deliver only one prekey ensemble when multiple prekey messages
are available for the same identity and the same instance tag.

    Given the server has the following values stored:

      (Identity 0x01 || User Profile (instance tag 0x01))
      (Identity 0x01 || Prekey Profile (instance tag 0x01))
      (Identity 0x01 || Prekey message 1 (instance tag 0x01))
      (Identity 0x01 || Prekey message 2 (instance tag 0x01))

    When a participant asks the Prekey Server for Indentity 0x01,
    Then the Prekey server should send any one of the following prekey
    messages, along with the User Profile and Prekey Profile:

      (Identity 0x01 || User Profile (instance tag 0x01) || Prekey Profile
      (instance tag 0x01) || Prekey message 1 (instance tag 0x01))

#### SCENARIO 2

The server must deliver additional prekey ensembles when multiple instance tags
are found for the same identity.

    Given the server has the following prekey messages stored:

      (Identity 0x01 || User Profile (instance tag 0x01))
      (Identity 0x01 || User Profile (instance tag 0x02))
      (Identity 0x01 || Prekey Profile (instance tag 0x01))
      (Identity 0x01 || Prekey Profile (instance tag 0x02))
      (Identity 0x01 || Prekey message 1 (instance tag 0x01))
      (Identity 0x01 || Prekey message 2 (instance tag 0x02))

    When a participant asks a Prekey Server for Identity 0x01,
    Then the Prekey Server should send two prekey ensembles:

      (Identity 0x01 || User Profile (instance tag 0x01) || Prekey Profile
      (instance tag 0x01) || Prekey message 1 (instance tag 0x01))

      (Identity 0x01 || User Profile (instance tag 0x02) || Prekey Profile
      (instance tag 0x02) || Prekey message 1 (instance tag 0x02))

#### Receiving prekey ensembles

Clients should not trust that the Prekey Server will always return valid Prekey
ensembles, and must validate them by themselves. If a client can find any usable
prekey ensembles (or any of its values) from the Prekey Server's response, it
may perform additional requests.

#### Receiving multiple prekey messages

Clients should group all received prekey ensembles by instance tag, and, from
these groups by long-term public key. They should choose from each group only
the one with the latest expiry time. This must be done to avoid sending multiple
offline messages to the same instance tag.

If there's still multiple prekey ensembles after filtering out duplicate
instance tags, the client needs to decide which client the offline message
should be sent to, or even send to all of them. Clients may need to inform
the user before sending the offline encrypted messages to multiple instance
tags, or ask the user about which from the many possible actions should be
taken.

If the client decides to send offline encrypted messages to multiple instances
tags, it also needs to decide to either keep multiple conversations established
with the publisher (one for each received Prekey Ensemble) or always terminate
the conversation after the offline message is sent.

Notice that an attacker that impersonates the publisher's identity to the
Prekey Server (someone can, for example, steal the XMPP password) can publish a
new user profile (with a new long-term public key), prekey profile and prekey
messages, and guarantee they will receive copies of every encrypted offline
message sent by the retriever. Notice, although, that an attacker can do this
until the profiles expire.

### Consequences

The Prekey Server can be subject to DoS attacks. As it is untrusted, it can,
furthermore, send expired prekey ensembles, or send incomplete values or not
send anything at all to a retriever. Clients are expected to keep this in mind
while working with the Prekey Server.
