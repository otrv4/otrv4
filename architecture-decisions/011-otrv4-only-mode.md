## ADR 11: "OTRv4 only" mode

### Context

ADR #010 defines the need for specifying alternative modes for the OTR protocol
version 4.

This document outlines the implications of having a "OTRv4 only" mode to the
spec as per revision 585ba0dfcecf6abc0d30ba0ff0524bce3795110a.

When thinking about the consequences, we had the following scenarios in mind:

#### Scenario A: QueMás (a OTR4-only WhatsApp clone)

Alice wants to send a message to Bob.

1. Alice adds Bob as a contact:
  * Immediately do a DAKE (interactive or non-interactive depending on the
    contact's availability to the network) and store the conversation keys on
    the device for later use.
  * No identity verification is necessary and the app uses a TOFU policy. Bob's
    User Profile can be used to present additional information about the
    alleged identity.

2. Alice types a message and "sends it" to Bob
  * Every message will always be encrypted.
  * Instance tags could be optional in this "one device per contact" model.
  * Fragmentation could be optional depending on the network.

3. Bob receives the message from Alice.

There is no plaintext messages in this scenario, since the only way to send
messages through this app's network is using the app.

#### Scenario B: Sparrow (a OTR4-only Pidgin clone)

Alice wants to send a message to Bob.

1. Alice adds Bob as a contact
2. Alice verifies Bob's identity. She either:
  * Uses Bob's User Profile and verifies Bob's fingerprint using a business
    card, a HTTPS website, etc.
  * Performs a interactive DAKE and uses SMP.

2. Alice types a message and "sends it" to Bob.
  * A DAKE is performed if the app is not already in an encrypted state.
  * Alice is warned about any problem to establish an encrypted channel and/or
    any problem with the identity verification for Bob.
  * The conversation keys do not need to be stored on the device for later use.
  * Instance tags are required because there may be multiple devices.
  * Fragmentation could be optional depending on the network, but this is
    unlikely due support to multiple networks.

3. Bob receives the message from Alice.

If the network allows Alice to receive messages from devices not on the same
mode, plaintext messages may arrive. Such messages should be handled by the app,
and not by the OTRv4 protocol. If the app allows Alice to send plaintext
messages, they should be directly delivered to Bob by the app and not by the
OTRv4 protocol.

### Decision

(From ADR #010)

> OTRv4 only: a always encrypted mode. This mode will not know how to handle
> any kind of plain text, including query messages and whitespace tags.

> Furthermore, 'OTRv4 only' mode will only support version 4 of OTR. The User
> Profile, therefore will only allow the 1-byte version string "4". It will also
> not allow the Transitional Signature parameter on the same profile.

Although this mode requires encryption, TLV type 1 (Disconnected) are still
necessary to provide a mechanism to session expiration.

By requiring encryption, this mode may encourage long-lived sessions
(conversations). The section "Session expiration" of OTRv4 protocol spec
outlines how to mitigate the risks of long-lived sessions.

Even though there is no need to prefix OTR messages with "?OTR:", since the
protocol only handles OTR messages, this mode does not remove this encodiing
for convenience.

### Consequences

As a consequence of requiring encryption, this protocol may be stuck if, for
example, a DAKE message is lost. This mode does not define any strategy, like a
timeout, for dealing with such cases.

There may be loss of deniability if a interactive DAKE is followed by a
non-interactive. This mode does not address this neither recommend any way to
warn the user when it happen.

The spec for this mode would be the same spec as per (current revision) except:

- "High Level Overview": remove "Requests OTR conversation" from diagram and
  change diagram's description.
- "Encoded Messages": there may not have a need to use a particular encoding to
  distinguish between plaintext messages and OTR messages, since every message
  in this mode is an OTRv4 message. That is, remove the "?OTR:" prefix.
- "User Profile Data Type": if there is no query message, and every
  conversation is strictly OTR4, does the field "Versions" have any use now?
- "Creating a User Profile": according to the current spec, "Versions" MUST be
  "4" only. The field "Public Shared Prekey" could be optional in the mode
  "interactive-only".
- "Establishing Versions". This is not true anymore: "A compliant OTRv4
  implementation is required to support version 3 of OTR, but not versions
  1 and 2.". In this mode, for example, is not required.
- "Create a User Profile Signature": Ignore first paragraph.
- "Online Conversation Initialization": The introduction is wrong: there is
  no query message or whitespace tag anymore. Everything in this section
  that mentions them (diagrams, for example) is also wrong.
- "Protocol states": the START protocol does not allow messages to be sent,
  since plaintext messages are not part of this mode. Also, the description of
  state FINISHED becomes weird because sending plaintext should be prevented
  by the protocol regardless of the state.

Ignore completely the sections:

- "User requests to start an OTR conversation"
- "Receiving plaintext without the whitespace tag", and
  "Receiving plaintext with the whitespace tag": should probably be replaced by
  "Receiving plaintext: reject".
- "Receiving a Query Message"

TODO: State the security properties of this mode, or the implications to the
security in this model?