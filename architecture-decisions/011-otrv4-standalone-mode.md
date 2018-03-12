## ADR 11: "OTRv4 Standalone" mode

### Context

ADR #010 defines the need for specifying alternative modes for the OTR protocol
version 4.

One of this modes is the 'OTRv4-standalone' mode: an always encrypted mode.
This mode will not know how to handle any kind of plaintext message, including
query messages and whitespace tags. It will support interactive and
non-interactive conversations.

This mode might work on this kind of applications and scenarios:

#### Scenario A: an OTRv4-standalone WhatsApp-like application

Alice wants to send a message to Bob.

1. Alice adds Bob as a contact:
  * A DAKE (interactive or non-interactive depending on the contact's
    availability) is immediately done. The conversation keys are stored on
    the device for later use.
  * No identity verification is necessary and the app uses a Trust on first use
    (TOFU) policy. Bob's User Profile can be used to verify the information
    about the alleged identity.
2. Alice types messages, encrypts them and "sends them" to Bob.
  * Every message will always be encrypted.
  * Instance tags could be optional in this "one device per contact" model.
  * Fragmentation will be optional as it depends on the network.
3. Bob receives the encrypted messages from Alice.

There is no plaintext messages in this scenario, since the only way to send
messages through this app's network is using the app.

#### Scenario B: an OTRv4-standalone Pidgin-like application

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
mode, plaintext messages may arrive. Such messages should be handled by the
application, and not by the OTRv4 protocol in this mode. If the application
allows Alice to send plaintext messages, they should be directly delivered to
Bob by the application and not by the OTRv4 protocol in this mode.

### Decision

This mode is defined as an "always encrypted mode". This means that it will
not know how to handle any kind of plaintext messages, including query messages
and whitespace tags.

A 'OTRv4 standalone' mode will only support version 4 of OTR. The User
Profile, therefore will only allow the 1-byte version string "4". It will also
not allow the Transitional Signature parameter on the same profile.

By always requiring encryption, this mode may encourage long-lived sessions.
The section "Session expiration" of OTRv4 protocol specification outlines how to
mitigate the risks of long-lived sessions. For this reason, TLVs type 1
(Disconnected) are necessary.

Even though there is no need to prefix OTR messages with "?OTR:", since the
protocol only handles OTR messages, this mode does not modify this encoding
for convenience.

### Consequences

As a consequence of always requiring encryption, this protocol could be stuck if,
for example, a DAKE message is lost and never delivered. This mode does not
define any strategy, like a timeout, for dealing with such cases; but
implementers are recommended to do so.

There may be loss of deniability if an interactive DAKE is followed by a
non-interactive one. Implementers are recommended to warn the users about this
when it happens.

This mode is compliant with the security properties described in the
[security properties](../otrv4.md#security-properties) section.