## ADR 11: "OTRv4 only" mode

### Context

ADR #010 defines the need for specifying alternative modes for the OTR protocol
version 4.

This document outlines the implications of having a "OTRv4 only" mode to the
spec as per revision 585ba0dfcecf6abc0d30ba0ff0524bce3795110a.

When thinking about the consequences, we had the following scenarios in mind:

#### Scenario A: QueMás (a OTR4-only WhatsApp clone)

Alice wants to send a message to Bob.

1. Alice adds Bob as a contact
  a. Immediately do the DAKE (interactive or non-interactive depending on the
     contact's availability to the network) and store the conversation keys on
     the device for later use.
  b. No identity verification is necessary and the app uses a TOFU policy. Bob's
     User Profile can be used to present additional information about the
     alleged identity.
2. Alice types a message and "send it" to Bob.
  a. Every message will always be encrypted.
  b. Instance tags could be optional in this "one device per contact" model.
  c. Fragmentation could be optional depending on the network.
3. Bob receives the message from Alice.

There is no plaintext messages in this scenario, since the only way to send
messages through this app's network is using the app.

#### Scenario B: Sparrow (a OTR4-only Pidgin clone)

Alice wants to send a message to Bob.

1. Alice adds Bob as a contact
2. Alice verifies Bob's identity. She either:
  a. Use Bob's User Profile and verify Bob's fingerprint using a businecc card,
     a HTTPS website;
  b. Perform a interactive DAKE and use SMP.
2. Alice types a message and "send it" to Bob.
  a. A DAKE is performed if the app is not already in an encrypted state.
  b. Alice is warned about any problem to establish the encrypted channel and/or
     any problem with the identity verification for Bob.
  c. The conversation keys do not need to be stored on the device for later use.
  d. Instance tags are required because there may be multiple devices.
  e. Fragmentation could be optional depending on the network, but this is
     unlikely due support to multiple networks.
3. Bob receives the message from Alice.

If the network allows Alice to receive messages from devices not on the same
mode, plaintext messages may arrive. Such messages should be handled by the app,
and not by the OTRv4 protocol. If the app allows Alice to send plaintext
messages, they should be directly delivered to Bob by the app and not by the
OTRv4 protocol.

### Temporary place for discussion before decisions are made

1. Do we need query messages or whitespace tags? Do we need "disconnected TLVs"?
2. Do we want to specify a timeout for the DAKE? Encryption is mandatory so we need a reasonable expectation of success in establishing the encripted conversation.
3. Do we want non-interactive DAKE to be upgraded to interactive (in order to provide stronger security properties)?
  What should the Initiator do when it receives an offline message (a non-interactive DAKE has completed)? Continue on the same DAKE (there is already no deniability for they in regard to an online judge) or start an interactive DAKE ASAP to replace the current one?
4. How long should the otr4 conversations be active (encryption is required)?
  a. There could be long-lived conversations in a WhatsApp-like scenario (with optinally recommending an expiration time).
    i. This is similar to the problem of late messages in the out-of-order network. How long should we keep keys in memory/disk waiting for late messages to be delivered?
  b. There could be short-lived conversations in a Coy-like scenario (a conversation has the lifetime of a client).
5. Should we keep the message format (which is inspired on OTR3)?
6. Should we encrypt the headers?
7. Should we support fragmentation?
8. Should we support instance tags?

### Decision

(From ADR #010)

> OTRv4 only: a always encrypted mode. This mode will not know how to handle
> any kind of plain text, including query messages and whitespace tags.

> Furthermore, 'OTRv4 only' mode will only support version 4 of OTR. The User
> Profile, therefore will only allow the 1-byte version string "4". It will also
> not allow the Transition Signature parameter on the same profile.


### Consequences

To be defined
