# OTR version 4: OTRv3 Compatible Mode

[ADR#010](https://github.com/otrv4/otrv4/tree/master/architecture-decisions)
defines the need for specifying alternative modes for the OTR protocol
version 4.

This document describes the version 4 of the Off-the-Record Messaging protocol,
in a operation that aims to provide a transition path from the previous version
of the protocol, namely OTRv3, to the current version.

The OTRv3-Compatible mode is a mode with backwards compatibility with OTRv3.
It knows how to handle plaintext messages, including query messages and
whitespace tags. It is considered the 'default' mode.

## Mode description

An implementation of the OTRv4 protocol in an OTRv3-compatible mode must be
compliant with the full protocol specification:
[OTRv4 protocol](../otrv4.md#table-of-contents). That is, it must comply with
every section on it.

### Scenarios and applications

This mode might work on this kind of application and scenario:

#### Pidgin (a OTRv3-Compatible Pidgin-like-plugin)

Alice wants to send a message to Bob.

1. Alice adds Bob as a contact.
2. Alice verifies Bob's identity. She either:
   * Uses Bob's User Profile and verifies Bob's fingerprint using a business
     card, a HTTPS website, etc.
   * Performs an interactive DAKE with Bob and uses SMP.
3. Alice types messages, encrypts them and "sends them" to Bob.
   * A DAKE is performed if the application is not already in an encrypted state.
   * She is warned about any problem while establishing an encrypted channel
     and/or any problem with the identity verification of Bob.
   * Instance tags are required because the same client might be logged into
     Alice's account from multiple locations
   * Fragmentation will be optional as it depends on the network. It is
     unlikely due support of multiple networks.
4. Bob receives the encrypted messages from Alice.

## Considerations

Unlike the other two modes, plaintext messages are allowed in conversations with
OTRv3-Compatible mode. The use of policies, similar to OTRv3, can be used to
safely handle the transition from an "encrypted" to a "plaintext" state.

Notice that in this mode, the security properties stated in the
[security properties](../otrv4.md#security-properties) section only hold for
when a conversation with OTRv4 is started. They do not hold for the previous
versions of the OTR protocol, meaning that if a user that supports version 3 and
4 starts a conversation with someone that only supports version 3, a
conversation with OTRv3 will start, and its security properties will not be the
ones stated in those paragraphs. The security properties will be those defined
by OTRv3.

The network model will also change when starting a conversation with OTRv3. If a
user that supports version 3 and 4 starts a conversation with someone that
only supports version 3, a conversation with OTRv3 will start, and its network
model will only provide in-order delivery of messages.