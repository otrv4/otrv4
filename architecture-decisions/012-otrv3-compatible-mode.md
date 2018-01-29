## ADR 11: "OTRv3 compatible" mode

### Context

ADR #010 defines the need for specifying alternative modes for the OTR protocol
version 4.

This document outlines the implications of having a "OTRv3 compatible" mode to the
spec as per revision 585ba0dfcecf6abc0d30ba0ff0524bce3795110a.

When thinking about the consequences, we had the following scenarios in mind:

#### Pidgin (a OTRv3-compatible plugin)

Alice wants to send a message to Bob.

1. Alice adds Bob as a contact

2. Alice verifies Bob's identity. She either:

  a. Use Bob's User Profile and verify Bob's fingerprint using a business card,
     a HTTPS website;

  b. Perform a interactive DAKE and use SMP.

2. Alice types a message and "sends it" to Bob.

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

TODO: OTR3 supports plaintext messages. Should this mode support it too? I think
so.

### Decision

(From ADR #010)

To be defined. This is pretty much the spec as per revision
585ba0dfcecf6abc0d30ba0ff0524bce3795110a.

### Consequences

To be defined
