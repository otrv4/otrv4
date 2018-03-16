# OTR version 4: Standalone Mode

[ADR 10](https://github.com/otrv4/otrv4/tree/master/architecture-decisions/010-modes.md)
defines the need for specifying alternative modes for the OTR protocol
version 4.

This document describes the version 4 of the Off-the-Record Messaging protocol,
in an operation mode that aims to provide an always encrypted mode with higher
security properties than OTRv3. This mode will be referred as the "standalone
mode".

The 'OTRv4-Standalone' mode is an always encrypted mode. It does not know how to
handle any kind of plaintext messages, including query messages and whitespace
tags. It supports both interactive and non-interactive conversations. It is
not backwards compatible with OTRv3.

## Mode description

An implementation of the OTRv4 protocol in a OTRv4-Standalone mode must be
compliant with the overall protocol specification
[OTRv4 protocol](../otrv4.md#table-of-contents), with the following exceptions
and the following changes.

Ignore these sections:

- "User requests to start an OTR conversation", including "Query Messages" and
  "Whitespace Tags".
- "Requesting conversation with older OTR versions".
- "Receiving plaintext without the whitespace tag".
- "Receiving plaintext with the whitespace tag".
- "Receiving a Query Message".
- "OTRv3 Specific Encoded Messages".
- "OTRv3 Protocol State Machine".

The specification for this mode, as compared with the overall version, will
differ in these sections:

- "High Level Overview": there is not a "Requests OTR conversation" step.
- "Conversation started by an Interactive DAKE": the conversation begins when
  a participant sends an identity message. In this mode, there is no
  advertisement of which version a participant supports as both parties
  only support OTRv4.
- "Creating a User Profile": the `Versions` field must only allow the 1-byte
  version string "4".
- "Creating a User Profile": the `Transitional Signature` field is not allowed
  in this mode: there is no DSA signature generation or verification. Therefore,
  when validating a user profile, the DSA signature must not be verified.
- "Establishing Versions": ignore the paragraph: "A compliant OTRv4
  implementation is required to support version 3 of OTR, but not versions
  1 and 2". This mode only allows version 4 of the protocol.
- "Online Conversation Initialization": ignore everything that refers to query
  messages and whitespace tags. Always check that the compatible version in the
  participant's user profile includes "4".
- "Offline Conversation Initialization": always check that the compatible
  version in the participant's user profile includes "4".
- "Fragmentation": only OTRv4 fragmentation is allowed. Ignore this paragraph:
  "For fragmentation in OTRv3, refer to the "Fragmentation" section on OTRv3
  specification".
- "Protocol states": the `START` and `FINISHED` states of the protocol state
  machine should not allow any plaintext message to be sent, since plaintext
  messages are not allowed in this mode.

Online OTRv4 conversations in this mode are initialized by sending an Identity
Message, as defined in the
[Starting a conversation interactively](../otrv4.md#starting-a-conversation-interactively)
section.

### Interactive DAKE Overview in OTRv4-Standalone Mode

```
Alice                                           Bob
---------------------------------------------------
       Identity message -------->
       <------------------------------------ Auth-R
       Auth-I --------------------------------->
```

Alice will be initiating the DAKE with Bob.

**Alice:**

1. Generates an Identity message, as defined in
   [Identity message](../otrv4.md#identity-message) section.
2. Sets `Y` and `y` as `our_ecdh`: the ephemeral ECDH keys.
3. Sets `B` as  and `b` as `our_dh`: the ephemeral 3072-bit DH keys.
4. Sends Bob the Identity message.

**Bob:**

1. Receives an Identity message from Alice:
    * Verifies the Identity message as defined in the
      [Identity message](#identity-message) section. If the verification fails
      (for example, if Alice's public keys -`Y` or `B`- are not valid), rejects
      the message and does not send anything further.
    * Checks that the version in Alice's user profile includes "4". If it is not,
      Bob does not send any further messages.
    * Sets `Y` as `their_ecdh`.
    * Sets `B` as `their_dh`.
2. Generates an Auth-R message, as defined in
   [Auth-R message](../otrv4.md#auth-r-message) section.
3. Sets `X` and `x` as `our_ecdh`: the ephemeral ECDH keys.
4. Sets `A` and `a` as `our_dh`: the ephemeral 3072-bit DH keys.
5. Calculates the Mixed shared secret (`K`) and the SSID:
    * Calculates ECDH shared secret
      `K_ecdh = ECDH(our_ecdh.secret, their_ecdh)`.
      Securely deletes `our_ecdh.secret`.
    * Calculates DH shared secret `k_dh = DH(our_dh.secret, their_dh)`.
      Securely deletes `our_dh.secret`.
    * Calculates the brace key `brace_key = KDF_1(0x02 || k_dh, 32)`.
      Securely deletes `k_dh`.
    * Calculates the Mixed shared secret
      `K = KDF_1(0x04 ||K_ecdh || brace_key, 64)`.
      Securely deletes `K_ecdh` and `brace_key`.
    * Calculates the SSID from shared secret: the first 8 bytes of
      `KDF_1(0x05 || K, 64)`.
6. Sends Alice the Auth-R message (see [Auth-R message](../otrv4.md#auth-r-message) section).

**Alice:**

1. Receives the Auth-R message from Bob:
   * Picks a compatible version of OTR listed on Bob's profile (only "4" for
     this mode). If the versions are incompatible, Alice does not send any
     further messages.
2. Retrieves the ephemeral public keys from Bob:
    * Validates that the received ECDH ephemeral public key `X` is on curve
      Ed448 and sets it as `their_ecdh`.
      See [Verifying that a point is on the curve](../otrv4.md#verifying-that-a-point-is-on-the-curve)
      section for details.
    * Validates that the received DH ephemeral public key `A` is on the correct
      group and sets it as `their_dh`. See
      [Verifying that an integer is in the DH group](../otrv4.md#verifying-that-an-integer-is-in-the-dh-group)
      section for details.
3. Verifies the Auth-R message as defined in the
   [Auth-R message](../otrv4.md#auth-r-message) section.
4. Creates an Auth-I message (see [Auth-I message](../otrv4.md#auth-i-message)
   section).
5. Calculates the Mixed shared secret (`K`) and the SSID:
    * Calculates ECDH shared secret
      `K_ecdh = ECDH(our_ecdh.secret, their_ecdh)`.
      Securely deletes `our_ecdh.secret`.
    * Calculates DH shared secret `k_dh = DH(our_dh.secret, their_dh)`.
      Securely deletes `our_dh.secret`.
    * Calculates the brace key `brace_key = KDF_1(0x02 || k_dh, 32)`.
      Securely deletes `k_dh`.
    * Calculates the Mixed shared secret
      `K = KDF_1(0x04 || K_ecdh || brace_key, 64)`.
      Securely deletes `k_ecdh` and `brace_key`.
    * Calculates the SSID from shared secret: the first 8 bytes of
      `KDF_1(0x05 || K, 64)`.
6. Initializes the double-ratchet:
    * Sets ratchet id `i` as 0.
    * Sets `j` as 0, `k` as 0 and `pn` as 0.
    * Generates Bob's ECDH and DH public keys:
       * Generates an ephemeral ECDH key pair, as defined in
         [Generating ECDH and DH keys](#generating-ecdh-and-dh-keys), but instead
         of using a random value `r`, it will use : `r = KDF_1(0x19 || K, 57)`.
         Securely replaces `their_ecdh` with the output
         `our_ecdh.public (G * s)` and securely deletes the output
         `our_ecdh.secret (s)`.
       * Generates an ephemeral DH key pair, as defined in
         [Generating ECDH and DH keys](#generating-ecdh-and-dh-keys), but instead
         of using a random value `r`, it will use : `r = KDF_1(0x20 || K, 80)`.
         Securely replaces `their_dh` with the output
         `our_dh.public (g3 ^ r)` and securely deletes the output
         `our_dh.secret (r)`.
7. At this point, the interactive DAKE is complete for Alice:
   * In the case that she wants to immediately send a data message:
     * Follows what is defined in the
       [When you send a Data Message](../otrv4.md#when-you-send-a-data-message)
       section. Note that she will perform a new DH ratchet.

7. At this point, the interactive DAKE is complete for Alice, but the
   double ratchet still needs to be correctly set up.

**Bob:**

1. Receives the Auth-I message from Alice:
   * Verifies the Auth-I message as defined in the
     [Auth-I message](../otrv4.md#auth-i-message) section.
2. Initializes the double ratchet:
   * Sets ratchet id `i` as 0.
   * Sets `j` as 0, `k` as 0 and `pn` as 0.
   * Generates an ephemeral ECDH key pair, as defined in
     [Generating ECDH and DH keys](../otrv4.md#generating-ecdh-and-dh-keys),
     but instead of using a random value `r`, it will use :
     `r = KDF_1(0x19 || K, 57)`.
     Securely replaces `our_ecdh` with the outputs.
   * Generates an ephemeral DH key pair, as defined in
     [Generating ECDH and DH keys](../otrv4.md#generating-ecdh-and-dh-keys),
     but instead of using a random value `r`, it will use :
     `r = KDF_1(0x20 || K, 80)`. Securely replaces `our_dh` with the outputs.
   * Securely deletes `their_ecdh` and `their_dh`.
1. At this point, the interactive DAKE is complete for Bob, but he has to
   correctly setup the double ratchet mechanism:
   * In the case that he immediately receives a data message that advertises the
     new public keys from Alice:
     * Follows what is defined in the
       [When you receive a Data Message](../otrv4.md#when-you-receive-a-data-message)
       section. Note that he will perform a new DH ratchet for the first
       received data message. When he wants to send a data message after
       receiving one, she will follow the
       [When you send a Data Message](../otrv4.md#when-you-send-a-data-message)
       section, and perform a new DH Ratchet. He is only allowed to send data
       messages after having received one from Alice.

### Scenarios and applications

This mode might work on this kind of applications and scenarios:

#### Scenario A: an OTRv4-Standalone WhatsApp-like application

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
messages through this application's network is using the application.

#### Scenario B: an OTRv4-Standalone Pidgin-like application

Alice wants to send a message to Bob.

1. Alice adds Bob as a contact
2. Alice verifies Bob's identity. She either:
   * Uses Bob's User Profile and verifies Bob's fingerprint using a business
     card, a HTTPS website, etc.
   * Performs a interactive DAKE and uses SMP.
2. Alice types a messages and "sends them" to Bob.
   * A DAKE is performed if the application is not already in an encrypted state.
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

## Considerations

Plaintext messages are not allowed in conversations in OTRv4-Standalone mode.
This means that query messages and whitespace tags are not allowed in this
mode.

By always requiring encryption, this mode may encourage long-lived sessions.
The section [session expiration](../otrv4.md#session-expiration) of the OTRv4
protocol specification outlines how to mitigate the risks of long-lived
sessions. For this reason, TLVs type 1 (Disconnected) are necessary in this
mode.

Furthermore, as this mode always requires encryption, the protocol can get stuck
if, for example, a DAKE message is lost and never delivered. This mode does not
define any strategy, like a timeout, for dealing with such cases; but
implementers are recommended to do so.

Even though there is no need to prefix OTR messages with the five bytes "?OTR:",
since the protocol only handles OTR messages, this mode does not modify this
encoding for convenience.

This mode is compliant with the security properties described in the
[security properties](../otrv4.md#security-properties) section. But, take into
account that there may be a loss of deniability if an interactive DAKE is
followed by a non-interactive one. Implementers are recommended to warn the
users about it when it happens.
