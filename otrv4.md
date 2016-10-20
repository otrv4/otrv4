# OTR version 4

The following messaging protocol provides way for two people to have a conversation over a network
in a way that provides the same security as a private in person conversation, where no external party
can overhear what is being said, and no one (not even the conversation participants) can prove what
was said, or even that the two participants spoke to each other at all.

## Table of Contents

1. [Main Changes over Version 3](#main-changes-over-version-3)

2. [High Level Overview](#high-level-overview)

3. [Assumptions](#assumptions)

4. [Security Properties](#security-properties)

5. [OTR Conversation Initialization](#otr-conversation-initialization)
    1. [Requesting a conversation](#requesting-a-conversation)
    2. [Deniable Authenticated Key Exchange (DAKE)](#deniable-authenticated-key-exchange-dake)
    3. [Interactive DAKE](#interactive-dake)
    4. [Non-interactive DAKE](#non-interactive-dake)

6. [Requesting conversation with older OTR version](#requesting-conversation-with-older-otr-version)

7. [Data exchange](#data-exchange)

## Main Changes over Version 3

TODO: Write this section when we have fleshed out the other sections of the spec and decide what is important to highlight here

## High Level Overview

Off The Record messaging (OTR) is a messaging protocol that achieves forward-secrecy
and deniability.

OTR conversations may happen while both participants are online (interactive), or one side
is offline (non-interactive).

The high level flow of this protocol will be:

    Alice                                            Bob
    --------------------------------------------------------------------------------
    Request OTR conversation          ------------->
                                      <-------------  OTR v4 is supported
    Establish Conversation with DAKE  <------------>  Establish Conversation with DAKE
    Exchange Data Messages            <------------>  Exchange Data Messages

## Assumptions

At least one participant is online at the start of a conversation.

Messages in a conversation will be exchanged over an insecure channel, where an attacker can eavesdrop or interfere with the messages.

We assume a network model which provides in-order delivery of messages. Some messages may not be delivered.

## Security Properties

In an off the record conversation, both sides can verify the identity of the other participant
(but cannot transfer this knowledge to a third party). Participants can converse with the assurance
that their conversation will not be read or modified by a hostile third party.

To resemble an in-person conversation means that both ends can deny that they have participated in
said conversation. Both ends can also deny having sent one or many of the exchanged messages in the conversation.

### DAKE properties
 * Mutual authentication
 * Interactive: participation repudiation for both initiator and receiver
 * Non-interactive: participation repudiation for *only* the receiver

### Conversation properties
 * Confidentiality
 * Integrity
 * Forward secrecy
 * Message deniability

Threats that an OTR conversation does not mitigate:
* An active attacker may perform a Denial of Service attack but not learn the contents of messages.

## OTR Conversation Initialization

OTR4 conversations are established by an deniable authenticated key exchange
protocol (DAKE). The DAKE is different for either an interactive or non-interactive
conversation.

### Initialization in the interactive case

There are two ways Alice can inform Bob that she is willing to use the OTR
protocol to speak with him in an interactive setting: by sending him the OTR
Query Message, or by including a special "tag" consisting of whitespace
characters in one of her messages to him. Each method also includes a way for
Alice to communicate to Bob which versions of the OTR protocol she is willing
to speak with him.

The semantics of the interactive OTR Query Message are that Alice is requesting
that Bob start an OTR conversation with her (if he is willing and able to do
so). The semantics of the whitespace tag are that Alice is opportunistically
indicating to Bob that she is willing to have an OTR conversation with him.

For example, if Bob has a policy of "only use OTR when it's explicitly
requested", then he would start an OTR conversation upon receiving an OTR
Query Message, but would not upon receiving the whitespace tag.

Both the OTR Query Message and Whitespace tag include the OTR versions Alice
supports and is willing to use.

Once Bob has decided to start the conversation in response to Alice's request,
he will initiate an interactive, deniable, authenticated key exchange DAKE.

### Initialization in the non-interactive case

OTR4 introduces the ability to send a message to an offline participant.

In this scenario, there is no Query Message or Whitespace tag. Bob begins the
DAKE by placing his prekeys on an untrusted server. To send a message to Bob,
Alice fetches one of Bob's prekeys and uses it to complete the DAKE and send
Bob an encrypted message.

### Version negotiation

OTR4 introduces mandatory version negotiation to resist version rollback. In
both cases, the receiving party will include in the DAKE authenticated
information about what versions they received, and the initializing party will
verify that the versions are correct.

### Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the Deniable Authenticated Key Exchange, which
is a way for two parties to mutually agree upon a shared key and authenticate one
another while also allowing a level of participation deniability.

This process is based on the Spawn protocol, which utilizes Dual Receiver
Encryption (DRE) and a NIZKPK for authentication (Auth).

### Interactive DAKE Overview

```
    Alice                                          Bob
    ---------------------------------------------------
    Query Message or Whitespace Tag ------->
                                    <------- ψ1
                                 ψ2 ------->
                                             Verify & Decrypt (ψ2)
```

The Query Message or Whitespace Tag will include the versions supported by
Alice.

ψ1 = { "B", pubB, g^b, Bobs_versions }

"B" is Bob's account identifier. Bobs_versions are the versions supported
by Bob.

ψ2 = { "A", pubA, γ, σ } where
γ = DRE(pubB, pubA, "B" || g^b || "A" || g^a)
σ = Auth(hA, zA, {hB, hA, g^b}, "B" || "A" || g^b || Alices_versions || Bobs_versions || γ )

"A" is Alice's account identifier.

After receiving ψ2, Alice authenticates σ and decrypts γ. She then verifies the
versions that were sent by both parties. If Bob did not receive the Query
Message or Whitespace Tag sent by Alice or if Bob is using a version of OTR that
is not the highest preferable version, this check will fail. If all checks pass,
then Alice and Bob have a shared secret with which to encrypt their data
messages.

### Non-interactive DAKE Overview

```
    Alice                       Prekey storage                     Bob
    --------------------------------------------------------------------
                                                <--------- Prekey (ψ1)
    Prekey request              ------------->
                                <-------------             Prekey (ψ1)
    ψ2 & m         -------------------------------------->
                                                 Verify & Decrypt (ψ2)
```

In the non-interactive DAKE, Bob generates one (or more) prekeys and places
them in a prekey storage, like a server.

A prekey consists of pubB, g^b, "B", and the OTR version of the prekey.

When Alice wants to start a secure conversation with Bob, she requests one of
Bob's prekeys from the storage, and then she computes ψ2 and m.

ψ2 = { pubA, γ, σ }
γ = DRE(pubB, pubA, "B" || g^b || "A" || g^a || Alices_versions )
σ = Auth(hA, zA, {hB, hA, g^b}, "B" || "A" || g^b || Bobs_prekey_version || γ )

m is a data message encrypted with the shared secret generated from g^a and g^b.

Before Bob decrypts the message, he auathenticates the auth σ and decrypts γ. He
then verifies that the prekey Alice is using corresponds to the version he placed
on the server, and then he checks that Alice and Bob are using the highest
preferable version. If all the checks pass then Bob will decrypt the message

TODO: How pre-key storage is protocol-specific, maybe mention the XMPP
extension for this.

TODO: How to encode pre-keys.

### Packet format

#### Pre-key message

This is the first message of the DAKE. Bob sends it to Alice to commit to a choice of D-H key.

```
Protocol version (SHORT)
    The version number of this protocol is 0x0004.
Message type (BYTE)
    The D-H Commit Message has type 0x0f.
Sender Instance tag (INT)
    The instance tag of the person sending this message.
Receiver Instance tag (INT)
    The instance tag of the intended recipient. For a commit message this will often be 0, since the other party may not have identified their instance tag yet.
g^b (DATA)
    The public part of ECDH, b is randomly selected from the group defined.
Supported versions (DATA)
    TODO: encode this field
```

#### DRE-Auth message

This is the second message of the DAKE. Alice sends it to Bob to commit to a choice of D-H key and acknowledgement of Bob's D-H key,
use dual-receiver-encryption and zero-knowledge-proof-of-knowledge to encrypt and authenticate this message

```
Protocol version (SHORT)
    The version number of this protocol is 0x0004.
Message type (BYTE)
    The D-H Commit Message has type 0x00.
Sender Instance tag (INT)
    The instance tag of the person sending this message.
Receiver Instance tag (INT)
    The instance tag of the intended recipient. For a commit message this will often be 0, since the other party may not have identified their instance tag yet.
DREncrypted {pubB, pubA, "B" || g^b || "A" || g^a} (DATA)
    Produce this field as follows:
    TODO: decribe how to generate
Authenticated {"B" || "A" || g^b || γ} (DATA)
    Produce this field as follows:
    TODO: decribe how to generate
```

## Requesting conversation with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. If this is the
case the protocol falls back to [OTR version 3 specification][2].

Note: OTR version 4 is the latest version to support previous versions.

## Data Exchange

This section describes how each participant will use the Double Ratchet
algorithm to exchange data using the shared secret established in the DAKE.

TODO: Define structure of a data message (includes header, encrypted message, MAC, ephemeral key, old mac keys)

```
    Alice                                                                           Bob
    -----------------------------------------------------------------------------------
    Initialize root key, chain keys                        Initialize root key, chain keys
    Generate DH, pubDHa, privDHa                           Generate DH, pubDHb, privDHb
    Send data message 0_0            -------------------->
    Send data message 0_1            -------------------->


                                                           Receive data message 0_0
                                                           Recover receiving chain key 0_0
                                                           Derive Enc-key & MAC-key
                                                           Verify MAC, Decrypt message 0_0

                                                           Receive data message 0_1
                                                           Recover receiving chain key 1_1
                                                           Derive Enc-key & MAC-key
                                                           Verify MAC, Decrypt message 0_1

                                                           Ratcheting with root key, pubDHa, privDHb
                                     <-------------------- Send data message 1_0
                                     <-------------------- Send data message 1_1

    Receive data message 1_0
    Recover receiving chain key 1_0
    Derive Enc-key & MAC-key
    Verify MAC, Decrypt message 1_0

    Receive data message 1_1
    Recover receiving chain key 1_1
    Derive Enc-key & MAC-key
    Verify MAC, Decrypt message 1_1
```

### Key management

For each correspondent, keep track of:

    ratchet_flag
    i as Current ratchet id
    j as Previous sent message id
    k as Previous received message id

    R as Root key
    Cs_j as Sending Chain key
    Cr_k as Receiving Chain key
    our_dh, their_dh

Initialization of Double Ratchet

    After the DAKE is finished, both side will initialize the first group of root key (R0) and chain key
    (C0_0) deriving from SharedSecret.

    ```
    R0, Ca0_0, Cb0_0 = KDF(SharedSecret)
    ```
    - For the Initiator:
      - She will ratchet once again by generating a new pair of DH keys and derive R1, Ca1_0, Cb1_0
    - For the Receiver:
      - He will reuse the DH keys used in the DAKE

    Both side will compare their public keys to choose a chain key for sending and receiving:

    - Initiator (and similarly for Receiver) determines if she is the "low" end or the "high" end of this Data Message.
    If Initiator's ephemeral D-H public key is numerically greater than Receiver's public key, then she is the "high" end.
    Otherwise, she is the "low" end.
    - Initiator selects the chain keys for sending and receiving:
      - If she is the "high" end, use Ca0_0 as the sending chain key, Cb0_0 as the receiving chain key.
      - If she is the "low" end, use Cb0_0 as the sending chain key, Ca0_0 as the receiving chain key.

When you send a Data Message:

    1. If ratchet_flag is true, first ratchet:
        1. Derive new pair of R, Cs_0, Cr_0 from private part of our_dh and public part of their_dh.
        2. Securely forget our_dh, increment i, and set our_dh to a new DH key pair which you generate.
        3. Set ratchet_flag to false.

    2. Set the ratchet_id to i.
    3. Set the DH pubkey in the Data message to the public part of our_dh.
    4. Increment j, and use Cs_j to derive the Enc and MAC key.
    5. Use the Enc key to encrypt the message, and the MAC key to calculate its mactag.

When you receive a Data Message:

    1. If the ratchet_id does not equal i+1, reject the message.
    2. If the message_id is not larger than k, reject the message.
    3. Use the message_id to compute the Receiving Chain key Cr_message_id.
    4. Use the Cr_message_id to derive the Enc and MAC key.
    5. Use the MAC key to verify the mactag on the message. If it does not verify, reject the message.
    6. Decrypt the message using the Enc key.
    7. Set k to message_id, Set ratchet_flag to true, Set their_dh as pubDHRs of the message.

### Revealing MAC Keys

We reveal old MAC keys to provide forgeability of messages. Old MAC keys are keys for messages that have already been received, therefore will no longer be used to verify the authenticity of a message.

MAC keys are revealed with data messages. They are also revealed with heartbeat messages (data messages that encode a plaintext of zero length) if the receiver has not sent a message in a configurable amount of time.

A receiver can reveal a MAC key in the following case:

- the receiver has received a message and has verified the message's authenticity
- the receiver has discarded associated message keys
- the receiver has discarded the chain key that can be used to compute the message keys (chain keys from previous ratchets might be stored to compute message keys for skipped or delayed messages)


### Packet format

```
Protocol version (SHORT)

    The version number of this protocol is 0x0004.

Message type (BYTE)

    The Data Message has type 0x03.

Sender Instance tag (INT)

    The instance tag of the person sending this message.

Receiver Instance tag (INT)

    The instance tag of the intended recipient.

Flags (BYTE)

    The bitwise-OR of the flags for this message. Usually you should set this to 0x00. The only currently defined flag is:

    IGNORE_UNREADABLE (0x01)

        If you receive a Data Message with this flag set, and you are unable to decrypt the message or verify
        the MAC (because, for example, you don't have the right keys), just ignore the message instead of producing
        some kind of error or notification to the user.

Ratchet id i (INT)

    Must be strictly greater than 0, and increment by 1 with each ratchet

Message id Ns (INT)

    Must be strictly greater than 0, and increment by 1 with each message

pubDHRs (MPI)

    The *next* ratchet [i.e. sender_keyid+1] public key for the sender

Top half of counter init (CTR)

    This should monotonically increase (as a big-endian value) for each message sent with the same (sender keyid,
    recipient keyid) pair, and must not be all 0x00.

Encrypted message (DATA)

    Using the appropriate encryption key (see below) derived from the sender's and recipient's DH public keys
    (with the keyids given in this message), perform AES128 counter-mode (CTR) encryption of the message.
    The initial counter is a 16-byte value whose first 8 bytes are the above "top half of counter init" value,
    and whose last 8 bytes are all 0x00.
    Note that counter mode does not change the length of the message, so no message padding needs to be done.
    If you *want* to do message padding (to disguise the length of your message), use the above TLV of type 0.

Authenticator (MAC)

    The SHA3 MAC, using the appropriate MAC key (see below) of everything from the Protocol version to the end
    of the encrypted message

Old MAC keys to be revealed (DATA)

    See "Revealing MAC Keys"
```

[1]: http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
[2]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
