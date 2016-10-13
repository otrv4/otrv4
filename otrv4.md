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
    Exchange Data Messages           <------------>  Exchange Data Messages

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
    Alice                              Prekey storage                     Bob
    ---------------------------------------------------------------------------
                                                       <--------- Prekey (ψ1)
    Prekey request    ------------->
                      <-------------   Prekey (ψ1)
               ψ2 & m ------------------------------------------>
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
                                     <-------------------- Reveal MAC key of message 0_0

                                                           Receive data message 0_1
                                                           Recover receiving chain key 0_1
                                                           Derive Enc-key & MAC-key
                                                           Verify MAC, Decrypt message 0_1
                                     <-------------------- Reveal MAC key of message 0_1

                                                           Ratcheting with root key, pubDHa, privDHb

                                     <-------------------- Send data message 1_0
                                     <-------------------- Send data message 1_1

    Receive data message 1_0

    Ratcheting with root key, pubDHa, privDHb

    Recover receiving chain key 1_0
    Derive Enc-key & MAC-key
    Verify MAC, Decrypt message 1_0
    Reveal MAC key of message 1_0    -------------------->

    Receive data message 1_1
    Recover receiving chain key 1_1
    Derive Enc-key & MAC-key
    Verify MAC, Decrypt message 1_1
    Reveal MAC key of message 1_1    -------------------->
```
### Initialization of Double Ratchet

After the DAKE is finished, both side will initialize the first group of root key (R0) and chain key
(C0_0) deriving from SharedSecret.

```
R0, Ca0_0, Cb0_0 = KDF(SharedSecret)
```
Both side will compare their public keys to choose a chain key for sending and receiving:

- Alice (and similarly for Bob) determines if she is the "low" end or the "high" end of this Data Message.
If Alice's ephemeral D-H public key is numerically greater than Bob's public key, then she is the "high" end.
Otherwise, she is the "low" end.
- Alice selects the chain keys for sending and receiving:
  - If she is the "high" end, use Ca0_0 as the sending chain key, Cb0_0 as the receiving chain key.
  - If she is the "low" end, use Cb0_0 as the sending chain key, Ca0_0 as the receiving chain key.

### Sending Messages

If a new DH Ratchet key (pubDHRr) has been received, begin a new ratchet.

To begin a new ratchet, create and store a pair of DH Ratchet key (privDHRr, pubDHRr)
and use ECDH to compute a shared secret from (privDHRr) and (pubDHRr).
This shared secret and the current root key (Ri-1) are used as input to a KDF to derive
new root key (Ri) and chain key (Ci).

```
if New_Ratchet:
  i = i + 1
  Ns = 0
  pubDHRs, privDHRs = generateECDH()
  store(privDHRs, pubDHRs)
  NewSharedSecret = SHA3(Ri-1 || ECDH(privDHRs, pubDHRr))
  Ri, Cai_0, Cbi_0 = KDF(NewSharedSecret)
  discard(Ri-1)
else:
  reuse(privDHRs, pubDHRs)
```

The current ratchet id (i), current message keyid (Ns) and the (pubDHRs) must also be sent.
If this is the first message sent after starting a new ratchet, the keyid is 0.
If this is the second message, the keyid is 1 and so on.

```
header = i || Ns || pubDHRs
```
The current chain key (Csi_Ns) is used to derive message keys for encrypting the message
and generating a MAC tag.
```
MKenc, MKmac = KDF(Csi_Ns || "0")
ciphertext = Enc(MKenc, plaintext)
mactag = MAC(MKmac, header || ciphertext)
```
Use SHA3-256 to compute a new chain key (Csi_Ns+1) from the current chain key (Csi_Ns), and
increase the current message keyid (Ns) by one.

Csi_Ns+1 = SHA3-256(Csi_Ns || "1")
Ns = Ns + 1
```
Send the header, ciphertext, mactag.


### Receiving Message

Receive the header, ciphertext, mactag.
```
i || Ns || pubDHRs = header

Derive the keys for decryption and MAC verification from the chain key and use
these keys to verify the MAC tag and decrypt the message.
```
Cri_Ns = SHA3-256(Cri_Ns-1 || "1")
MKdec, MKmac = KDF(Cri_Ns || "0")
if valid(MKmac, mactag):
    plaintext = Decrypt(MKdec, ciphertext)
    reveal(MKmac)
```

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

    The version number of this protocol is 0x0003.

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

Sender keyid Ns (INT)

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
