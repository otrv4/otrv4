# OTR version 4

The following messaging protocol provides way for two people to have a conversation over a network
in a way that provides the same security as a private in person conversation, where no external party
can overhear what is being said, and no one (not even the conversation participants) can prove what
was said, or even that the two participants spoke to each other at all.

Terms used in the context of this protocol have been defined in the [glossary][3] and the [cryptography primitives][4] pages.

##Table of Contents

1. [What's New in version 4](#whats-new-in-version-4)

2. [High Level Overview](#high-level-overview)

3. [Assumptions](#assumptions)

4. [Security Properties](#security-properties)

5. [OTR Conversation Initilization](#otr-conversation-initilization)
    1. [Requesting a conversation](#requesting-a-conversation)
    2. [Deniable Authenticated Key Exchange (DAKE)](#deniable-authenticated-key-exchange-dake)
    3. [Interactive DAKE](#interactive-dake)
    4. [Non-interactive DAKE](#non-interactive-dake)

6. [Requesting conversation with older OTR version](#requesting-conversation-with-older-otr-version)

7. [Data exchange](#data-exchange)

## What's New in version 4

1. Participation repudiation
2. Support for out of order data messages
3. Encrypted messaging to offline participants
4. Update crypto primitives to higher security level

## High Level Overview

Off The Record messaging (OTR) is a messaging protocol that achieves forward-secrecy
and deniability.

OTR conversations may happen while both participants are online, or one side
is offline. Participants in an OTR conversation can go online and offline while
the conversation is ongoing.

The high level flow of this protocol will be:

    Alice                                            Bob
    --------------------------------------------------------------------------------
    Request OTR conversation          ------------->
                                      <-------------  OTR v4 is supported
    Establish Conversation with DAKE  <------------>  Establish Conversation with DAKE
    Exchange Data Messages           <------------>  Exchange Data Messages

## Assumptions

At least one participant has an available network and that both ends run the OTR protocol
over an underlying protocol which enables the exchange of messages.

TODO: Is this about the network model?

## Security Properties

In an off the record conversation, both sides can verify the identity of the other participant
(but cannot transfer this knowledge to a third party). Participants can converse with the assurance
that their conversation will not be read or modified by a hostile third party.

To resemble an in-person conversation means that both ends can deny that they have participated in
said conversation. Both ends can also deny having sent one or many of the exchanged messages in the conversation.

An conversation will take place over an insecure channel where
potential hostile intermediaries are present at different levels.

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

OTRv4 conversations are established by an deniable authenticated key exchange
protocol (DAKE).

TODO: How are long-term public keys distributed? In OTRv3 they are distributed
as part of the DAKE.

### Requesting a conversation

The semantics of the OTR Query Message are that Alice is requesting that
Bob start an OTR conversation with her (if he is willing and able to do so).
The semantics of the whitespace tag are that Alice is opportunistically indicating
to Bob that she is willing to have an OTR conversation with him.

For example, if Bob has a policy of "only use OTR when it's explicitly requested",
then he would start an OTR conversation upon receiving an OTR Query Message, but
would not upon receiving the whitespace tag.

Both OTR Query Message and Whitespace tag include the OTR versions Alice supports
and is willing to use.

Once Bob has decided to start the conversation in response to Alice's request,
he will initiate an interactive authenticated key exchange (DAKE).

### Deniable Authenticated Key Exchange (DAKE)

A Deniable Authenticated Key Exchange is a way for two parties to agree upon a
shared key- but later be able to deny their participation- and mutually authenticate
to one another.

This process will use the deniable authenticated key exchange mechanism, Spawn, defined by
Nik Unger and Ian Goldberg in their paper.
["Improved Techniques for Implementing Strongly Deniable Authenticated Key Exchanges"][1].

1. Initiator sends the Pre-key message
    1. Select i
    2. Send ψ1 = {"I", g1^i} to Receiver
2. Receiver receives Pre-key message
    1. Select r
    2. Compute γ = DREnc(PK_I, PK_R, {"I" || "R" || g1^i || g1^r})
    3. Compute σ = Auth(h_R, z_R, {h_I, h_R, g1^i}, {"I" || "R" || g1^i || γ})
    4. Send ψ2 ={"R", γ, σ} to Initiator
    5. Compute k = (g1^i)^r and securely erase r
3. Initiator receives the DRE and Auth message
    1. Decrypt γ using SK_I, retrieve m = {"I" || "R" || g1^i || g1^r}
    2. Verify σ, m using {h_I, h_R, g1^i}
    3. Compute k = (g1^r)^i and securely erase i

Now both sides have an authenticated shared secret k, that can be used to exchange
encrypted data messages.
i
### Interactive DAKE

```
    Alice                                          Bob
    ---------------------------------------------------
    Conversation Request ------->
                         <------- Pre-key (ψ1)
    DRE and Auth (ψ2)    ------->
                                  Verify & Decrypt (ψ2)
```

### Non-interactive DAKE

```
    Alice                              Pre-key storage                     Bob
    ---------------------------------------------------------------------------
                                                       <--------- Pre-key (ψ1)
    Pre-key request   ------------->
                      <-------------   Pre-key (ψ1)
    DRE and Auth (ψ2) ------------------------------------------>
                                                         Verify & Decrypt (ψ2)
```

In the non-interactive DAKE, Bob generates one (or more) D-H Commit messages,
named pre-keys for convenience, and stores them in a pre-key storage.

When Alice wants to start a secure conversation, she asks the pre-key storage
for a pre-key associated with Bob, and treats it as if it were a D-H Commit
message in the interactive DAKE.

TODO: How pre-key storage is protocol-specific, maybe mention the XMPP
extension for this.

TODO: How to encode pre-keys.
TODO: How to store pre-keys on device.

## Requesting conversation with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. If this is the
case the protocol falls back to [OTR version 3 specification][2].

Note: OTR version 4 is the latest version to support previous versions.

## Data Exchange

This section describes how each participant will use the Double Ratcheting
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

                                                           Racheting with root key, pubDHa, privDHb

                                     <-------------------- Send data message 1_0
                                     <-------------------- Send data message 1_1

    Receive data message 1_0

    Racheting with root key, pubDHa, privDHb

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
these keys to verify the tag and decrypt the message.
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
[3]: glossary.md
[4]: crytographic_primitives.md
