# OTR version 4

The following messaging protocol provides way for two people to have a conversation over a network
in a way that provides the same security as a private in person conversation, where no external party
can overhear what is being said, and no one (not even the conversation participants) can prove what
was said, or even that the two participants spoke to each other at all.

Terms used in the context of this protocol have been defined in the [glossary][3] and the [cryptography primitives][4] pages.

##Table of Contents

1. [What's New in version 4](#whats-new)

2. [High Level Overview](#overview)

3. [Assumptions](#assumptions)

4. [Security Properties](#security-properties)

5. [Online Conversation Initialization](#online-conversation-init)
  1. [OTR Conversation Request] (#conversation-request)
  2. [Interactive authenticated key exchange (AKE)] (#interactive-AKE)

6. [Offline Conversation Initialization](#offline-conversation-init)
  1. [Offline authenticated key exchange (AKE)] (#offline-AKE)

7. [Data exchange] (data-exchange)

## What's New in version 4 <a name="whats-new"></a>

1. Participation repudiation
2. Support for out of order data messages
3. Encrypted messaging to offline participants
4. Update crypto primitives to higher security level

## High Level Overview <a name="overview"></a>

Off The Record messaging (OTR) is a messaging protocol that achieves forward-secrecy
and deniability.

OTR conversations may happen while both participants are online, or one side
is offline. Participants in an OTR conversation can go online and offline while
the conversation is ongoing.

The high level flow of this protocol will be:

    Alice                                            Bob
    --------------------------------------------------------------------------------
    Request OTR conversation         ------------->
                                     <-------------  OTR v4 is supported
    Establish Conversation with AKE  <------------>  Establish Conversation with AKE
    Exchange Data Messages           <------------>  Exchange Data Messages

## Assumptions <a name="assumptions"></a>

At least one participant has an available network and that both ends run the OTR protocol
over an underlying protocol which enables the exchange of messages.

TODO: Is this about the network model?

## Security Properties <a name="security-properties"></a>

TODO: differentiate between entire OTR conversation (including AKE) and text conversation (which happens after AKE)

In an off the record conversation, both sides can verify the identity of the other participant
(but cannot transfer this knowledge to a third party). Participants can converse with the assurance
that their conversation will not be read or modified by a hostile third party.

To resemble an in-person conversation means that both ends can deny that they have participated in
said conversation. Both ends can also deny having sent one or many of the exchanged messages in the conversation.

An conversation will take place over an insecure channel where
potential hostile intermediaries are present at different levels.

### AKE properties:
 * Mutual authentication
 * Interactive: participation repudiation for both initiatior and receiver
 * Non-interactive: participation repudiation for *only* the receiver

### Conversation properties:
 * Confidentiality
 * Integrity
 * Forward secrecy
 * Message deniability

Threats that an OTR conversation does not mitigate:
* An active attacker may perform a Denial of Service attack but not learn the contents of messages.

## OTR Conversation Initilization 

OTRv4 conversations are established by an deniable authenticated key exchange
protocol (DAKE).

This process will use the deniable authenticated key exchange
mechanism RSDAKE defined by Nik Unger and Ian Goldberg in their paper 
["Improved Techniques for Implementing Strongly Deniable
Authenticated Key Exchanges"][1].

TODO: introduce interactive and non-interactive AKE

TODO: How are long-term public keys distributed? In OTRv3 they are distributed
as part of the AKE.

## Establishing a conversation when both parties are online <a name="online-conversation-init"></a>

A OTRv4 conversation is established by Alice requesting a conversation with
Bob.

There are two ways Alice can inform Bob that she is willing to speak
with him: by sending him the OTR Query Message, or by including a special
"tag" consisting of whitespace characters in one of her messages to him.

Bob then decides to respond this request or not depending on his policy. And
AKE messages will be exchanged to establish a shared secret.

The message flow is:

    Alice                                            Bob
    ---------------------------------------------------------
    OTRv4 Conversation Request    ------------->
                                  <-------------    D-H Commit (ψ1)
    D-H Key and Auth (ψ2)         -------------> 

### Requesting a conversation <a name="conversation-request"></a>

The semantics of the OTR Query Message are that Alice is requesting that
Bob start an OTR conversation with her (if he is willing and able to do so).
The semantics of the whitespace tag are that Alice is opportunistically indicating
to Bob that she is willing to have an OTR conversation with him.

For example, if Bob has a policy of "only use OTR when it's explicitly requested",
then he would start an OTR conversation upon receiving an OTR Query Message, but
would not upon receiving the whitespace tag.

Both OTR Query Message and Whitespace tag include the OTR versions Alice supports
and is willing to use.

Once Bob has decided to start the conversation in response to Alice'e request,
he will initiate an interactive authenticated key exchange (AKE).

### Interactive authenticated key exchange (AKE) <a name="interactive-AKE"></a>

TODO: introduce this
TODO: Explain and talk about encoding, state machine, errors, all of it

| Alice                              | Bob                            |
|------------------------------------|--------------------------------|
|                                    | select i, send {"I"; g^i}      |
| select r, send {"R"; g^r; Auth(R)} |                                |
|                                    | verify Auth(R), send {Auth(I)} |
| verify Auth(R)                     |                                |

## Establishing a conversation when one participant is offline <a name="offline-conversation-init"></a>

TODO: explain when this will be used?


### Non-interactive authenticated key exchange (AKE) <a name="offline-AKE"></a>

TODO: briefly explains the non-interactive AKE, how its the same as interactive
but with a pre-key storage mechanism.

    Alice                              Pre-key storage                     Bob
    ---------------------------------------------------------------------------
                                                       <------ D-H Commit (ψ1) 
    Pre-key request     ------------->
                        <------------- D-H Commit (ψ1)
    D-H Key and Auth (ψ2) ------------------------------------> 

In the non-interactive AKE, Bob generates one (or more) D-H Commit messages,
named pre-keys for convenience, and stores them in a pre-key storage.

When Alice wants to start a secure conversation, she asks the pre-key storage
for a pre-key associated with Bob, and treats it as if it were a D-H Commit
message in the interactive AKE.

TODO: How pre-key storage is protocol-specific, maybe mention the XMPP
extension for this.

TODO: How to encode pre-keys.
TODO: How to store pre-keys on device.

## Requesting conversation with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. If this is the
case the protocol falls back to [OTR version 3 specification][2].

Note: OTR version 4 is the latest version to support previous versions.

## Data Exchange <a name="data-exchange"></a>
This section describes how each participant will use the Double Ratcheting
algorithm to exchange data using the shared secret established in the DAKE.

### Sending Messages

If it's the very first message we send after AKE.
The shared secret established in the DAKE will be used to create the initial first
set of keys: root key (R0), header key (H0), and chain key (C0).

If a new DH Ratchet key has been received (pubDHRr), begin a new ratchet.

To begin a new ratchet, create and store a pair of DH Ratchet key (privDHRr, pubDHRr)
and use ECDH to compute a shared secret from (privDHRr) and (pubDHRr).
This shared secret and the current root key (Ri-1) are used as input to a HKDF to derive
new root key (Ri), header key (Hi), and chain key (Ci).

```
if First_Message:
  R0, H0, C0_0 = HKDF(SharedSecret)
else if New_Rachet:
  pubDHRs, privDHRs = generateECDH()
  store(privDHRs, pubDHRs)
  Ri, Hi, Ci_0 = HKDF(Ri-1, ECDH(privDHRs, pubDHRr))
else:
  reuse(privDHRs, pubDHRs)
  reuse(Ri, Hi, Ci_0)
```

The current message number (msgNum) and the (pubDHRs) must also be encrypted with the header key (Hi)
and sent. If this is the first message sent after starting a new ratchet, the msgNum is 0.
If it is the second message, the msgNum is 1 and so on.

```
ephemeral = Enc(Hi, msgNum || pubDHRs)
```

Then the current chain key (Ci_msgNum) is used to derive messages keys for encrypting the message
and generating a MAC tag.

```
MKenc || MKmac = SHA3-256(Ci_msgNum || "0")
ciphertext = Enc(MKenc, plaintext)
mactag = MAC(MKmac, ciphertext)
```

Use SHA3-256 to compute a new chain key (Ci_msgNum+1) from the current chain key (Ci_msgNum).
And increase the current message number (msgNum) by one.

```
Ci_msgNum+1 = SHA3-256(Ci_msgNum || "1")
msgNum = msgNum + 1
```

Send the ephemeral, ciphertext, mactag.

### Receiving Message

Receive the ephemeral, ciphertext, mactag.

If it's the very first message we receive after AKE

```
R0, H0, C0_0 = HKDF(SharedSecret)
```

Otherwise we derive the keys with current header key (Hi)

```
msgNum || pubDHRs = Decrypt(Hi, ephemeral)
```

Derive the keys for decryption and MAC tag verification from the chain key and use
these keys to verify the tag and decrypt the message.

```
Ci_msgNum = SHA3-256(Ci_msgNum-1 || "1")
MKenc || MKmac = SHA3-256(Ci_msgNum || "0")
if valid(MKmac, mactag):
    plaintext = Decrypt(MKenc, ciphertext)
```

### Revealing MAC Keys

To provide forgeability of messages, we want to reveal the MAC keys after deciding to abort
corresponding chainkey.

A receiver can always reveal a MAC key directly after verified this message.
But receiver should not use/accept the revealed MAC key anymore.

A sender would have different scenarios:
1. the message is received and MAC key is revealed, which is fine
2. the message is received but MAC key is not revealed
3. the message is not yet received

The second and third scenarios are kind of conflict, because it appears the same for a sender
while no any acknowledgement announced from receiver.

In this case, we need to give the sender a expiring preference to reveal a MAC key by itself
when he decide the corresponding chain key is no more useful, regardless whether receiver has
received and verified the message or not.

TODO: deceide when and how the revealing MAC key should be like

[1]: http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
[2]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
[3]: glossary.md
[4]: crytographic_primitives.md
