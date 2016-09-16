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

7. [Data message exchange] (conversation-msg-exchange)

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

## Data message exchange

[1]: http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
[2]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
[3]: glossary.md
[4]: crytographic_primitives.md
