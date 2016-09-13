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
  1. [OTR Query Message] (#query-message)
  2. [Online authenticated key exchange (AKE)] (#online-AKE)

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

## Security Properties <a name="security-properties"></a>

TODO: we need to find a better way to describe following (does this belong in the terminology section?)

In an off the record conversation, both sides can verify the identity of the other participant
(but cannot transfer this knowledge to a third party). Participants can converse with the assurance
that their conversation will not be read or modified by a hostile third party listening to the conversation.

To resemble an in person conversation means that both ends can deny to
have participated in said conversation or to have sent one or many of
the exchanged messages once the conversation is over.

An conversation will take place over an insecure channel where
potential hostile intermediaries are present at different levels.

Online:

An online conversation happens when both initiator and receiver are
online.
* at conversation start
 * authentication
 * repudiation for both initiator and receiver
* while exchanging messages
 * confidentiality
 * integrity
* after conversation is over
 * forward secrecy
 * malleability
 * repudiation for both initiator and receiver

Offline:

An offline conversation happens when the initiator is offline and the receiver is
online.
* at conversation start
 * authentication
 * repudiation for *only* the receiver
* while exchanging messages
 * confidentiality
 * integrity
* after conversation is over
 * forward secrecy
 * malleability
 * repudiation for both initiator and receiver

Threats that an OTR conversation does not mitigate:
* An active attacker may perform a Denial of Service attack but not learn the contents of messages.

## Online Conversations Initialization <a name="online-conversation-init"></a>

Alice knows Bob is online because the underlying protocol is
able to answer questions about Bob's presence.

Alice starts a conversation with Bob by sending a request that
Bob responds notifying he's ready to start and data message exchange
begins.

### OTR query message <a name="query-message"></a>

To start a conversation Alice should send either a request to do so or
notify her willingness to start a conversation (using a whitespace-tagged
plain-text message). Difference between them is that, in the first,
a response is expected and, in the second that a response is not expected
but may appear in the future.

There are two ways Alice can inform Bob that she is willing to speak
with him: by sending him the OTR Query Message, or by including a special
"tag" consisting of whitespace characters in one of her messages to him.

The semantics of the OTR Query Message are that Alice is requesting that
Bob start an OTR conversation with her (if, of course, he is willing and
able to do so). On the other hand, the semantics of the whitespace tag are
that Alice is merely indicating to Bob that she is willing and able to have
an OTR conversation with him. If Bob has a policy of "only use OTR when it's
explicitly requested", for example, then he would start an OTR conversation
upon receiving an OTR Query Message, but would not upon receiving the
whitespace tag.

Both OTR Query Message and Whitespace tag should include the OTR
versions Alice supports and is willing to use.

The response should include the OTR version that Bob supports and will be used
through the whole conversation. Bob must choose the latest version he supports.

Alice requests Bob to start a conversation:

| Alice                            | Bob                   |
|----------------------------------|-----------------------|
| OTR Query Message or Space Tags  |                       |
|                                  | supported OTR version |


### Online authenticated key exchange (AKE) <a name="online-AKE"></a>

Once the conversation has started Bob will initiate the authenticated key
exchange (AKE) with Alice.

This process will use the deniable authenticated key exchange
mechanism RSDAKE defined by Nik Unger and Ian Goldberg in their paper 
["Improved Techniques for Implementing Strongly Deniable
Authenticated Key Exchanges"][1].

| Alice                              | Bob                            |
|------------------------------------|--------------------------------|
|                                    | select i, send {"I"; g^i}      |
| select r, send {"R"; g^r; Auth(R)} |                                |
|                                    | verify Auth(R), send {Auth(I)} |
| verify Auth(R)                     |                                |

#### Requesting Online conversation with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. If this is the
case the protocol falls back to [OTR version 3 specification][2].

Note: OTR version 4 is the latest version to support previous versions.


## Offline Conversations Initialization <a name="offline-conversation-init"></a>

### Requesting Offline conversation

#### Requesting Offline conversation with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. Since previous
versions do not provide the ability to maintain an offline
conversations the starting process is dropped.

Note. OTR version 4 is the last version to support previous versions.

### Offline authenticated key exchange (AKE) <a name="offline-AKE"></a>

#### Initiating Offline AKE
#### Recieving Offline AKE

## Data message exchange

[1]: http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
[2]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
[3]: glossary.md
[4]: crytographic_primitives.md
