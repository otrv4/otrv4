# OTR version 4

The following protocol aims to allow two people to maintain a conversation over a network in a way that comes as close as possible to a private person to person conversation - where no other entity can overhear what is being said, and the other party can't prove anything that was said - or even the fact that you talked. 

Security here means that both ends can verify at the beginning of the
conversation the identity of the other end and the establishment of a
trusted channel. Private here means that exchanged messages are hard
to be read, added, removed or modified by a hostile third party
listening to the conversation.

To resemble a in person conversation means that both ends can deny to
have participated in said conversation or to have sent one or many of
the exchanged messages once the conversation is over.

##Table of Contents

1.[Overview](#overview)

2.[Security Properties](#security-properties)

3.[Assumptions](#assumptions)

4.[Exceptions](#exceptions)

5.[Online Conversations](#online-conversation)
  1. [OTR Query Message] (#query-message)
  2. [Online authenticated key exchange (AKE)] (#online-AKE)
  3. [Data message exchange] (#online-conversation-msg-exchange)
  4. [Online conversation end] (#online-conversation-end)

6.[Offline Conversations](#offline-conversation)
  1. [Offline authenticated key exchange (AKE)] (#offline-AKE)
  2. [Data message exchange] (#offline-conversation-msg-exchange)
  3. [Offline conversation end] (#offline-conversation-end)

## Overview <a name="overview"></a>

This protocol refers to the initiator of the conversation as Alice
and refers to the receiver as Bob, to a passive attacker as Eve and 
to an active attacker as Mallory, in order to use the common 
terminology used in cryptography literature.

The messages exchanged between Alice and Bob are said to be
transported through a channel.

This conversation may happen while both Alice and Bob are online or,
when only Alice is online and Bob will receive messages posted for him
as soon as he gets online.

The initial connection state of both Alice and Bob might change while
the conversation is happening.

This conversation will take place over public infrastructure where
potential hostile intermediaries are present at different levels.

## Security Properties <a name="security-properties"></a>

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

## Assumptions <a name="assumptions"></a>

This protocol assumes that at least Alice has an available network and that both ends run this protocol over an underlying protocol which enables the exchange of messages.

## Exceptions <a name="exceptions"></a>

This protocol is not intended to enable group conversations.

## Online Conversations <a name="online-conversation"></a>

Alice knows Bob is online because the underlying protocol is
able to answer questions about Bob's presence.

Alice starts a conversation with Bob by sending a request that
Bob responds notifying he's ready to start and messages exchange
begins. Once all the desired messages have been sent and received any
of the ends can signal the other end the conversation has finished.

| Alice                           | Server        | Bob                              |
|---------------------------------|---------------|----------------------------------|
| Requests for Bob' status        | Bob is online |                                  |
| Query Message                   |               | OTR v4 is supported              |
| Establish Conversation with AKE |               |                                  |
| Exchange data message           |               | Exchange data message            |
| End conversation                |               | Acknowledges end of conversation |

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
mechanism RSDAKE defined by Neil Unger in his paper ["RSDAKE and SPAWN
paper"][1].

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

### Data message exchange <a name="online-conversation-msg-exchange"></a>

### Online conversation end <a name="online-conversation-end"></a>

## Offline Conversations <a name="offline-conversation"></a>

### Requesting Offline conversation <a name="offline-conversation-start"></a>

#### Requesting Offline conversation with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. Since previous
versions do not provide the ability to maintain an offline
conversations the starting process is dropped.

Note. OTR version 4 is the last version to support previous versions.

### Offline authenticated key exchange (AKE) <a name="offline-AKE"></a>

#### Initiating Offline AKE
#### Recieving Offline AKE

### Data message exchange <a name="offline-conversation-msg-exchange"></a>

### Offline conversation end <a name="offline-conversation-end"></a>


[1]: http://www.paper.net/Unger/rsdake_spawn.pdf
[2]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
