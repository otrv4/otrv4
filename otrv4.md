# OTR version 4

The following protocol aims to allow two people to maintain a conversation over a network in a way that comes as close as possible to a private person to person conversation - where no other entity can overhear what is being said, and the other party can't prove anything that was said - or even the fact that you talked. 

Security here means that both ends can verify at the begining of the
conversation the identity of the other end and the stablishment of a
trusted channel. Private here means that exchanged messages are hard
to be read, added, removed or modified by a hostile third party
listening to the conversation.

To ressemble a in person conversation means that both ends can deny to
have participated in said conversation or to have sent one or many of
the exchanged messages once the conversation is over.

##Table of Contents

1.[Overview](#overview)

2.[Assumptions](#assumptions)

3.[Exceptions](#exceptions)

4.[Online Conversations](#conversation1)

5.[Offline Conversations](#conversation2)

## Overview <a name="overview"></a>

This protocol refers to the initiator of the conversation as Alice
and refers to the receiver as Bob, to a passive attacker as Eve and 
to an active attacker as Mallory, in order to use the common 
terminology used in the cryptographic literature.

The messages exchanged between Alice and Bob are said to be
transported through a channel.

This conversation may happen while both Alice and Bob are online or,
when only Alice is online and Bob will receive messages posted for him
as soon as he gets online.

The initial connection state of both Alice and Bob might change while
the conversation is happening.

This conversation will take place over public infrastructure where
potential hostile intermediaries are present at different levels.


## Assumptions <a name="assumptions"></a>

This protocol assumes that at least Alice has an available network and that both ends run this protocol over an undelying protocol which enables the exchange of messages.

## Exceptions <a name="exceptions"></a>

This protocol is not intended to enable group conversations.

## Online Conversations <a name="conversation1"></a>

An online conversation happens when both Alice and Bob are
online. An online conversation provides both participants with the
following security properties:
* at conversation start
 * identity verification
* while exchanging messages
 * confidentiality: only Alice and Bob should be able to read the messages that make up their online conversation.
* after conversation is over
 * participation repudiability
 * message repudiability
 * forward secrecy: unability to read past messages even if an attacker has the proper keys. 

Alice knows Bob is online because the underlying protocol is
able to answer questions about Bob's presence.

Alice then starts a conversation with Bob by sending a request that
Bob responds notifying he's ready to start and messages exchange
begins. Once all the desired messages have been sent and received any
of the ends can signal the other end the conversation has finished.

| Alice                       		| Server		| Bob					|
|---------------------------------------|-----------------------|---------------------------------------|
| Requests for Bob' status   		| Bob is online		|					|
| Requests to start conversation 	|			| Responds ready to start		|
| Autenticates to Bob			|			| Autenticates to Alice			|
| Sends message				|			| Receives message			|
| Signals end of conversation		|			| Acknowledges end of conversation	|


### Online conversation start

To start a conversation Alice should send either a request to do so or
notify her willingness to start a conversation (using a whitespace-tagged 
plaintext message). Difference between them is that, in the first, 
a response is expected and, in the second that a response is not expected 
but may appear in the future.

There are two ways Alice can inform Bob that she is willing to speak 
with him: by sending him the OTR Query Message, or by including a special 
"tag" consisting of whitespace characters in one of her messages to him.

Both the request and notification of willingness include the OTR
versions Alice supports and is willing to use. 
The response should include the OTR version. Bob supports and that version 
will be used through the whole conversation. Bob must choose the higher 
version he supports.

Once the conversation has started Alice and Bob will autenticate to
each other and setup a secure channel for the conversation to take
place. 

Bob will initiate the authenticated key exchange (AKE) with Alice. 
This process will use the deniable authenticated key exchange
mechanism RSDAKE defined by Neil Unger in his paper ["RSDAKE and SPAWN
paper"][1] which provide both Alice and Bob with the following security
properties:
* Participation deniability
* Message deniability

Once the exchange has finished both ends have a channel which
provides the following properties
* Forward secrecy
* Repudation (participation and message)
* Malleability

Alice requests Bob to start a conversation

| Alice		          | Server  | Bob               |
|-------------------------|---------|-------------------|
| request "?OTRV4,OTRV3"  |         | response "?OTRV4"	|
| G^x			  |	    | G^y, m, m', c, c'	|
| m, m', c, c'	          |         |			|

Alice notifies Bob willingness to start a conversation

| Alice				| Server	| Bob			|
|-------------------------------|---------------|-----------------------|
| notify "        "		|		|			|
| 				|		| response "?OTRV4"	|
| G^x				|		| G^y, m, m', c, c'	|
| m, m', c, c'			|		|			|

#### Online conversation start with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. If this is the
case the protocol falls back to [OTR version 3 specification][2].

Note: OTR version 4 is the lastest version to support previous versions.

### Online conversation message exchange

### Online conversacion end

## Offline conversation <a name="conversation2"></a>

### Offline conversation start

#### Offline conversation start with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. Since previous
versions do not provide the ability to maintain an offline
conversations the starting process is dropped.

Note. OTR version 4 is the last version to support previous versions.

### Offline conversation message exchange

### Offline conversation end


[1]: http://www.paper.net/Unger/rsdake_spawn.pdf
[2]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
