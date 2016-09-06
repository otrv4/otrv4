# OTR version 4#

The following protocol aims to allow two people to maintain a conversation over a network in a way that comes as close as possible to a private person to person conversation - where no other entity can overhear what is being said, and the other party can't prove anything that was said - or even the fact that you talked. 

Security here means that both ends can verify at the begining of the
conversation the identity of the other end and the stablishment of a
trusted channel. Private here means that exchanged messages are hard
to be read, added, removed or modified by a hostile third party
listening to the conversation.

To ressemble a in person conversation means that both ends can deny to
have participated in said conversation or to have sent one or many of
the exchanged messages once the conversation is over.

## Assumptions ##

This protocol assumes there is an available network and an undelying
protocol which enables the exchange of messages.

## Exceptions ##

This protocol is not intended to enable group conversations.

## Overview ##

This protocol refers to the initiator of the conversation as Alice
and, refers to the receiver as Bob, in order to use the common 
terminology used in the cryptographic literature.

The messages exchanged between Alice and Bob are said to be
transported through a channel.

This conversation may happen while both Alice and Bob are online or,
when only Alice is online and Bob will receive messages posted for him
as soon as he gets online.

The initial connection state of both Alice and Bob might change while
the conversation is happening.

This conversation will take place over public infraestructure where
potential hostile intermediaries are present at different levels.

## Online Conversations ##

An online conversation happens when both Alice and Bob are
online. An online conversation provides both participants with the
following security properties:
* at conversation start
 * identity verification
* while exchanging messages
 * confidentiality
* after conversation is over
 * participation repudiability

Alice knows Bob is online because the underlying protocol is
able to answer questions about Bob's presence.

Alice then starts a conversation with Bob by sending a request that
Bob responds notifying he's ready to start and messages exchange
begins. Once all the desired messages have been sent and received any
of the ends can signal the other end the conversation has finished.

| Alice                       		| Server		| Bob					|
|---------------------------------|-----------|-------------|
| Requests for Bob's status   		| Bob is online		|					|
| Requests to start conversation 	|			| Responds ready to start		|
| Autenticates to Bob			|			| Autenticates to Alice			|
| Sends message				|			| Receives message			|
| Signals end of conversation		|			| Acknowledges end of conversation	|

### Online conversation start ###

To start a conversation Alice should send either a request to do so or
notify her willingness to start a conversation. Difference between
requesting to start a conversation is that a response is expected and
notifying willingness is that response is not expected but may come in
the future.

Both the request and notification of willingness include the OTR
versions Alice supports. The response should include the OTR version
Bob supports and that version will be used through the whole
conversation. Bob should choose the higher version he supports.

Once the conversation has started Alice and Bob will autenticate to
each other and setup a secure channel for the conversation to take
place. This process will use the deniable authenticated key exchange
mechanism RSDAKE defined by Neil Unger in his paper ["RSDAKE and SPAWN
paper"][1] which provide both Alice and Bob with the following security
properties:
* Participation deniability
* Message deniability
* ...

Once the exchange has finished bothe ends have a channel which
provides the following properties
* MitM resistence
* ...

Alice requests Bob to start a conversation

| Alice				            | Server	| Bob			          |
|-------------------------|---------|-------------------|
| request "?OTRV4,OTRV3"	|		      | response "?OTRV4"	|
| G^x				              |		      | G^y, m, m', c, c'	|
| m, m', c, c'			      |		      |			              |

Alice notifies Bob willingness to start a conversation

| Alice				| Server	| Bob			|
|-------------|---------|---------|
| notify "        "		|		|			|
| 				|		| response "?OTRV4"	|
| G^x				|		| G^y, m, m', c, c'	|
| m, m', c, c'			|		|			|

#### Online conversation start with older OTR version ####

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version four. If this is the
case the protocol falls back to [OTR version 3 specification][2].

Note. OTR version 4 is the last version to support previous versions.

### Online conversation message exchange ###

### Online conversacion end ###

## Offline conversation ##

### Offline conversation start ###

#### Offline conversation start with older OTR version ####

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version four. Since previous
versions do not provide the ability to maintain an offline
conversations the starting process is dropped.

Note. OTR version 4 is the last version to support previous versions.

### Offline conversation message exchange ###

### Offline conversacion end ###

## Transition from online conversation to offline conversation ##


[1]: http://www.paper.net/Unger/rsdake_spawn.pdf
[2]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
