## ADR 013: Multiple Query Messages

### Context

When a client has more than one version of OTR protocol allowed (v3 and v4) he can send multiple query messages each with a different protocol version.

Also a person could have more than one client active at the same time and these clients could answer the same query message multiple times.

### Decision

We decided that if a query message is sended to start a new DAKE it will set the running protocol version as the one which the query message brings. If a conversation was already started with some protocol version and suddenly a new query message with a different protocol version arrives the messages will now be encrypted using the protocol version of this message and any message encrypted with the previous decision of running version will be ignored.

### Example 1
Alice wants to talk with Bob, both have clients with support to protocol version 3 and 4.

Alice starts the conversation and send a query message requesting that the conversation occurs with version 4 of the protocol and Bob's client accept it and the conversation starts with protocol running version equal to 4.

After a while Alice client had a bug and the conversation stops from her side without send the finish message to Bob. To keep the conversation she opens another client but this one support only the protocol version 3, so it sends a new query message with version 3 of the protocol, Bob will receive this message and change the protocol running version in his client.

All the Bob's message with protocol running version 4 sent to Alice during the period of the first client bug will be lost.

### Consequences

Some messages could not be received succesfully due different protocol version.