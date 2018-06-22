## ADR 013: Multiple Query Messages

### Context

When a client has more than one version of OTR protocol allowed (v3 and v4) he can send multiple query messages each with a different protocol version.

Also a person could have more than one client active at the same time and these clients could answer the same query message multiple times.

### Decision

We decided that if a query message is sended to start a new DAKE it will set the running protocol version as the one which the query message brings. If a conversation was already started with some protocol version and suddenly a new query message with a different protocol version arrives the messages will now be encrypted using the protocol version of this message and any message encrypted with the previous decision of running version will be ignored.

### Consequences

Some messages could not be received succesfully due different protocol version.