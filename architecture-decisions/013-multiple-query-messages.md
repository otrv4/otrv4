## ADR 013: Multiple Query Messages

### Context

When a client has more than one version of OTR protocol allowed (v3 and v4), it
can send several query messages each one with a different protocol version.

If Alice wishes to communicate to Bob that she would like to use OTR, she sends
a message containing the string "?OTRv" followed by an indication of what
versions of OTR she is willing to use with Bob. The versions she is willing to
use, whether she can set this on a global level or per-correspondent basis, is
up to the implementer. However, enabling users to choose whether they want to
allow or disallow a version is required, as OTR clients can set different
policies for different correspondents.

Furthermore, a user can have more than one client active at the same time. These
clients could answer to the same query message multiple times.

### Decision

A query message will set the running version that the protocol is started with.
If a query message, for example, only contains the byte identifier "4", then
an instance of OTRv4 will be started. If the byte identifier contains more than
one versions (version "4" and 3"), the highest version will be chosen and an
instance of OTR of that version will begin.

If a conversation was already started with a protocol version and a new query
message with a different protocol version arrives (while being in
`ENCRYPTED_MESSAGES` state), the conversation will be set to this new version.
Any previous messages sent prior to the arrival of the new query message will be
undecryptable.

### Example

Alice wants to talk with Bob. Their clients respectively support version 3 and 4
of the OTR protocol.

Alice starts a conversation and sends a query message with version 4 of the
protocol. Bob accepts this query message and the conversation starts with
version 4.

After a while, Alice's client has a bug and the conversation stops from her side
without sending the TLV type 1 Disconnected. To stay in the conversation, she
opens another client that only supports version 3 of the protocol. She sends
a new query message that advertises version 3. Bob receives this message and
changes the protocol running version of his client.

All Bob's messages sent prior to the change of the running version, will be lost
and undecryptable.

### Consequences

Some messages will not be received or be able to be decrypted due to the change
on the protocol versions.

A conversation started with and Identity message, in the OTRv4-interactive-only
or OTRv4-standalone mode, is not able to handle plaintext messages and,
therefore, is unable to change the running version with a new query message.

As always, the protocol version 3 will not be able to receive messages from a
non-interactive DAKE, even if previously it was in version 4.