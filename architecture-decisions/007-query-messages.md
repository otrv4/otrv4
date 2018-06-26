## ADR 7: Query Messages

### Context

In OTRv3, "the semantics of the OTR Query Message are that Alice is requesting
that Bob starts an OTR conversation with her (if, of course, he is willing and
able to do so)".

A query message can be sent at any time during the protocol execution, it will
have no guarantee of being answered (a client that does not support any
compatible OTR version will simply ignore it), and is always answered by a
compatible client (to initiate a new AKE).

In OTRv3, query messages are used to:

  * **Start an OTR session**: if both participants are willing to use OTRv3,
    the query message causes both to start the AKE, and when it is finished,
    both participants have the same D-H key and transition from
    `MSGSTATE_PLAINTEXT` to `MSGSTATE_ENCRYPTED`.

  * **Force a key rotation**: forward secrecy depends on
    advertising/acknowledging the new D-H keys. The same key is reused until a
    message from the other peer is received (heartbeats are intended to address
    this issue). Because a new AKE behaves exactly like a normal key rotation,
    there is no loss of messages.

  * **Provide client mobility**: If Alice is in an OTR conversation with Bob,
    all she needs to do in order to continue the conversation in another client
    is to login to another client and send a new Query Message by choosing to
    "start an OTR conversation". Instance tags are another essential part of
    this.

We propose to use query messages in OTRv4 with the same format as OTRv3, but
with a slightly difference in the semantics:

* "Force a key rotation" use case is made unnecessary by virtue of OTRv4's
  Double Ratchet Algorithm.
* Query messages can be sent at any time except when the participant is already
  in `ENCRYPTED_MESSAGES` state.

Allowing query messages to be sent on `ENCRYPTED_MESSAGES` causes a new DAKE
to be started while a conversation already exists. In this case, messages from
the previous conversation that arrive after the new DAKE starts may not be
decrypted, since each participant replaces their key material when engage on a
new DAKE.

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

We will prevent query messages to be used to force a key rotation in OTRv4 by
disallowing its sending in `ENCRYPTED_MESSAGES` state.

We will not prevent receiving query messages on the same state, because it would
also prevent client mobility.

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

### Example of multiple query messages sent

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

A participant is still able to receive a query message while on
`ENCRYPTED_MESSAGES` from a dishonest participant.

If the receiver starts a new DAKE, messages from the previous conversation
that start a new ratchet will fail to be verified and decrypted (the receiver
will need the DH private key from before the new DAKE).

Some messages will not be received or be able to be decrypted due to the change
on the protocol versions.

A conversation started with and Identity message, in the OTRv4-interactive-only
or OTRv4-standalone mode, is not able to handle plaintext messages and,
therefore, is unable to change the running version with a new query message.

As always, the protocol version 3 will not be able to receive messages from a
non-interactive DAKE, even if previously it was in version 4.