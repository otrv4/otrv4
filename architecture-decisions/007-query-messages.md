## ADR 7: Query Messages

### Context

In OTRv3, "the semantics of the OTR Query Message are that Alice is requesting
that Bob starts an OTR conversation with her (if, of course, he is willing and
able to do so)".

A query message can be sent at any time during the protocol execution, have no
guarantee of being answered (a client that does not support any compatible OTR
version will simply ignore it), and is always answered by a compatible client
(to initiate a new AKE).

In OTRv3, query messages are used to:

  * **Start an OTR session**: if both participants are willing to use OTRv3,
  the query message causes both to start the AKE, and by its end both have the
  same D-H key and transition from `MSGSTATE_PLAINTEXT` to
  `MSGSTATE_ENCRYPTED`.

  * **Force a key rotation**: forward secrecy depends on
  advertising/acknowledging new D-H keys. The same key is reused until a
  message from the other peer is received (heartbeats are intended to address
  this issue). Because a new AKE behaves exactly like a normal key rotation,
  there is no loss of messages.

  * **Provide device mobility**: If Alice is in an OTR conversation with Bob,
  all she needs to do in order to continue the conversation in another device
  is to login to another device and send a new Query Message by choosing to
  "start an OTR conversation". Instance tags are another essential part of
  this.

We propose to use query messages in OTRv4 with the same format as OTRv3, but
with a slightly difference in the semantics:

* "Force a key rotation" use case is made unnecessary by virtue of OTRv4
  double ratchet.

* Query messages can be sent at any time but when the participant is already
  on `ENCRYPTED_MESSAGES`.

Allowing query messages to be sent on `ENCRYPTED_MESSAGES` causes a new DAKE
to be started while a conversation already exists. In this case, messages from
the previous conversation that arrive after the new DAKE starts may not be
decrypted, since each participant replaces their key material when engage on a
new DAKE.

### Decision

We will not change the DAKE to allow receiving late messages and decrypt them.

We will prevent query messages to be used to force a key rotation in OTRv4
by disallowing its sending on `ENCRYPTED_MESSAGES`.

We will not prevent receiving query messages on the same state, because it would
also prevent device mobility.

### Consequences

A participant is still able to receive a query message while on
`ENCRYPTED_MESSAGES` from a dishonest participant.

If the receiver starts a new DAKE, messages from the previous conversation
that start a new ratchet will fail to be verified and decrypted (the receiver
will need the DH private key from before the new DAKE).