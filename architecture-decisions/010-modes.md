## ADR 10: OTRv4 Modes

### Context

OTRv4 is a protocol that aims to:

1. Be an alternative to current messaging applications that work in synchronous
   and asynchronous messaging environments.
2. Be a comprehensive and up-to-date specification: it updates cryptographic
   primitives and increase the security level of the whole protocol to 224 bits.
3. Provide better deniability properties.
4. Be compatible with OTRv3 and be useful for instant messaging protocols
   (e.g. XMPP).

In order to be an alternative to current messaging applications and to be
compatible with OTRv3, OTRv4 protocol must define three modes in which it can be
implemented: a only OTRv4 mode and a OTRv3-compatible mode. These are the three
modes enforced by the protocol, but, it must be taken into account, that OTRv4
can and may be also implemented in other modes.

### Decision

To attain all of the purposes of OTRv4, the specification can work in three
modes:

1. OTRv4-standalone mode: an always encrypted mode. This mode will not know how
   to handle any kind of plaintext message, including query messages and
   whitespace tags.
2. OTRv3-compatible-mode: a mode with backwards compatibility with OTRv3.
   This mode will know, therefore, how to handle plaintext messages, including
   query messages and whitespace tags.
3. OTRv4-interactive-only-mode: a always encrypted mode that provides higher
   deniability properties when compared to the previous two modes. It only
   supports interactive conversations.

### Consequences

As a result, OTRv4' state machine will need to know the mode is working on when
initialized. It will also need to take this mode into account every time it
makes a decision on how to transition from every state. This increases the
complexity of the specification and implementation.

Furthermore, "OTRv4-standalone" mode will only support version 4 of OTR. The
Client Profile, therefore will only allow the 1-byte version string "4". It will
also not allow the Transitional Signature parameter on the same Client Profile.

In addition to only supporting the version 4 of OTR (and imposing the same
restrictions to the Client Profile as the "OTRv4-standalone" mode), the
"OTRv4 interactive-only" mode will only support the interactive DAKE. This mode
will not handle or generate any Prekey Profile or prekey messages, nor implement
a Prekey Sever, not retrieve prekey ensembles.

It should be taken into account, also, that some clients might implement
different modes when talking with each other. In those cases:

* If a client implements "OTRv4-standalone" mode or "OTRv4-interactive-only"
  mode and a request for an OTRv3 conversation arrives, reject this request.
* If a client implements "OTRv4-interactive-only" mode and a request for an
  offline conversation arrives, reject this request.
