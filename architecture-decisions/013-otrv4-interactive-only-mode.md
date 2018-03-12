## ADR 13: "OTRv4 interactive-only" mode

### Context

ADR#010 defines the need for specifying alternative modes for the OTR protocol
version 4.

One of this modes is the 'OTRv4-interactive-only-mode', an always encrypted mode
that provides higher deniability properties when compared with the other modes.
It only supports interactive conversations.

This mode might work on the same kind of applications and scenarios, as the ones
defined in ADR#011. The DAKE is restricted to its interactive version.

### Decision

A 'OTRv4 only-interactive' mode will only support version 4 of OTR. The User
Profile, therefore will only allow the 1-byte version string "4". It will also
not allow the Transitional Signature parameter on the same profile.

By always requiring encryption, this mode may encourage long-lived sessions.
The section "Session expiration" of OTRv4 protocol specification outlines how to
mitigate the risks of long-lived sessions. For this reason, TLVs type 1
(Disconnected) are necessary in this mode.

Even though there is no need to prefix OTR messages with "?OTR:", since the
protocol only handles OTR messages, this mode does not modify this encoding
for convenience.

### Consequences

Same as ADR #011, and also the User Profile should not have a Public Shared
Prekey (and it should probably be moved to the end of the User Profile data
structure).

This mode achieves different security properties as the ones described in the
[security properties](../otrv4.md#security-properties) section, as it does
not achieve the security properties given by a non-interactive DAKE. Therefore,
it provides offline and online (participation) deniability for both
participants.
