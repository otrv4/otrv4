## ADR 8: Interactive DAKE

### Context

OTRv3 Authenticated Key Exchange (AKE) protocol does not have any deniability
properties because cryptographic signatures are created as a conversation takes
place.

We believe the security of OTRv4 can be improved by employing a Deniable
Authenticated Key Exchange (DAKE) protocol. This would allow both parties to
deny having participated in the conversation.  A DAKE is strongly deniable when
its transcripts retain deniability even when long term key material has been
compromised and when an outside party tries to collude one participant in order
to reveal that a particular person is talking with them.

### Decision

We chose to use the DAKEZ protocol from the paper "Improved Techniques for
Implementing Strongly Deniable Authenticated Key Exchanges"
[\[1\]](#references). DAKEZ is the most efficient DAKE out of Nik Unger and Ian
Goldberg's research since it does not use Dual Receiver Encryption and digital
signatures like RSDAKE. Instead, it uses a signature non-interactive zero
knowledge proof of knowledge (SNIZKPK) for the authentication. It also has a
shared session state (`phi`) variable that guards against misbinding of the
context.

### Consequences

Supporting both an interactive and a non-interactive DAKE in OTRv4 raises its
complexity. But this was done to maximize the deniability properties for
interactive conversations.

### References
1. http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf "N. Unger, I.
   Goldberg: Improved Techniques for Implementing Strongly Deniable
   Authenticated Key Exchanges"