## ADR 8: Interactive DAKE

### Context

OTRv3 Authenticated Key Exchange (a variant of the SIGMA protocol) provides
partial deniability properties. A participant in a conversation is able to
reuse ephemeral keys signed by the other party in forged transcripts, and,
thereby provide partial participation deniability. OTRv3 also used the Socialist
Millionaires Protocol to prevent identity misbinding attacks that violate
participant consistency [\[1\]](#references).

The security of OTRv4 can be improved by using Deniable Authenticated Key
Exchanges (DAKE) as part of the protocol. This allows both parties to
deny having participated in the conversation or having sent a message in a
conversation when faced both with an offline or online judge. A DAKE is strongly
deniable when its transcripts retain deniability even when long term key
material is compromised, and when an outside party tries to collude one
participant in order to reveal information.

We choose to implement both interactive and non-interactive DAKEs. This document
discusses the first.

### Decision

We chose to use the DAKEZ protocol from the paper "Improved Techniques for
Implementing Strongly Deniable Authenticated Key Exchanges"
[\[2\]](#references). DAKEZ is the most efficient DAKE out of Nik Unger and Ian
Goldberg's research since it does not use Dual Receiver Encryption and digital
signatures like RSDAKE. Instead, it uses a signature non-interactive zero
knowledge proof of knowledge (`RSig`) for the authentication. It also uses a
shared session state (`phi`) variable that guards against misbinding of
context.

Due to the usage of the Double Ratchet Algorithm in the protocol, a correct way
for initializing it after the interactive DAKE must be taken into consideration.
To preserve the security proofs of the DAKE [\[2\]](#references), initial
ephemeral keys (that are not used for the Ring Signature or the derivation
of the first Mixed Shared Secret) are used. These keys are attached to the first
two interactive DAKE messages (the Identity message and the Auth-R message).
These ratcheting ephemeral public keys should be included in the "Phi" value.

### Consequences

Supporting both an interactive and a non-interactive DAKE in OTRv4 raises the
complexity of the whole protocol.

Choosing DAKEZ for the interactive DAKE maximizes the deniability properties for
interactive conversations.

### References

1. Alexander, C. and Goldberg, I. (2007). *Improved User Authentication in
   Off-The-Record Messaging*, Waterloo, Canada: University of
   Waterloo. Available at:
   https://webencrypt.org/otr/attachment/impauth.pdf
2. Goldberg, I. and Unger, N. (2016). *Improved Strongly Deniable Authenticated
   Key Exchanges for Secure Messaging*, Waterloo, Canada: University of
   Waterloo. Available at:
   http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf