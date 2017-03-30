## ADR 8: DAKE

### Context

OTRv3 Authenticated Key Exchange (AKE) protocol lacks strong deniability
properties: partial participation deniability and full message deniability.

We believe the security of OTRv4 can be improved by employing a Deniable
Authenticated Key Exchange (DAKE) protocol.

The paper "Deniable Key Exchanges for Secure Messaging" [1] and
"Improved Techniques for Implementing Strongly Deniable Authenticated Key
Exchanges" [2] mentions a few DAKES and their message and participation
deniability properties in regard to an online and offline judge:

- RSDAKE:
- Spawn * :
  - non-interactive: NO online deniability with respect to R simulating I.
  - interactive: online deniability for both parties. Security weakness
    (sections 3.8.5 and 3.8.6 of paper 1).
- QuickSpawn: non-interactive that intentionally sacrifices online deniability
  for R for simplicity.

TODO: Improve the summary of properties.

### Decision

We choose to use Spawn because:

- We want to support non-interactive AKE, ideally in OTRv4.
- We want to reduce complexity of implementing OTRv4 by ideally having the same
  DAKE for both interactive and non-interactive settings.

### Consequences

We will need to implement a Cramer-Shoup cryptosystem on Ed448 plus
Dual-Receiver Encryption (DRE) and NIZKPK.
The resulting messages are not as efficient as other DAKES, but this hasn't
been a problem so far.

### References

1 - https://uwspace.uwaterloo.ca/handle/10012/9406
2 - http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf