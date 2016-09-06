# Some thougths and questions

- we should aim for a ROM level security of primitives
- security level
    - either 256 bits classically
    - or 128 bits quantum insurance
- DAKE: Spawn, Quickspawn or RSDAKE
    - Quickspawn for noninteractive and RSDAKE for interactive, if we can make it work
- Specify prekeys somewhere
- Ratcheting: Axolotl double ratcheting
- Updated primitives
    - AES-256
    - SHA3-256
- Protection agains version rollback
- Do we need to create a version specifier in the fragments, or can we get away without it?
- Is it possible to mix in something like ntru in the DAKE to get some PQ?
- Either Curve25519 or 448 depending on what security level we want

## Questions

- Should we use 25519 or 448?
- Is it really possible to use 25519 for Cramer Shoup - none of the implementations of curve25519 or ed25519 seems to expose point addition
- What about "super" encryption? "2048-bit mod p Diffie-Hellman" around the outside
