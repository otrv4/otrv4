# Off-the-Record Messaging Protocol version 4 - DRAFT

(add in specific places so it's not spread all over:
- news
- algorithm choices)

This document describes version 4 of the Off-the-Record Messaging protocol. The main changes over version 3 include:
  * Online and offline messaging
  * Stronger deniability
  * ...

## High level overview

## Security properties

## Compatibility with prior versions


## Protocol specification
(We merged the high level overview and the details of the protocol sections to make this more linear)

### Diffie-Hellman Group

### OTR Data types
  * Bytes
  * Shorts
  * Ints
  * Multi-precision integers
  * Opaque variable-length data
  * ...

### Public keys, signatures, and fingerprints
  * Serialization
  * Deserialization

### Instance Tags
  * Valid/invalid tags
  * Serialization
  * Deserialization

### Requesting an OTR conversation

### Authenticated Key Exchange (AKE)
  * AKE message type specification
  * Interactive
    * OTR Query Messages
    * Tagged plaintext messages
  * Non-Interactive

### Client Key Management
  * Long-term identity keys
  * Computing prekeys

### Role of Central Server
  * Prekey management for non-interactive AKE

(if this is not a mandatory part of OTR maybe this should be in a separate appendix)

### Protocol state machine
  * Message state
  * Authentication state
  * Policies
  * State transitions

### Exchanging data
  * Data message type specification
  * Deriving shared session keys from AKE
    * Axolotl double ratcheting
  * Extra symmetric key

### OTR Error Messages
  * Reacting to receiving an error message
  * Encoding

### Socialist Millionaires' Protocol (SMP)
  * Secret information
  * SMP state machine

### Fragmentation
  * Transmitting fragments
  * Receiving fragments


