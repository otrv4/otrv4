# OTR version 4

The following messaging protocol provides way for two people to have a conversation over a network
in a way that provides the same security as a private in person conversation, where no external party
can overhear what is being said, and no one (not even the conversation participants) can prove what
was said, or even that the two participants spoke to each other at all.

## Table of Contents

1. [Main Changes over Version 3](#main-changes-over-version-3)
2. [High Level Overview](#high-level-overview)
3. [Assumptions](#assumptions)
4. [Security Properties](#security-properties)
5. [OTR Conversation Initialization](#otr-conversation-initialization)
  1. [Version Advertisement](#version-advertisement)
  2. [Deniable Authenticated Key Exchange (DAKE)](#deniable-authenticated-key-exchange-dake)
6. [Requesting conversation with older OTR version](#requesting-conversation-with-older-otr-version)
7. [Data exchange](#data-exchange)
8. [Socialist Millionaires' Protocol (SMP)](#socialist-millionaires-protocol-smp)
9. [The protocol state machine](#the-protocol-state-machine)
10. Appendices
  1. ROM DRE
  2. ROM Authentication

## Main Changes over Version 3

TODO: Write this section when we have fleshed out the other sections of the spec and decide what is important to highlight here

## High Level Overview

Off The Record messaging (OTR) is a messaging protocol that achieves forward-secrecy
and deniability.

The high level flow of this protocol will be:

    Alice                                            Bob
    --------------------------------------------------------------------------------
    Request OTR conversation          ------------->
                                      <-------------  OTR v4 is supported
    Establish Conversation with DAKE  <------------>  Establish Conversation with DAKE
    Exchange Data Messages            <------------>  Exchange Data Messages

TODO: Should we mention the protocol API? This was confusing to me when I first implemented OTR. Example:

OTR works on top of an existing messaging protocol, like XMPP, with capabilities of sending and receiving messages to and from a peer. A messaging client which does not support OTR will present received messages to the user and will send messages typed by the user to the other peer, like the following diagram:

```
# Receiving messages
while received = messaging.receive()
  client.display(received)

# Sending messages
while to_send = client.message_to_send()
  messaging.send(to_send)
```

A messaging client which supports OTR will forward messages to the OTR implementation before presenting received messages to the user and before sending messages to the other peer, like the following diagram:

```
# Receiving messages
while received = messaging.receive():
  to_send, received = otr.receive(received)
  client.display(received)

  for each message in to_send:
    messaging.send(message)

# Sending messages
while to_send = client.message_to_send()
  for each message in otr.send(to_send):
    messaging.send(message)

```

## Assumptions

Both participants are online at the start of a conversation.

Messages in a conversation will be exchanged over an insecure channel, where an attacker can eavesdrop or interfere with the messages.

We assume a network model which provides in-order delivery of messages, but some messages may not be delivered.

## Security Properties

In an off the record conversation, both sides can verify the identity of the other participant
(but cannot transfer this knowledge to a third party). Participants can converse with the assurance
that their conversation will not be read or modified by a hostile third party.

To resemble an in-person conversation means that both ends can deny that they have participated in
said conversation. Both ends can also deny having sent one or many of the exchanged messages in the conversation.

### DAKE properties
 * Mutual authentication
 * Participation repudiation for both initiator and receiver

### Conversation properties
 * Confidentiality
 * Integrity
 * Forward secrecy
 * Message deniability

Threats that an OTR conversation does not mitigate:
* An active attacker may perform a Denial of Service attack but not learn the contents of messages.

## Preliminaries

### Notation

Integer variables are in lower case (x, y). Points and other variables are in upper case (P, Q).

Addition and subtraction of elliptic curve points A and B is A + B and A - B. Scalar multiplication of an integer a with an elliptic curve point B yields a new point C = a*B.

The concatenation of byte sequences x and P is x || P. In this case, x and P represent a fixed-length byte sequence encoding the respective values. See section "Data types" for encoding and decoding details.

### Elliptic Curve Parameters

OTRv4 uses the Curve448 elliptic curve specified in (add reference), which defines the following parameters:

```
Base point (B)
  (x=117812161263436946737282484343310064665180535357016373416879082147939404277809514858788439644911793978499419995990477371552926308078495, y=19)

Cofactor (c)
  4

Identity point (I)
  (x=0, y=1)

Field prime (p)
  2448 - 2224 - 1

Order of base point (q) [prime; q < p; q*B = I]
  2446 - 13818066809895115352007386748515426880336692474882178609894547503885

Number of bits in p (|p|)
  448 bits

Number of bits in q (|q|)
  446 bits
```

An integer modulo p is a "field element". An integer modulo q is a a "scalar" (also a value on Z_q), and is considered a MPI for encoding and decoding purposes.

TODO: If we use u-coordinate for encoding according to XEdDSA, do we need to consider the sign byte when hashing to a field element (the first byte)? Simply clearing seems to be the simplest solution.

### Data types

    Bytes (BYTE):
      1 byte unsigned value

    Shorts (SHORT):
      2 byte unsigned value, big-endian

    Ints (INT):
      4 byte unsigned value, big-endian

    Multi-precision integers (MPI):
      4 byte unsigned len, big-endian
      len byte unsigned value, big-endian
      (MPIs must use the minimum-length encoding; i.e. no leading 0x00 bytes. This is important when calculating public key fingerprints.)

    ED448 points (POINT):
      TODO: We need to choose a point serialization format for ed448 points

    Opaque variable-length data (DATA):
      4 byte unsigned len, big-endian
      len byte data


### Public keys and fingerprints

OTR public authentication Cramer-Shoup key (PUBKEY):

    Pubkey type (SHORT)
      Cramer-Shoup public keys have type 0x0010

    c (MPI)
    d (MPI)
    h (MPI)
      (c, d, h) are the Cramer-Shoup public key parameters

OTR public keys have fingerprints, which are hex strings that serve as identifiers for the public key. The fingerprint is calculated by taking the SHA-1 hash of the byte-level representation of the public key.

## OTR Conversation Initialization

OTR4 conversations are established by an deniable authenticated key exchange
protocol (DAKE).

There are two ways Alice can inform Bob that she is willing to use the OTR
protocol to speak with him in an interactive setting: by sending him the OTR
Query Message, or by including a special "tag" consisting of whitespace
characters in one of her messages to him. Each method also includes a way for
Alice to communicate to Bob which versions of the OTR protocol she is willing
to speak with him.

The semantics of the interactive OTR Query Message are that Alice is requesting
that Bob start an OTR conversation with her (if he is willing and able to do
so). The semantics of the whitespace tag are that Alice is opportunistically
indicating to Bob that she is willing to have an OTR conversation with him.

For example, if Bob has a policy of "only use OTR when it's explicitly
requested", then he would start an OTR conversation upon receiving an OTR
Query Message, but would not upon receiving the whitespace tag.

Both the OTR Query Message and Whitespace tag include the OTR versions Alice
supports and is willing to use.

Once Bob has decided to start the conversation in response to Alice's request,
he will initiate an interactive, deniable, authenticated key exchange DAKE.

### Version Advertisement

OTR4 introduces mandatory version advertisement to resist version rollback. In
both cases, the receiving party will include in the DAKE authenticated
information about what versions they received, and the initializing party will
verify that the versions are correct.

### Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the Deniable Authenticated Key Exchange, which
is a way for two parties to mutually agree upon a shared key and authenticate one
another while also allowing a level of participation deniability.

This process is based on the Spawn protocol[1], which utilizes Dual Receiver
Encryption (DRE) and a NIZKPK for authentication (Auth).

Alice long-term Cramer-Shoup key-pair is `SKa = (x1a, x2a, y1a, y2a, za)` and `PKa = (Ca, Da, Ha)`.  
Bob long-term Cramer-Shoup key-pair is `SKb = (x1b, x2b, y1b, y2b, zb)` and `PKb = (Cb, Db, Hb)`.  
Both key pairs are generated with `DRGen()`.  

#### Overview

```
Alice                                          Bob
---------------------------------------------------
Query Message or Whitespace Tag ------->
                                <------- Prekey (ψ1)
                  DRE-Auth (ψ2) ------->
                                         Verify & Decrypt (ψ2)
```

**Alice:**

1. Generates an ephemeral private key `i` and a public key `G1*i`.
2. Sends Bob `ψ1 = ("I", G1*i)`.


**Bob:**

1. Generates an ephemeral private key `r` and public key `G1*r`.
2. Computes `γ = DREnc(PKb, PKa, m)`, being `m = "I" || "R" || G1*i || G1*r`.
3. Computes `σ = Auth(Hb, zb, {Ha, G1*i}, "I" || "R" || G1*i || γ)`.
4. Computes `k = (G1*i) * r` and securely erase `r`.
5. Sends Alice `ψ2 = ("R", γ, σ)`.

**Alice:**

1. Verifies `Verif({Ha, Hb, G1*i}, σ, “I” || “R” || G1*i || γ)`.
2. Decrypts `m = DRDec(PKa, PKb, SKa, γ)`.
3. Verifies the following properties of the decrypted message `m`:
  1. The message is of the correct form (e.g., the fields are of the expected length)
  2. Alice's identifier is the first one listed
  3. Bob's identifier is the second one listed, and it matches the identifier transmitted outside of the ciphertext
4. Computes `K = G1*r*i` and securely erase `i`.


**TODO: the following is about version advertisement and may need to be moved.**

The Query Message or Whitespace Tag will include the versions supported by
Alice.

```
ψ1 = { "B", pubB, g^b, Bobs_versions }
```

"B" is Bob's account identifier. Bobs_versions are the versions supported
by Bob.

```
ψ2 = { "A", pubA, γ, σ } where
γ = DRE(pubB, pubA, "B" || g^b || "A" || g^a)
σ = Auth(hA, zA, {hB, hA, g^b}, "B" || "A" || g^b || Alices_versions || Bobs_versions || γ )
```

"A" is Alice's account identifier.

After receiving ψ2, Alice authenticates σ and decrypts γ. She then verifies the
versions that were sent by both parties. If Bob did not receive the Query
Message or Whitespace Tag sent by Alice or if Bob is using a version of OTR that
is not the highest preferable version, this check will fail. If all checks pass,
then Alice and Bob have a shared secret with which to initialize their data
messages exchange session.

**END OF TODO**

#### Pre-key message

This is the first message of the DAKE. Bob sends it to Alice to commit to a choice of D-H key.

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x01.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient. For a commit message this will often be 0, since the other party may not have identified their instance tag yet.
Initiator's identifier (DATA)
  This can be the fingerprint or something else.
g1*i (POINT)
  - Choose a random value i (446 bits) mod l
  - Encode g1*i as the MPI field.
```

This message has length:

```
LEN(Header) + LEN(Identifier) + LEN(Point)
  = 13 + 184 + 56 = 253 bytes  

LEN(Header) = 4 + 1 + 4 + 4 = 13 bytes  

If Identifier is the public key,  
  Len(Identifier) = 4 + 3*Len(MPI) = 4 + 3*(4 + 56) = 184 bytes
```

#### DRE-Auth message

This is the second message of the DAKE. Alice sends it to Bob to commit to a choice of her D-H key and acknowledgement of Bob's D-H key.
Dual-receiver-encryption is used to encrypt the public key and Zero-knowledge-proof-of-knowledge is used to authenticate the message.

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x02.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient. For a commit message this will often be 0, since the other party may not have identified their instance tag yet.
Receiver's identifier (DATA)
  This can be the fingerprint or something else.
γ (DATA)
  - Choose a random value r (446 bits) mod l
  - Compute g1*r
  - Generate m = "I" || "R" || g1*i || g1*r
  - Compute (u11, u21, e1, v1, u12, u22, e2, v2, L, n1, n2, nonce, φ) = DREnc(pubA, pubB, m)
  - Encode each returned value individually and concatenate all of them as γ.
  - Encode the resulting value γ as the DATA field.

  DREnc values are encoded as follows:
  - u11 (POINT)
  - u21 (POINT)
  - e1 (POINT)
  - v1 (POINT)
  - u12 (POINT)
  - u22 (POINT)
  - e2 (POINT)
  - v2 (POINT)
  - L (MPI)
  - n1 (MPI)
  - n2 (MPI)
  - nonce (DATA)
  - φ (DATA)
σ (DATA)
  - Compute (c1, r1, c2, r2, c3, r3) = Auth(hB, zB, {hA, g1*i}, "I" || "R" || g1*i || γ)
  - Encode each returned value individually and concatenate all of them as σ.
  - Encode the resulting value σ as the DATA field.

  Auth values are encoded as follows:
  - c1 (MPI)
  - r1 (MPI)
  - c2 (MPI)
  - r2 (MPI)
  - c3 (MPI)
  - r3 (MPI)
```

This message has length:

```
LEN(HEADER) + LEN(Identifier) + LEN(γ) + LEN(σ)
  = 13 + 184 + 1164 + 360 = 1721 bytes.

LEN(γ) = 8 * LEN(Point) + 3 * LEN(MPI) + LEN(nonce) + LEN(φ) = 1164 bytes
  8*56 + 3*60 + 24 + 512 = 1164 bytes
  LEN(φ) = 32 + LEN(m) = 32 + 184 + 184 + 56 + 56 = 512 bytes  

LEN(σ) = 6 * LEN(MPI) = 360 bytes
```

## Requesting conversation with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. If this is the
case the protocol falls back to [OTR version 3 specification][2].

Note: OTR version 4 is the latest version to support previous versions.

## Data Exchange

This section describes how each participant will use the Double Ratchet
algorithm to exchange data initialized with the shared secret established in the DAKE.

To perform a new ratchet means to rotate the root key and chain key to use a new D-H key pair.
A ratchet represents a group of data messages which are encrypted by keys derived from the
same D-H key pair.

A message with an empty human-readable part (the plaintext is of zero length, or starts
with a NUL) is a "heartbeat" packet, and should not be displayed to the user. (But it's
still useful to effect key rotations.)

```
Alice                                                                           Bob
-----------------------------------------------------------------------------------
Initialize root key, chain keys                        Initialize root key, chain keys
Generate DH, pubDHa, privDHa                           Generate DH, pubDHb, privDHb
Send data message 0_0            -------------------->
Send data message 0_1            -------------------->


                                                       Receive data message 0_0
                                                       Recover receiving chain key 0_0
                                                       Derive Enc-key & MAC-key
                                                       Verify MAC, Decrypt message 0_0

                                                       Receive data message 0_1
                                                       Recover receiving chain key 1_1
                                                       Derive Enc-key & MAC-key
                                                       Verify MAC, Decrypt message 0_1

                                                       Perform a new ratchet
                                 <-------------------- Send data message 1_0
                                 <-------------------- Send data message 1_1

Receive data message 1_0
Recover receiving chain key 1_0
Derive Enc-key & MAC-key
Verify MAC, Decrypt message 1_0

Receive data message 1_1
Recover receiving chain key 1_1
Derive Enc-key & MAC-key
Verify MAC, Decrypt message 1_1
```

### Key management

#### For each correspondent, keep track of:

ratchet_flag  
i as Current ratchet id  
j as Previous sent message id  
k as Previous received message id

R as Root key  
Cs_j as Sending Chain key  
Cr_k as Receiving Chain key  
our_dh, their_dh

#### Initialization of Double Ratchet

After the DAKE is finished, both side will initialize the first group of root key (R0) and chain key
(C0_0) deriving from SharedSecret.

How to derive the first ratchet (R0):
```
R0, Ca0_0, Cb0_0 = KDF(SharedSecret)
```

- For the Initiator:
  - Set ratchet_flag as true
  - Set their_dh as g^b from the DAKE
  - She will perform a new ratchet once again when sending her first message
- For the Receiver:
  - Set ratchet_flag as false

TODO: What is `g`?

Both side will compare their public keys to choose a chain key for sending and receiving:

- Initiator (and similarly for Receiver) determines if she is the "low" end or the "high" end of this Data Message.
If Initiator's ephemeral D-H public key is numerically greater than Receiver's public key, then she is the "high" end.
Otherwise, she is the "low" end.
- Initiator selects the chain keys for sending and receiving:
  - If she is the "high" end, use Ca0_0 as the sending chain key, Cb0_0 as the receiving chain key.
  - If she is the "low" end, use Cb0_0 as the sending chain key, Ca0_0 as the receiving chain key.

#### When you send a Data Message:

1. If ratchet_flag is true, first ratchet:
    1. Derive new pair of R, Cs_0, Cr_0 from private part of our_dh and public part of their_dh.
    2. Securely forget our_dh, increment i, and set our_dh to a new DH key pair which you generate.
    3. Set ratchet_flag to false.

    ```
    our_dh = {pubDHa, privDHa} = generateECDH()

    R1 = SHA3(0x00 || R0 || ECDH(our_dh, their_dh))
    Ca1_0 = SHA3(0x01 || R0 || ECDH(our_dh, their_dh))
    Cb1_0 = SHA3(0x02 || R0 || ECDH(our_dh, their_dh))

    i = i+1
    ratchet_flag = false
    ```

2. Set the ratchet_id to i.
3. Set the DH pubkey in the Data message to the public part of our_dh.
4. Increment j, and use Cs_j to derive the Enc and MAC key.

    ```
    MKenc = SHA3(0x00 || Cs_j)
    MKmac = SHA3(0x01 || Cs_j)
    ```

5. Use the Enc key to encrypt the message, and the MAC key to calculate its mactag.

    ```
    ciphertext = Enc(MKenc, m)
    msg = ciphertext || Mac(MKmac, ciphertext)
    ```

6. Derive the next sending Chain Key

    ```
    Cs_j+1 = SHA3(Cs_j)
    ```

#### When you receive a Data Message:

1. If the ratchet_id is not larger than i, reject the message.
2. If the message_id is not larger than k, reject the message.
3. Use the message_id to compute the Receiving Chain key Cr_message_id.

    ```
    Cr_message_id = SHA3(Cr_message_id-1)
    ```

4. Use the Cr_message_id to derive the Enc and MAC key.

    ```
    MKenc = SHA3(0x00 || Cs_j)
    MKmac = SHA3(0x01 || Cs_j)
    ```

5. Use the MAC key to verify the mactag on the message. If it does not verify, reject the message.

    ```
    ciphertext, mactag = msg
    verify(mactag == Mac(MKmac, m))
    ```

6. Decrypt the message using the Enc key.

    ```
    m = Dec(MKenc, ciphertext)
    ```

7. Set k to message_id, Set ratchet_flag to true, Set their_dh as pubDHRs of the message.

    ```
    k = message_id
    ratchet_flag = true
    ```

### Revealing MAC Keys

We reveal old MAC keys to provide forgeability of messages. Old MAC keys are keys for messages that have already been received, therefore will no longer be used to verify the authenticity of a message.

MAC keys are revealed with data messages. They are also revealed with heartbeat messages (data messages that encode a plaintext of zero length) if the receiver has not sent a message in a configurable amount of time.

A receiver can reveal a MAC key in the following case:

- the receiver has received a message and has verified the message's authenticity
- the receiver has discarded associated message keys
- the receiver has discarded the chain key that can be used to compute the message keys (chain keys from previous ratchets might be stored to compute message keys for skipped or delayed messages)

### Packet format

```
Protocol version (SHORT)

    The version number of this protocol is 0x0004.

Message type (BYTE)

    The Data Message has type 0x03.

Sender Instance tag (INT)

    The instance tag of the person sending this message.

Receiver Instance tag (INT)

    The instance tag of the intended recipient.

Flags (BYTE)

    The bitwise-OR of the flags for this message. Usually you should set this to 0x00. The only currently defined flag is:

    IGNORE_UNREADABLE (0x01)

        If you receive a Data Message with this flag set, and you are unable to decrypt the message or verify
        the MAC (because, for example, you don't have the right keys), just ignore the message instead of producing
        some kind of error or notification to the user.

Ratchet id i (INT)

    Must be strictly greater than 0, and increment by 1 with each ratchet

Message id Ns (INT)
    Must be strictly greater than 0, and increment by 1 with each message

pubDHRs (MPI)

    The *next* ratchet [i.e. sender_keyid+1] public key for the sender

Encrypted message (DATA)

    Using the appropriate encryption key (see below) derived from the sender's and recipient's DH public keys
    (with the keyids given in this message), perform Xsalsa encryption of the message.
    The initial counter is a 16-byte value whose first 8 bytes are the above "top half of counter init" value,
    and whose last 8 bytes are all 0x00.
    Note that counter mode does not change the length of the message, so no message padding needs to be done.
    If you *want* to do message padding (to disguise the length of your message), use the above TLV of type 0.

Authenticator (MAC)

    The SHA3 MAC, using the appropriate MAC key (see below) of everything from the Protocol version to the end
    of the encrypted message

Old MAC keys to be revealed (DATA)

    See "Revealing MAC Keys"
```

## Socialist Millionaires Protocol (SMP)

TODO: This may need to be moved.  
TODO: Define TLV  
TODO: Update to new notation: integers and points.  

The Socialist Millionaires' Protocol allows two parties with secret information x and y respectively to check whether (x==y) without revealing any additional information about the secrets. The protocol used by OTR is based on the work of Boudot, Schoenmakers and Traore (2001). A full justification for its use in OTR is made by Alexander and Goldberg, in a paper published in 2007. The following is a technical account of what is transmitted during the course of the protocol.

While data messages are being exchanged, either Alice or Bob may run SMP to detect impersonation or man-in-the-middle attacks.

We reuse the previously defined generator in Cramer-Shoup of DRE:

`G = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160)`

Assuming that Alice begins the exchange:

**Alice:**

* Picks random values `a2` and `a3`.
* Sends Bob `G2a = G*a2` and `G3a = G*a3`.


**Bob:**

* Picks field elements `b2` and `b3`.
* Computes `G2b = G*b2` and `G3b = G*b3`.
* Computes `G2 = G2a*b2` and `G3 = G3a*b3`.
* Picks random value `r`.
* Computes `Pb = G3*r` and `Qb = G*r + G2*y`, where y is the 'actual secret'.
* Sends Alice `G2b`, `G3b`, `Pb` and `Qb`.


**Alice:**

* Computes `G2 = G2b*a2` and `G3 = G3b*a3`.
* Picks random value `s`.
* Computes `Pa = G3*s` and `Qa = G1*s + G2*x`, where x is the 'actual secret'.
* Computes `Ra = (Qa - Qb)*a3`.
* Sends Bob `Pa`, `Qa` and `Ra`.


**Bob:**

* Computes `Rb = (Qa - Qb)*b3`.
* Computes `Rab = Ra*b3`.
* Checks whether `Rab == Pa - P_b`.
* Sends Alice `Rb`.


**Alice:**

* Computes `Rab = Rb*a3`.
* Checks whether `Rab == Pa - P_b`.


If everything is done correctly, then `Rab` should hold the value of `Pa - Pb` times `(G2*a3*b3)*(x - y)`, which means that the test at the end of the protocol will only succeed if `x == y`. Further, since `G2*a3*b3` is a random number not known to any party, if `x` is not equal to `y`, no other information is revealed.

TODO: It may be useful to streamline this section, similarly to how we did with the DAKE, adding a description of each message type with information about how to generate and how to serialize together. Then, present the state machine.

### Secret Information

The secret information x and y compared during this protocol contains not only information entered by the users, but also information unique to the conversation in which SMP takes place. Specifically, the format is:

    Version (BYTE)  
      The version of SMP used. The version described here is 1.
      TODO: Should it be version 2?

    Initiator fingerprint (20 BYTEs)
      The fingerprint that the party initiating SMP is using in the current conversation.

    Responder fingerprint (20 BYTEs)
      The fingerprint that the party that did not initiate SMP is using in the current conversation.

    User-specified secret
      The input string given by the user at runtime.

Then the HashToScalar() of the above becomes the actual secret (x or y) to be used in SMP. The additional fields insure that not only do both parties know the same secret input string, but no man-in-the-middle is capable of reading their communication either.

### The SMP state machine

Whenever the OTR message state machine has `MSGSTATE_ENCRYPTED` set (see below), the SMP state machine may progress. If at any point `MSGSTATE_ENCRYPTED` becomes unset, SMP must abandon its state and return to its initial setup. The SMP state consists of one main variable, as well as information from the partial computations at each protocol step.

### Expected Message

This main state variable for SMP controls what SMP-specific TLVs will be accepted. This variable has no effect on type 0 or type 1 TLVs, which are always allowed. smpstate can take one of four values:

    SMPSTATE_EXPECT1
      This state indicates that only type 2 (SMP message 1) and type 7 (SMP message 1Q) TLVs should be accepted. This is the default state when SMP has not yet begun. This state is also reached whenever an error occurs or SMP is aborted, and the protocol must be restarted from the beginning.

    SMPSTATE_EXPECT2
      This state indicates that only type 3 TLVs (SMP message 2) should be accepted.

    SMPSTATE_EXPECT3
      This state indicates that only type 4 TLVs (SMP message 3) should be accepted.

    SMPSTATE_EXPECT4
      This state indicates that only type 5 TLVs (SMP message 4) should be accepted.

### State Transitions

There are 7 actions that an OTR client must handle:

    Received TLVs:
      SMP Message 1
      SMP Message 2
      SMP Message 3
      SMP Message 4
      SMP Abort Message
    User actions:
      User requests to begin SMP
      User requests to abort SMP

The following sections outline what is to be done in each case. They all assume that `MSGSTATE_ENCRYPTED` is set. For simplicity, they also assume that Alice has begun SMP, and Bob is responding to her.

### SMP Hash function

TODO: check this

In the following actions, there are many places where a SHA3-256 hash of an integer followed by one or two MPIs is taken. The input to this hash function is:

    Version (BYTE)
      This distinguishes calls to the hash function at different points in the protocol, to prevent Alice from replaying Bob's zero knowledge proofs or vice versa.
    First MPI (MPI)
      The first MPI given as input, serialized in the usual way.
    Second MPI (MPI)
      The second MPI given as input, if present, serialized in the usual way. If only one MPI is given as input, this field is simply omitted.

### Receiving a type 2 TLV (SMP message 1)

SMP message 1 is sent by Alice to begin a DH exchange to determine two new generators, g2 and g3. It contains the following MPI values:

    g2_a
      Alice's half of the DH exchange to determine g2.
    c2, D2
      A zero-knowledge proof that Alice knows the value associated with her transmitted value g2_a.
    g3_a
      Alice's half of the DH exchange to determine g3.
    c3, D3
      A zero-knowledge proof that Alice knows the value associated with her transmitted value g3_a.

A type 7 (SMP Message 1Q) TLV is the same as the above, but is preceded by a user-specified question, which is associated with the user-specified portion of the secret.

When Bob receives this TLV he should do:  

If smpstate is not `SMPSTATE_EXPECT1`:  
Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (SMP abort) to Alice.

If smpstate is `SMPSTATE_EXPECT1`:  

* Verify Alice's zero-knowledge proofs for g2_a and g3_a:  
  1. Check that both `g2_a` and `g3_a` are `>= 2` and `<= modulus-2`.  
  2. Check that `c2 = SHA3-256(1, g1*D2 + g2_a*c2)`.  
  3. Check that `c3 = SHA3-256(2, g1*D3 + g3_a*c3)`.  

* Create a type 3 TLV (SMP message 2) and send it to Alice:
  1. Determine Bob's secret input `y`, which is to be compared to Alice's secret x.
  2. Pick random values `b2` and `b3`. These will used during the DH exchange to pick generators.
  3. Pick random values `r2`, `r3`, `r4`, `r5` and `r6`. These will be used to add a blinding factor to the final results, and to generate zero-knowledge proofs that this message was created honestly.
  4. Compute `g2_b = g1⊗b2` and `g3_b = g1⊗b3`.
  5. Generate a zero-knowledge proof that the value `b2` is known by setting `c2 = SHA3-256(3, g1*r2)` and `D2 = (r2 - (b2 * c2)) mod q`. In the zero-knowledge proofs the D values are calculated modulo q, where q = (p - 1) / 2, where p is the same 448-bit prime as elsewhere. The random values are 446-bit numbers. //TO DO: check bits.   
  6. Generate a zero-knowledge proof that the value `b3` is known by setting `c3 = SHA3-256(4, g1*r3)` and `D3 = r3 - b3 * c3 mod q`.
  7. Compute `g2 = g2_a*b2` and `g3 = g3_a*b3`.
  8. Compute `P_b = g3*r4` and `Q_b = g1*r4 + g2*y`.
  9. Generate a zero-knowledge proof that `P_b` and `Q_b` were created according to the protocol by setting `cP = SHA3-256(5, g3*r5, g1*r5 + g2*r6)`, `D5 = r5 - r4 cP mod q` and `D6 = r6 - y cP mod q`.
  10. Store the values of `g3_a`, `g2`, `g3`, `b3`, `P_b` and `Q_b` for use later in the protocol.
  11. Send Alice a type 3 TLV (SMP message 2) containing `g2_b`, `c2`, `D2`, `g3_b`, `c3`, `D3`, `P_b`, `Q_b`, `cP`, `D5` and `D6`, in that order.

* Set smpstate to `SMPSTATE_EXPECT3`.

### Receiving a type 3 TLV (SMP message 2)

SMP message 2 is sent by Bob to complete the DH exchange to determine the new generators, g2 and g3. It also begins the construction of the values used in the final comparison of the protocol. It contains the following mpi values:

    g2_b
      Bob's half of the DH exchange to determine g2.
    c2, D2
      A zero-knowledge proof that Bob knows the value associated with his transmitted value g2_b.
    g3_b
      Bob's half of the DH exchange to determine g3.
    c3, D3
      A zero-knowledge proof that Bob knows the value associated with his transmitted value g3_b.
    P_b, Q_b
      These values are used in the final comparison to determine if Alice and Bob share the same secret.
    cP, D5, D6
      A zero-knowledge proof that P_b and Q_b were created according to the protocol given above.

When Alice receives this TLV she should do:

If smpstate is not `SMPSTATE_EXPECT2`:  
Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (SMP abort) to Bob.

If smpstate is `SMPSTATE_EXPECT2`:

* Verify Bob's zero-knowledge proofs for `g2_b`, `g3_b`, `P_b` and `Q_b`:
    1. Check that `g2_b`, `g3_b`, `P_b` and `Q_b` are `>= 2` and `<= modulus-2`.
    2. Check that `c2 = SHA3-256(3, g1*D2 + g2_b*c2)`.
    3. Check that `c3 = SHA3-256(4, g1*D3 + g3_b*c3)`.
    4. Check that `cP = SHA3-256(5, g3*D5 + P_b*cP, g1*D5 + g2*D6 + Q_b*cP)`.
  
* Create a type 4 TLV (SMP message 3) and send it to Bob:
  
    1. Pick random values `r4`, `r5`, `r6` and `r7`. These will be used to add a blinding factor to the final results, and to generate zero-knowledge proofs that this message was created honestly.
    2. Compute `g2 = g2_b*a2` and `g3 = g3_b*a3`.
    3. Compute `P_a = g3*r4` and `Q_a = g1*r4 + g2*x`.
    4. Generate a zero-knowledge proof that `P_a` and `Q_a` were created according to the protocol by setting `cP = SHA3-256(6, g3*r5, g1*r5 + g2*r6)`, `D5 = r5 - r4 cP mod q` and `D6 = r6 - x cP mod q`.
    5. Compute `R_a = (Qa / Qb) * a3`. // TO DO: check notation
    6. Generate a zero-knowledge proof that `R_a` was created according to the protocol by setting `cR = SHA3-256(7, g1*r7, (Qa / Qb)*r7)` and `D7 = r7 - a3 cR mod q`.
    7. Store the values of `g3_b`, `(P_a / P_b)`, `(Q_a / Q_b)` and `R_a` for use later in the protocol.
    8. Send Bob a type 4 TLV (SMP message 3) containing `P_a`, `Q_a`, `cP`, `D5`, `D6`, `R_a`, `cR` and `D7` in that order.

* Set smpstate to `SMPSTATE_EXPECT4`.
 
### Receiving a type 4 TLV (SMP message 3)

SMP message 3 is Alice's final message in the SMP exchange. It has the last of the information required by Bob to determine if x = y. It contains the following mpi values:

    P_a, Q_a
      These values are used in the final comparison to determine if Alice and Bob share the same secret.
    cP, D5, D6
      A zero-knowledge proof that Pa and Qa were created according to the protcol given above.
    R_a
      This value is used in the final comparison to determine if Alice and Bob share the same secret.
    cR, D7
     A zero-knowledge proof that Ra was created according to the protcol given above.

When Bob receives this TLV he should do:

If smpstate is not `SMPSTATE_EXPECT3`:  
Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (SMP abort) to Bob.

If smpstate is `SMPSTATE_EXPECT3`:

* Verify Alice's zero-knowledge proofs for `P_a`, `Q_a` and `R_a`:
  1. Check that `P_a`, `Q_a` and `R_a` are `>= 2` and `<= modulus-2`.
  2. Check that `cP = SHA3-256(6, g3*D5 + P_a*cP, g1*D5 + g2*D6 + Q_a*cP)`.
  3. Check that `cR = SHA3-256(7, g1*D7 + g3_a*cR, (Q_a / Q_b)*D7 + R_a*cR)`.

* Create a type 5 TLV (SMP message 4) and send it to Alice:
  1. Pick a random value `r7`. This will be used to generate Bob's final zero-knowledge proof that this message was created honestly.
  2. Compute `R_b = (Qa / Qb) * b3`.
  3. Generate a zero-knowledge proof that `R_b` was created according to the protocol by setting `cR = SHA3-256(8, g1*r7, (Q_a / Q_b)*r7)` and `D7 = r7 - b3 cR mod q`.
  4. Send Alice a type 5 TLV (SMP message 4) containing `R_b`, `cR` and `D7` in that order.
 
* Check whether the protocol was successful:
  1. Compute `R_a_b = R_a*b3`.
  2. Determine if `x = y` by checking the equivalent condition that `(P_a / P_b) = R_a_b`.

* Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected from Alice.

### Receiving a type 5 TLV (SMP message 4)

SMP message 4 is Bob's final message in the SMP exchange. It has the last of the information required by Alice to determine if x = y. It contains the following MPI values:

    R_b
      This value is used in the final comparison to determine if Alice and Bob share the same secret.
    cR, D7
      A zero-knowledge proof that Rb was created according to the protcol given above.

When Alice receives this TLV she should do:

If smpstate is not `SMPSTATE_EXPECT4`:  
Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (SMP abort) to Bob.

If smpstate is SMPSTATE_EXPECT4:

* Verify Bob's zero-knowledge proof for R_b:
   1. Check that `R_b` is `>= 2` and `<= modulus-2`.
   2. Check that `cR = SHA3-256(8, g1*D7 g3_b*cR, (Q_a / Q_b)*D7 + R_b*cR)`.

* Check whether the protocol was successful:
    1. `Compute R_a_b = R_b*a3`.
    2. Determine if `x = y` by checking the equivalent condition that `(P_a / P_b) = R_a_b`.

Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected from Bob.
 
### User requests to begin SMP

If smpstate is not set to `SMPSTATE_EXPECT1`:  
SMP is already underway. If you wish to restart SMP, send a type 6 TLV (SMP abort) to the other party and then proceed as if smpstate was `SMPSTATE_EXPECT1`. Otherwise, you may simply continue the current SMP instance.

If smpstate is set to `SMPSTATE_EXPECT1`:  

No current exchange is underway. In this case, Alice should create a valid type 2 TLV (SMP message 1) as follows:

1. Determine her secret input `x`, which is to be compared to Bob's secret `y`.
2. Pick random values `a2` and `a3` (128 bits). These will be Alice's exponents for the DH exchange to pick generators. // TODO: should they still be 128 bits? 
3. Pick random values `r2` and `r3` (128 bits). These will be used to generate zero-knowledge proofs that this message was created according to the protocol. // TODO: should they still be 128 bits? 
4. Compute `g2_a = g1*a2` and `g3_a = g1*a3`.
5. Generate a zero-knowledge proof that the value a2 is known by setting `c2 = SHA3-256(1, g1*r2)` and `D2 = r2 - a2 * c2 mod q`.
6. Generate a zero-knowledge proof that the value a3 is known by setting `c3 = SHA3-256(2, g1*r3)` and `D3 = r3 - a3 * c3 mod q`.
7. Store the values of `x`, `a2` and `a3` for use later in the protocol.
8. Send Bob a type 2 TLV (SMP message 1) containing `g2_a`, `c2`, `D2`, `g3_a`, `c3` and `D3` in that order.

* Set smpstate to `SMPSTATE_EXPECT2`.

### User requests to abort SMP

In all cases, send a type 6 TLV (SMP abort) to the correspondent and set smpstate to `SMPSTATE_EXPECT1`.

## The protocol state machine

An OTR client maintains separate state for every correspondent. For example, Alice may have an active OTR
conversation with Bob, while having an unprotected conversation with Charlie. This state consists of two
main state variables, as well as some other information (such as encryption keys).
The two main state variables are:

### Message state

The message state variable, msgstate, controls what happens to outgoing messages typed by the user. It can take one of three values:

MSGSTATE_PLAINTEXT

    This state indicates that outgoing messages are sent without encryption. This is the state that is used before an OTR conversation is initiated. This is the initial state, and the only way to subsequently enter this state is for the user to explicitly request to do so via some UI operation.

MSGSTATE_ENCRYPTED

    This state indicates that outgoing messages are sent encrypted. This is the state that is used during an OTR conversation. The only way to enter this state is for the authentication state machine (below) to successfully complete.

MSGSTATE_FINISHED

    This state indicates that outgoing messages are not delivered at all. This state is entered only when the other party indicates he has terminated his side of the OTR conversation. For example, if Alice and Bob are having an OTR conversation, and Bob instructs his OTR client to end its private session with Alice (for example, by logging out), Alice will be notified of this, and her client will switch to MSGSTATE_FINISHED mode. This prevents Alice from accidentally sending a message to Bob in plaintext. (Consider what happens if Alice was in the middle of typing a private message to Bob when he suddenly logs out, just as Alice hits Enter.)

### Authentication state

The authentication state variable, authstate, can take one of four values:

AUTHSTATE_NONE

    This state indicates that the authentication protocol is not currently in progress. This is the initial state.

AUTHSTATE_AWAITING_DRE_AUTH

    After Bob initiates the authentication protocol by sending Alice the Pre-key Message, he enters this state to await Alice's reply.

TODO: backward compatiblity

### Policies

OTR clients can set different policies for different correspondents. For example, Alice could set up her client so that it speaks only OTR version 4, except with Charlie, who she knows has only an old client; so that it will opportunistically start an OTR conversation whenever it detects the correspondent supports it; or so that it refuses to send non-encrypted messages to Bob, ever.

The policies that can be set (on a global or per-correspondent basis) are any combination of the following boolean flags:

```
ALLOW_V1
Allow version 1 of the OTR protocol to be used (in general this document will not address OTR protocol version 1; see previous protocol documents for these details).
ALLOW_V2
Allow version 2 of the OTR protocol to be used.
ALLOW_V3
Allow version 3 of the OTR protocol to be used.
ALLOW_V4
Allow version 4 of the OTR protocol to be used.
REQUIRE_ENCRYPTION
Refuse to send unencrypted messages.
SEND_WHITESPACE_TAG
Advertise your support of OTR using the whitespace tag.
WHITESPACE_START_AKE
Start the OTR AKE when you receive a whitespace tag.
ERROR_START_AKE
Start the OTR AKE when you receive an OTR Error Message.
Note that it is possible for UIs simply to offer the old "combinations" of options, and not ask about each one separately.
```

## Appendices

### ROM DRE

The DRE scheme consists of three functions:

`PK, SK = DRGen()`, a key generation function.  
`γ = DREnc(PK1, PK2, m)`, an encryption function.  
`m = DRDec(PK1, PK2, SKi, γ)`, a decryption function.

#### Domain parameters

The Cramer-Shoup scheme uses a group (G, q, g1, g2). This is a group with the same q as Curve 448. The generators G1 and G2 are:

G1 = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160)

G2 = (433103962059265674580308903270602732554589039120240665786107503148578357355610867319637982957210103802741854255963765310708419199319826, 637671230437811306883071736319873166937007728586178661428553286712849083212910048075550542694415936278788300723371476615776878488331711)

TODO: I want to replace one of the generators by B from Curve 448.

#### Dual Receiver Key Generation: DRGen()

1. Pick random values `x1, x2, y1, y2, z` in Z_q.
2. Compute group elements
  - `C = G1*x1 + G2*x2`
  - `D = G1*y1 + G2*y2`
  - `H = G1*z`.
3. The public key is `PK = {C, D, H}` and the secret key is `SK = {x1, x2, y1, y2, z}`.

#### Dual Receiver Encryption: DREnc(PK1, PK2, m)

Let `{C1, D1, H1} = PK1` and `{C2, D2, H2} = PK2`

1. Pick random values `k1, k2, r` in Z_q and compute `K = G1*r`.
2. For i ∈ {1, 2}:
  1. Compute
    - `U1i = G1*ki`
    - `U2i = G2*ki`
    - `Ei = (Hi*ki) + K`
  2. Compute `αi = HashToScalar(U1i || U2i || Ei)`.
  3. Compute `Vi = Ci*ki + Di*(ki * αi)`
3. Compute `K_enc = SHA3-256(K)`. TODO: we do this for key compression (K == 446 bits, K_enc = 256).
4. Pick a random 24 bytes `nonce` and compute `φ = XSalsa20-Poly1305_K_enc(m, nonce)`
5. Generate a NIZKPK:
  1. for i ∈ {1, 2}:
    1. Pick random value `ti` in Z_q.
    2. Compute
      - `T1i = G1*ti`
      - `T2i = G2*ti`
      - `T3i = (Ci + Di*αi)*ti`
  2. Compute `T4 = H1*t1 - H2*t2`.
  3. Compute
    - `gV = G1 || G2 || q` (TODO: Do we really need to send this if they are part of the group definition)
    - `pV = C1 || D1 || H1 || C2 || D2 || H2`
    - `eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2`
    - `zV = T11 || T21 || T31 || T12 || T22 || T32 || T4`
    - `l = HashToScalar(gV || pV || eV || zV)`
  4. Generate for i ∈ {1,2}:
    1. Compute `ni = ti - l * ki (mod q)`.
6. Send `γ = (U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2, nonce, φ)`.

#### Dual Receiver Decryption: DRDec(PK1, PK2, SKi, γ):

Let `{C1, D1, H1} = PK1`, `{C2, D2, H2} = PK2` and `{x1i, x2i, y1i, y2i, zi} = SKi`.

TODO: How to say that `i` is 1 or 2 depending if it is the corresponding secret key of either 1 or 2.

1. Parse `γ` to retrieve components
  `(U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2, nonce, φ) = γ`.
2. Verify NIZKPKi:
  1. for j ∈ {1, 2} compute:
    1. `αj = HashToScalar(U1j || U2j || Ej)`
    2. `T1j = G1*nj + U1j*l`
    3. `T2j = G2*nj + U2j*l`
    4. `T3j = (Cj + Dj*αj)*nj + Vj*l`
  2. Compute `T4 = H1*n1 - H2*n2 + (E1-E2)*l`
  3. Compute
    - `gV = G1 || G2 || q` (TODO: Do we really need to get this from here if they are part of the group definition)
    - `pV = C1 || D1 || H1 || C2 || D2 || H2`
    - `eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2`
    - `zV = T11 || T21 || T31 || T12 || T22 || T32 || T4`
    - `l' = HashToScalar(gV || pV || eV || zV)`
  4. Verify `l' ≟ l`.
  5. Compute
    - `T1 = U1i*x1i`
    - `T2 = U2i*x2i`
    - `T3 = U1i*y1i`
    - `T4 = U2i*y2i`
  6. Verify `T1 + T2 + (T3 + T4)*αi ≟ Vi`.
3. Recover secret key `K_enc = SHA3-256(Ei - U1i*zi)`.TODO: we do this for key compression (K == 446 bits, K_enc = 256).
4. Decrypt `m = XSalsa20-Poly1305_K_enc(φ, nonce)`.

### ROM Authentication

The Authentication scheme consists of two functions:

`σ = Auth(A_2, a_2, {A_1, A_3}, m)`, an authentication function.  
`Verif({A_1, A_2, A_3}, σ, m)`, a verification function.

#### Domain parameters

We reuse the previously defined generator in Cramer-Shoup of DRE:

G = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160).

#### Authentication: Auth(A2, a2, {A1, A3}, m):

A2 is the public value associated with a2, that is, `A2 = G*a2`.  
m is the message to authenticate.

1. Pick random values `t1, c2, c3, r2, r3` in Z_q.
2. Compute `T1 = G*t1`.
3. Compute `T2 = G*r2 + A2*c2`.
4. Compute `T3 = G*r3 + A3*c3`.
5. Compute `c = HashToScalar(G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Compute `c1 = c - c2 - c3 (mod q)`.
7. Compute `r1 = t1 - c1 * a2 (mod q)`.
8. Send `σ = (c1, r1, c2, r2, c3, r3)`.

#### Verification: Verif({A1, A2, A3}, σ, m)

1. Parse σ to retrive components `(c1, r1, c2, r2, c3, r3)`.
2. Compute `T1 = G*r1 + A1*c1`
3. Compute `T2 = G*r2 + A2*c2`
4. Compute `T3 = G*r3 + A3*c3`
5. Compute `c = HashToScalar(G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Check if `c ≟ c1 + c2 + c3 (mod q)`.

### HashToScalar(d)

d is an array of bytes.

1. Compute `h = SHA3-512(d)` as an unsigned value, big-endian.
2. Return `h (mod q)`

## References

1. http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf  
2. https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
