## ADR 3: Mix Keys

**Status**: proposed

### Context
Because of potential classical weaknesses, and the potential of
quantum computers arriving earlier than predicted, we want an
additional mechanism that would protect against post-conversation
decryption of transcripts using those weaknesses.

We believe this can be achieved by mixing another key obtained from a
Diffie-Hellman exchange into the KDFs. This additional key will be
referred to as “mix key”.

This proposal specifies

1. adding an extra key to mix in with the ECDH key when deriving a new
root key.
2. an algorithm for ratcheting and deriving this mix key.

This proposal does not change the Double Ratchet algorithm, with the
exception of how to derive root keys.

The first 3072-bit DH key agreement would take place in the DAKE
agreement. See Nik Unger's paper[1], which specifies Transitionally
Secure Spawn. The exception to this entry in the paper, is that we are
trying to protect against ECC weaknesses and SIDH[2] relies on ECC. So
this will instead be just a DH exchange.

The options for ratcheting/re-deriving this mix key are:

1. Obtain every mix key from a DH function which requires the other party
to contribute to the computation every time we require one.
2. Obtain a mix key from a DH functions which requires the other party to
contribute to the computation every n times and the mix keys in the
middle would be obtained using a KDF that’s seed with the last DH key;
n equals to two but might be adjusted depending on performance.

### Algorithm

#### Definitions

*Mix key (X_i)*

A mix key is a key that is added to the key derivation function used
to produce new root and chains keys. A mix key can be produced through
a DH function and through a key derivation function, both of which
produce a 3072-bit long key. This key has a 128 bit security level per
Table 2: Comparable strengths in NIST’s Recommendation for Key
Management, page 53
(http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf).

*DH function - DH(x, g^y)*

This function produces a 3072 bits long key by computing the
exponentiation of g^y to the power of x.

Key Derivation Function - SHA3(Y)
This function produces a 3072 bits long key by computing a SHA3 value
from Y; where Y is a 3072 bits long key.

#### Considerations

Transmitting the 3072-bit DH public key will increase the time to
exchange messages. To mitigate this the key won’t be transmitted every
time the root and chain keys are changed. Instead, this key will be
computed with a DH function every third time and the interim keys will
be derived from previous mix key. When generating new DH keys, the
public key will be sent in every message of that ratchet in case of
dropped messages.  This should be clear when looking at the
pseudo-code implementation below.

The mix key X_i is to be mixed in at the root level with the ECDH
key.

#### Implementation

Alice's DH keypair = (a_i, A_i)
Bob's DH keypair = (b_i, B_i)
Mix key = X_i 

Every root key derivation requires both an ECDH key and a mix key. For
the purposes of this explanation, we will only discuss the mix key.

n is the number of root key derivations before performing a new DH
computation. The interim root key derivations will use a mix key that
is a KDF of a previous mix key.

_When n is configured to equal 3_
```
Alice                                                              Bob
-----------------------------------------------------------------------------------------------------------------------
Increases ratchet_id by one
Derives a new mix key from the one obtained in DAKE
    X_1 = pubDHa, secDHa = KDF(X_0)
Mixes X_1 into the KDF to generate root and chain keys
    R_1, Cs_0_1, Cr_0_1 = KDF(R_0, ECDH_1 || X_1)
Encrypts data message with Cs_0_1
Sends data_message_0_0 ----------------------------------------->
Encrypts data message with Cs_0_1
Sends data_message_0_1 ----------------------------------------->
                                                                   Derives a new mix key from the one obtained in DAKE
                                                                       X_1 = pubDHa, secDHa = KDF(X_0)
                                                                   Mixes DH_1 into the KDF to generate root and chain keys
                                                                       R_1, Cs_0_1, Cr_0_1 = KDF(pubECDHa, secECDHa || secDHa)
                                                                   Decrypts received message(s) with Cs_0_1
                                                                   Derives a new mix key from the one obtained in DAKE
                                                                       X_2 = pubDHa, secDHa = KDF(X_1)
                                                                   Mixes DH_2 into the KDF to generate root and chain keys
                                                                       R_1, Cs_1_0, Cr_1_0 = KDF(pubECDHa, secECDHa || secDHa)
                                                                   Encrypts data message with Cr_1_0
                       <----------------------------------------   Sends data_message_1_0
                                                                   Encrypts data message with Cr_1_0
                       <----------------------------------------   Sends data_message_1_0
```
**Alice or Bob sends the first message in a ratchet (/a first reply)**

The ratchet identifier increases every time a greater ratchet_id is
received or a new message is being sent and signals the machine to
ratchet i.e. `ratchet_id += 1`

Alice needs to generate new keys when `ratchet_id % 6 == 3` and Bob when
`ratchet_id % 6 == 0` (see diagram below)

If `ratchet_id % 6 == 3 || ratchet_id % 6 == 0`
Generate new public and secret keys
Any party that has computed a new mix key K_i using the DH function
should send the new public key to the other party for further key
computation.

(NOTE: K_i is calculated only when the first message of the ratchet is
to be sent or received, i.e. when the ratchet_id is increased)

if `ratchet_id % 3 == 0`
    Compute the new mix key from a new DH computation e.g. `K_i =
    DH(our_DH.secret, their_DH.public)`
otherwise
    Compute the new mix key `K_i = KDF(K_(i-1))`

**Alice or Bob send a follow-up message**

In case of dropped messages, when a new public key has been generated
and sent for a first message in a ratchet, all follow up messages in
that ratchet will also need the public key to ensure the other party
receives it.

If `ratchet_id % 6 == 3 || ratchet_id % 6 == 0`
    Send public key

**Alice or Bob receive a first message in a ratchet**

The ratchet_id will need to be increased,  so `ratchet_id += 1`

If `ratchet_id % 6 == 3 || ratchet_id % 6 == 0`
    A new public key should be attached to the message, if it is not,
    reject the message.
    
Otherwise, compute the new mix key from a new DH computation e.g. `K_i
= DH(our_DH.secret, their_DH.public)`

**Alice or Bob receive a follow up message**

If the ratchet_id is not greater than the current state of ratchet_id,
then this is not a new ratchet. In this case there is no further
action to be taken for the mix key.

Diagram representing the pattern of DH computations and key derivations

Both parties share knowledge of X_0, which is a mix key established at
DAKE. If Bob sends the first message then the root key derived from
X_0 will be used and then will continue as in the diagram below.

If Alice sends the first message:
```
    Alice                 ratchet_id        public_key           Bob
------------------------------------------------------------------------------------------------------------

K_1 = SHA3(K_0)         -----1----------------------->            K_1 = SHA3(K_0)
K_2 = SHA3(K_1)         <----2------------------------            K_2 = SHA3(K_1)     
K_3 = DH(a_1, B_0)      -----3------------A_1------>            K_3 = DH(b_0, A_1)
K_4 = SHA3(K_3)         <----4------------------------            K_4 = SHA3(K_3)     
K_5 = SHA3(K_4)         -----5----------------------->            K_5 = SHA3(K_4)   
K_6 = DH(a_1, B_1)      <----6------------B_1-------            K_6 = DH(b_1, A_1)
K_7 = SHA3(K_6)         -----7----------------------->            K_7 = SHA3(K_6)     
K_8 = SHA3(K_7)         <----8------------------------            K_8 = SHA3(K_7)     
K_9 = DH(a_2, B_1)      -----9------------A_2------>            K_9 = DH(b_1, A_2)
```
This diagram describes when public keys should be sent and when Alice
and Bob should compute the mix key from a SHA3 or a new Diffie Hellman
computation.

### Performance

Computation of g^a, g^b and g^a^b takes under a second using generator
g equals 2 and exponents a and b 3072 bits long over “Intel Core i7
2.2GHz”

| Operation | Repeat times | Time per Operation |
| --------- | ------------ | ------------------ |
| ComputeSharedSecret | 2000 | 22.198064 ms/op |
| KeyGeneration | 1000 | 31.607442 ms/op |

### Decision

We’ve decide to use a 3072-bit key produced by

1. a DH function which takes as argument the other party’s exponent
   through a data message and produces a mix key.
2. a KDF function which takes as argument the previous mix key to
   produce a new one.

The DH function will run every n times; n is equals three because of
the following reasons:

1. It is a small number so a particular key can only be compromised
   for a maximum of 2*n ratchets. This mean the maximum ratchets will
   be 6.
2.  The benefit of using an odd number is for simplicity of
    implementation. For an odd number, both Alice and Bob can generate
    a new public and secret key at the same time as sending the public
    key and compute a new mix key from a DH function. However, with an
    even number, Alice would need to generate and send a key in a
    different ratchet to the one where the public key would be
    used. This would be because the public key would only be used in a
    mix key computed from a new DH function on even numbers of
    ratchet_ids so only Bob would be the sender at these times.

### Consequences

Using a 3072 DH function to produce the mix key charges data messages
with extra key material 56 bytes long that may cause some transport
protocols to fragment these messages.

[1](http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf)
[2](https://eprint.iacr.org/2011/506.pdf)
[3](https://whispersystems.org/blog/advanced-ratcheting/)
