## ADR 5: Brace keys

### Context

We acknowledge that there may be potential weaknesses in elliptic curves and
that quantum computers may arrive earlier than predicted.

We propose an additional mechanism for protecting transcripts against post-
conversation decryption.

### Proposal

We believe we can protect transcripts from post-conversation decryption by
mixing another key obtained from a Diffie-Hellman (DH) exchange into the key
material. This additional key is called the “brace key”.

This document specifies:

1. The brace key to mix in with the ECDH shared secret when deriving a new
   root key.
2. An algorithm for ratcheting and deriving the brace key.

This document only changes the way root keys are derived during the Double
Ratchet algorithm.

The first 3072-bit DH key agreement takes place in the DAKE. This takes
place as a traditional Diffie-Hellman key exchange and not as the combined
quantum resistant key encapsulation mechanism (KEM) as proposed in Nik
Unger's paper [\[1\]](#references) (which is described to be optionally used).
Notice that the first derived DH key during the DAKE is used for generation
of the Mixed shared secret. For the initialization of the Double Ratchet
Logarithm, a DH key must be advertised.

We are not using the same quantum resistant KEM, as defined in the mentioned
paper (that recommends using either SIDH or New Hope), because we are aiming
to give additional protection against transcript decryption in the case of
ECC compromise and some protection if quantum computers arrive earlier than
expected. Because of this, we will use a traditional DH key exchange.

We considered two options for ratcheting/deriving the brace key:

1. Obtain a brace key from a DH function which requires the other party to
   contribute to the computation each time a new Mixed shared secret is derived.
2. Obtain a brace key with DH functions which require the other party to
   contribute to the computation every n times. Between these derivations,
   the brace keys are obtained using a key derivation function (KDF) that is
   seeded with the last DH key. We propose n = 3, but n can be adjusted for
   performance.

We chose the second option.

### Algorithm

In this description of the algorithm's functions, we will assume n = 3.

**k_dh = A_i, a_i**

A brace key is a key that is added to the KDF used to derive a new Mixed shared
secret. A brace key can be produced through a DH function or through a
key derivation function. The first method produces a 3072-bit public key which
is later used as an input to a key derivation function
`KDF_1(0x02 || k_dh, 32)`. The second method produces a 32-byte key as a result
of a key derivation function that takes as an input the previous brace key
`KDF_1(0x03 || brace_key, 32)`. This key has a 128-bit security level according
to Table 2: Comparable strengths in NIST’s Recommendation for Key Management,
page 53 [\[3\]](#references).

**generateDH function: generateDH()**

Generates `A_i` and `a_i`.

**DH function: DH(a_i, B_i)**

Given `a_i`, a secret key, and `B_i`, a public key, generates a shared secret
value: `k_dh`.

**Key Derivation Function: SHAKE-256(k_dh)**

Given a 3072-bit shared secret value `k_dh`, the SHAKE-256 generates a 32-byte
digest: `brace_key`.

**Key Derivation Function: SHAKE-256(brace_key)**

Given `brace_key`, the SHAKE-256 generates a 32-byte digest: a new `brace_key`.

#### Considerations

Transmitting the 3072-bit DH public key will increase the time it takes to
exchange messages. To mitigate this, the key won’t be transmitted every time
the root and chain keys are derived. Instead, this key will be computed with
a DH function every third time and the interim keys will be derived from the
previous `brace_key`. After generating new DH keys, the new public key will
be sent in every message of that ratchet in order to allow transmission even
if one of the messages is dropped.

The brace key will be mixed with the ECDH key to produce the Mixed shared
secret.

#### Implementation

Alice's DH keypair = `(a_i, A_i)`

Bob's DH keypair = `(b_i, B_i)`

Every Mixed shared secret derivation requires both an ECDH key and a brace key.
For the purposes of this explanation, we will only discuss the brace key.

`n` is the number of root key derivations before performing a new DH
computation.

The interim root key derivations will use a brace key derived from a
`SHAKE-256` using the previous brace key as the seed.

_When n is configured to equal 3_

```
If we assume messages have been sent by Alice and Bob after the DAKE and we
are now at ratchet 3:

Alice                                                 Bob
---------------------------------------------------------------------------------------------
* Generates a new public DH key 'A_1' and
  a secret key 'a_1'
* Derives a new DH shared secret using Bob's
  public key received in a previous ratchet ('B_0')
    'k_dh = DH(B_0, a_1)'
* Derives the new brace key from 'k_dh'
    brace_key_3 = KDF_1(0x02 || k_dh, 32)
* Mixes the brace key with the ECDH shared
  secret to create the Mixed shared secret 'K_3'
    'K_3 =
    KDF_1(0x04 || K_ecdh || brace_key_3, 64)'
* Generates the root key and
  the sending chain key from root key 2 ('root_key_2')
  and the Mixed shared secret ('K_3')
    'root_key_3 = KDF_1(0x21 || root_key_2 || K_3, 64)'
    'chain_key_s_3_0 = KDF_1(0x22 || root_key_2 || K_3, 64)'
* Encrypts data message with a message key
  derived from 'chain_key_s_3_0'
* Increases ratchet_id by one
* Sends data_message_3_0 with 'A_1' ----------------->
                                                     * Generates a new public DH key 'B_1' and secret
                                                       key 'b_1'
                                                     * Derives a new DH shared secret using Alice's
                                                       public key received in the data message ('A_1')
                                                         'k_dh = DH(A_1, b_1)'
                                                     * Derives the new brace key from the 'k_dh'
                                                         'brace_key_3 = KDF_1(0x02 || k_dh, 32)'
                                                     * Mixes the brace key with the ECDH shared secret
                                                       to create the shared secret 'K_3'
                                                         'K_3 = KDF_1(0x04 || K_ecdh || brace_key_3, 64)'
                                                     * Generates the root and the receiving chain key
                                                       from root key 2 ('root_key_2') and from the
                                                       Mixed shared secret ('K_3')
                                                        'root_key_3 = KDF_1(0x21 || root_key_2 ||
                                                         K_3, 64)'
                                                        'chain_key_r_3_0 = KDF_1(0x22 || root_key_2 ||
                                                         K_3, 64)'
                                                     * Decrypts the received message with a message key
                                                       derived from 'chain_key_r_3_0'
                                                     * Increases ratchet_id by one
                                                     * Derives a new brace key from the one derived
                                                       previously
                                                         'brace_key_4 = KDF_1(0x03 || brace_key, 32)'
                                                     * Generates new ECDH keys and uses Alice's ECDH
                                                       public key (received in data_message_3_0) to
                                                       create the ECDH shared secret ('K_ecdh').
                                                     * Mixes the brace key with 'K_ecdh' to create
                                                       the Mixed shared secret 'K_4'
                                                         'K_4 = KDF_1(0x04 || K_ecdh ||
                                                          brace_key_4, 64)'
                                                     * Generates the root and the sending chain key
                                                       from root key 3 ('root_key_3') and from the
                                                       Mixed shared secret ('K_4')
                                                         'root_key_4 = KDF_1(0x21 || root_key_3 ||
                                                          K_4, 64)'
                                                         'chain_key_s_4_0 = KDF_1(0x22 || root_key_3 ||
                                                          K_4, 64)'
                                                      * Encrypts data message with a message key derived
                                                        from 'chain_key_s_4_0'
                                  <-----------------  * Sends data_message_4_0
```

**Alice or Bob sends the first message in a ratchet (a first reply)**

The ratchet identifier `ratchet_id` increases every time a new ratchet is
received (when `j == 0` and the advertised ECDH public key from the other party
is different from the stored one) or sent.

If `ratchet_id % 3 == 0 && sending the first message of a new ratchet`

  * Compute the new brace key from a DH computation e.g.
    `brace_key_i = KDF_1(0x02 || DH(our_DH.secret, their_DH.public), 32)
  * Send the new `brace_key`'s public key (our_DH.public) to the other party
    for further key computation.

Otherwise

  * Derive the new brace key:
    `KDF_1(0x03 || brace_key_(i-1), 32)`

**Alice or Bob send a follow-up message**

When a new public key has been generated and sent in the first message in a
ratchet, all follow up messages in that ratchet will also need to advertise the
DH public key in case they arrive in an out-of-order way.

**Alice or Bob receive the first message in a ratchet**

If `ratchet_id % 3 == 0`:

   * Check that a new DH public key is attached to the message.

    * If it is not:
      * Reject the message.

    * Otherwise:
      * Compute the new brace key from a new DH computation e.g.
        `brace_key_i = KDF_1(0x02 || DH(our_DH.secret, their_DH.public), 32)
      * Use `brace_key_i` to calculate the Mixed shared secret.

The `ratchet_id` will need to be increased, so `ratchet_id += 1`

**Alice or Bob receive a follow up message**

If the received `ratchet_id` is not greater than the current state of
`ratchet_id`, then this is not a new ratchet. In this case there is no further
action to be taken regarding the brace key.

**Diagram: Pattern of DH computations and key derivations in a conversation**

This diagram describes when public keys should be sent and when Alice and Bob
should compute the `brace_key` from a KDF_1 or a new DH computation.

Both parties share knowledge of `brace_key_0`, established immediately after
the DAKE.

Given

    Alice's DH keypair = (a_i, A_i)
    Bob's DH keypair = (b_i, B_i)

If Alice sends the first message:

```
    Alice                 ratchet_id        public_key           Bob
---------------------------------------------------------------------------------------

brace_key_1 = KDF_1(brace_key_0)   -----1---------------->   brace_key_1 = KDF_1(brace_key_0)
brace_key_2 = KDF_1(brace_key_1)   <----2-----------------   brace_key_2 = KDF_1(brace_key_1)
brace_key_3 = KDF_1(DH(a_1, B_0))  -----3-------A_1------>   brace_key_3 = KDF_1(DH(b_0, A_1))
brace_key_4 = KDF_1(brace_key_3)   <----4-----------------   brace_key_4 = KDF_1(brace_key_3)
brace_key_5 = KDF_1(brace_key_4)   -----5---------------->   brace_key_5 = KDF_1(brace_key_4)
brace_key_6 = KDF_1(DH(a_1, B_1))  <----6-------B_1-------   brace_key_6 = KDF_1(DH(b_1, A_1))
brace_key_7 = KDF_1(brace_key_6)   -----7---------------->   brace_key_7 = KDF_1(brace_key_6)
brace_key_8 = KDF_1(brace_key_7)   <----8-----------------   brace_key_8 = KDF_1(brace_key_7)
brace_key_9 = KDF_1(DH(a_2, B_1))  -----9-------A_2------>   brace_key_9 = KDF_1(DH(b_1, A_2))
```

### Performance

Computation of `g^a`, `g^b` and `g^a^b` takes under a second when using the
generator `g = 2`. Exponents `a` and `b` are 3072 bits long in an Intel Core
i7 2.2GHz.

| Operation           | Repeat times | Time per Operation |
| ------------------- | ------------ | ------------------ |
| ComputeSharedSecret | 2000         | 22.198064 ms/op    |
| KeyGeneration       | 1000         | 31.607442 ms/op    |

### Decision

We've decide to use a 3072-bit key produced by:

1. a DH function which takes as an argument the other party’s exponent
   (advertised through a data message) to produce brace key.
2. a KDF `KDF_1(0x03 || brace_key, 32)` which uses the previous brace key
   to produce a new one.

The DH function will run every `n = 3` times because:

1. It is a small number so a particular key can only be compromised for a
   maximum of n ratchets. This means that the maximum ratchets that will
   use the brace key or a key derived from the brace key is 3 (from the
   sender and from the receiver side).

The group used for this key is the one assigned with id 15 in the IETF paper,
RFC 3526 [\[4\]](#references):

* Prime is:
  2^3072 - 2^3008 - 1 + 2^64 * (integer_part_of(2^2942 * π) + 1690314)
* Hex value:

  ```
  FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
  29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
  EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
  E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
  EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
  C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
  83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
  670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
  E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
  DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
  15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
  ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
  ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
  F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
  BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
  43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
  ```

* Generator g3: 2

### Consequences

Using a 3072-bit DH function to produce the brace key increases the size of
data messages by 56 bytes of extra key material. The increased size may cause
some transport protocols to fragment these messages.

### References

1. Goldberg, I. and Unger, N. (2016). *Improved Strongly Deniable Authenticated
   Key Exchanges for Secure Messaging*, Waterloo, Canada: University of
   Waterloo. Available at:
   http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf
2. Barker, E. (2016). *Recommendation for Key Management*, NIST Special
   Publication 800-57. Available at:
   http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
3. Kojo, M. (2003). *More Modular Exponential (MODP) Diffie-Hellman groups for
   Internet Key Exchange (IKE)*, Internet Engineering Task Force,
   RFC 3526. Available at: https://www.ietf.org/rfc/rfc3526.txt