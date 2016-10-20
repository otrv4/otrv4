## ROM DRE

The DRE scheme consists of three functions: 

1. `pk, sk = DRGen()`, a key generation function

2. `γ = DREnc(pk1, pk2, m)`, an encryption function

3. `m = DRDec(pk1, pk2, sk_i, γ)`, a decryption function

### Setup

The Cramer-Shoup scheme uses a group (G, ℓ, g1, g2). In OTRv4, we choose Ed448 with its group G and its
correspondant prime order ℓ of 446 bits. The generators g1 and g2 are:

g1 = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160)

g2 = (433103962059265674580308903270602732554589039120240665786107503148578357355610867319637982957210103802741854255963765310708419199319826, 637671230437811306883071736319873166937007728586178661428553286712849083212910048075550542694415936278788300723371476615776878488331711)

Regarding to elliptic curve operations, we use ⊕ to represent PointAddition, ⊗ to represent ScalarMultiplication and ⊖ to represent point substraction in the following definitions.


### Dual Receiver Key Generation: DRGen()

1. Pick random values x1, x2, y1, y2, z (56 bytes each) in Z_ℓ.
2. Compute group elements c = g1⊗x1 ⊕ g2⊗x2, d = g1⊗y1 ⊕ g2⊗y2, h = g1⊗z. 
3. The public key is pk = {c, d, h} and the secret key is sk = {x1, x2, y1, y2, z}.


### Dual Receiver Encryption: DREnc(pk_1, pk_2, m)

1. Pick random values K, k_1, k_2 (56 bytes each) in Z_ℓ.
2. For i ∈ {1,2}:
  1. pk_i = {c_i,d_i,h_i}
  2. Compute u_1i = g1⊗k_i, u_2i = g2⊗k_i, e_i = (h_i⊗k_i) ⊗ K
  3. Compute α_i = MapToZl(u_1i, u_2i, e_i).
  4. Compute v_i = (c_i⊗k_i) ⊕ (d_i⊗(k_i ⊗ α_i))
3. Compute K_enc = SHA3-256(K).
4. Pick a random 24 bytes nonce and compute φ = XSalsa20-Poly1305_K_enc(m, nonce)
5. Generate a NIZKPK: 
  1. for i ∈ {1,2}: 
    1. Pick random value t_i (56 bytes) in Z_ℓ. 
    2. Compute T_1i = g1⊗t_i, T_2i = g2⊗t_i, T_3i = (c_i ⊕ (d_i⊗α_i))⊗t_i. 
  2. Compute T_4 = (h_1⊗t_1) ⊖ (h_2⊗t_2).
  3. Compute L = MapToZl(g1 ∥g2 ∥ ℓ ∥ pk_1 ∥ pk_2 ∥ u_11 ∥ u_21 ∥ e_1 ∥ v_1 ∥ α_1 ∥ u_12 ∥ u_22 ∥ e_2 ∥ v_2 ∥ α_2 ∥ T_11 ∥ T_21 ∥ T_31 ∥ T_12 ∥ T_22 ∥ T_32 ∥ T_4 ).
  4. Generate for i ∈ {1,2}: 
    1. Compute n_i = t_i - L * k_i (mod ℓ).
6. Send γ = (u_11, u_21, e_1, v_1, u_12, u_22, e_2, v_2, L, n_1, n_2, nonce, φ).


### Dual Receiver Decryption: DRDec(pk_1, pk_2, sk_i, γ):

1. Parse γ to retrieve components γ = (u_11, u_21, e_1, v_1, u_12, u_22, e_2, v_2, L, n_1, n_2, nonce, φ).
2. Verify NIZKPKi: 
  1. for j ∈ {1,2} compute:
    1. α'_j = MapToZl(u1_j ∥ u_2j ∥ e_j)
    2. T'_1j = (g1⊗n_j) ⊕ (u_1j⊗L)
    3. T'_2j = (g2⊗n_j) ⊕ (u_2j⊗L)
    4. T'_3j = (c_j ⊕ (d_j⊗a'_j))⊗n_j ⊕ (v_j⊗L)
  2. T'_4 = ((h1⊗n1) ⊖ (h2⊗n2)) ⊕ ((e1 ⊖ e2)⊗L)
  3. Compute L' = MapToZl(g1 ∥ g2 ∥ q ∥ pk_1 ∥ pk_2 ∥ u_11 ∥ u_21 ∥ e_1 ∥ v_1 ∥ α'_1 ∥ u_12 ∥ u_22 ∥ e_2 ∥ v_2 ∥ α'_2 ∥ T'_11 ∥ T'_21 ∥ T'_31 ∥ T'_12 ∥ T'_22 ∥ T'_32 ∥ T'_4 ).
  4. Verify L ≟ L.
  5. Compute t_1 = u_1i⊗x_1i, t2 = u_2i⊗x_2i, t3 = u_1i⊗y_1i, t4 = u_2i⊗y_2i
  6. Verify t_1 ⊕ t2 ⊕ (t3 ⊕ t4)⊗α'_i ≟ v_i.
3. Recover secret key K_enc = (e_i) ⊖ (u1_i⊗z_i).
4. Decrypt m = XSalsa20-Poly1305_K_enc(φ, nonce).


## ROM Authentication

The Authentication scheme consists of two functions:

1. `σ = Auth(A_2, a_2, {A_1, A_3}, m)`, an authentication function

2. `Verif({A_1, A_2, A_3}, σ, m)`, a verification function


## Setup

We reuse the previously defined generator in Cramer-Shoup of DRE:

g = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160).

### Authentication: Auth(A2, a_2, {A_1, A_3}, m):

A_2 is the public value associated with a_2.
m is the message to authenticate.

1. Pick random values t_1, c_2, c_3, r_2, r_3 (56 bytes each) in Z_ℓ.
2. Compute T_1 = g⊗t_1.
3. Compute T_2 = (g⊗r_2) ⊕ (A_2⊗c_2).
4. Compute T_3 = (g⊗r_3) ⊕ (A_3⊗c_3).
5. Compute c = MapToZl(g ∥ ℓ ∥ A_1 ∥ A_2 ∥ A_3 ∥ T_1 ∥ T_2 ∥ T_3 ∥ m).
6. Compute c_1 = c - c_2 - c_3 (mod ℓ).
7. Compute r_1 = t_1 - c_1 * a_2 (mod ℓ). 
8. Send σ = (c_1, r_1, c_2, r_2, c_3, r_3).

### Verification: Verif({A_1, A_2, A_3}, σ, m)

1. Parse σ to retrive components (c_1, r_1, c_2, r_2, c_3, r_3).
2. Compute T1 = (g⊗r_1) ⊕ (A_1⊗c_1)
3. Compute T2 = (g⊗r_2) ⊕ (A_2⊗c_2)
4. Compute T3 = (g⊗r_3) ⊕ (A_3⊗c_3)
5. Compute c' = MapToZl(g ∥ ℓ ∥ A_1 ∥ A_2 ∥ A_3 ∥ T1 ∥ T2 ∥ T3 ∥ m).
6. Check if c' ≟ c_1 + c_2 + c_3 (mod ℓ).

## MapToZl(d)

d is an array of bytes.

1. Compute h = SHA3-512(d) as an unsigned value, big-endian.
2. Return h mod ℓ

## DAKE

Alice long-term Cramer-Shoup key-pair is `SKa = (x1A, x2A, y1A, y2A, zA)` and `PKa = (cA, dA, hA)`.  
Bob long-term Cramer-Shoup key-pair is `SKb = (x1B, x2B, y1B, y2B, zB)` and `PKb = (cB, dB, hB)`.  
Both key pairs are generated with `DRGen()`.  

### Interactive SPAWN:

Alice:

1. Generates an ephemeral private key `i` from `Z_ℓ` and a public key `g1^i`.
2. Sends Bob `ψ1 = ("I", g1^i)`.


Bob:

1. Generates an ephemeral private key `r` from `Z_ℓ` and public key `g1^r`.
2. Computes `m = "I" ∥ "R" ∥ g1^i ∥ g1^r`, `γ = DREnc(PKb, PKa, m)`.
3. Computes `σ = Auth(hB, zB, {hA, g1^i}, "I" ∥ "R" ∥ g1^i ∥ γ)`.
4. Computes `k = (g1^i) * r` and securely erase `r`.
5. Sends Alice `ψ2 = ("R", γ, σ)`.


Alice:

1. Verifies `Verif({hA, hB, g1^i}, σ, “I” ∥ “R” ∥ g1^i ∥ γ)`.
2. Decrypts `m = DRDec(PKa, PKb, SKa, γ)`.
3. Verifies the following properties of the decrypted message `m`:
  1. The message is of the correct form (e.g., the fields are of the expected length)
  2. Alice's identifier is the first one listed
  3. Bob's identifier is the second one listed, and it matches the identifier transmitted outside of the ciphertext


### Non-interactive SPAWN:

Alice:

1. Generates an ephemeral private key `i` from `Z_ℓ` and a public key `g1^i`.
2. Sends the pre-key `ψ1 = ("I", g1^i)` to a storage server.


Bob:
1. Requests one of Alice's pre-keys from the storage server.
2. Generates an ephemeral private key `r` from `Z_ℓ` and public key `g1^r`.
3. Computes `m = "I" ∥ "R" ∥ g1^i ∥ g1^r`, `γ = DREnc(PKb, PKa, m)`.
4. Computes `σ = Auth(hB, zB, {hA, g1^i}, "I" ∥ "R" ∥ g1^i ∥ γ)`.
5. Computes `k = (g1^i) * r` and securely erase `r`.
6. Generates a data message `d` according to the spec.
7. Sends Alice `ψ2 = ("R", γ, σ, d)`.


Alice:

1. Verifies `Verif({hA, hB, g1^i}, σ, “I” ∥ “R” ∥ g1^i ∥ γ)`.
2. Decrypts `m = DRDec(PKa, PKb, SKa, γ)`.
3. Verifies the following properties of the decrypted message `m`:
  1. The message is of the correct form (e.g., the fields are of the expected length)
  2. Alice's identifier is the first one listed
  3. Bob's identifier is the second one listed, and it matches the identifier transmitted outside of the ciphertext
  4. g1^i is a pre-key that Alice previously sent and remains unused.
4. Process the data message `d` according to the spec.

