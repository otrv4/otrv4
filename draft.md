## ROM DRE

The DRE scheme consists of three functions: 

1. `pk, sk = DRGen()`, a key generation function

2. `γ = DREnc(pk1, pk2, m, r)`, an encryption function

3. `m = DRDec(pk1, pk2, sk_i, γ)`, a decryption function

It consists of the Cramer-Shoup cryptosystem and a NIZKPK.

### Setup

In the Cramer-Shoup scheme, we have a group G with prime order q. In OTRv4, we choose Ed448 with its group G and its
correspondant prime order ℓ of 446 bits. 

We select the following two elements as generators from G:

g1 = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160)

g2 = (433103962059265674580308903270602732554589039120240665786107503148578357355610867319637982957210103802741854255963765310708419199319826, 637671230437811306883071736319873166937007728586178661428553286712849083212910048075550542694415936278788300723371476615776878488331711)

Regarding Ed448 group operations, we use ⊕ to represent PointAddition, ⊗ to represent ScalarMultiplication and ⊖ to represent point substraction in the following definitions.


### Dual Receiver Key Generation: DRGen()

1. Pick random values x1, x2, y1, y2, z (56 bytes each) in Z_ℓ.
2. Compute group elements c = g1⊗x1 ⊕ g2⊗x2, d = g1⊗y1 ⊕ g2⊗y2, h = g1⊗z. 
3. The public key is pk = {c, d, h} and the secret key is sk = {x1, x2, y1, y2, z}.

### Dual Receiver Encryption: DREnc(pk_1, pk_2, m)

pk_1 and pk_2 are the Cramer-Shoup public key.

1. Pick random values K, k_1, k_2 (56 bytes each) in Z_ℓ.
2. For i ∈ {1,2}:
  1. pk_i = {c_i,d_i,h_i}
  2. Compute u_1i = g1⊗k_i, u_2i = g2⊗k_i, e_i = (h_i⊗k_i) ⊗ K
  3. Compute α_i = decodeIntEd448_big-endian(SHA-3_512(u_1i, u_2i, e_i)).
  4. Compute v_i = (c_i⊗k_i) ⊕ (d_i⊗(k_i ⊗ α_i))
3. Compute K_enc = SHA-3_256(K).
4. Pick a random 24 bytes nonce and compute φ = XSalsa20-Poly1305_K_enc(m, nonce)
5. Generate a NIZKPK: 
  1. for i ∈ {1,2}: 
    1. Pick random value t_i (56 bytes) in Z_ℓ. 
    2. Compute T_1i = g1⊗t_i, T_2i = g2⊗t_i, T_3i = (c_i ⊕ (d_i⊗α_i))⊗t_i. 
  2. Compute T_4 = (h_1⊗t_1) ⊖ (h_2⊗t_2).
  3. Compute L = decodeIntEd448_big-endian(SHA-3_512(g1 ∥g2 ∥ ℓ ∥ pk_1 ∥ pk_2 ∥ u_11 ∥ u_21 ∥ e_1 ∥ v_1 ∥ α_1 ∥ u_12 ∥ u_22 ∥ e_2 ∥ v_2 ∥ α_2 ∥ T_11 ∥ T_21 ∥ T_31 ∥ T_12 ∥ T_22 ∥ T_32 ∥ T_4 )).
  4. Generate for i ∈ {1,2}: 
    1. Compute n_i = t_i - L * k_i (mod ℓ).
6. Send γ = (u_11, u_21, e_1, v_1, u_12, u_22, e_2, v_2, L, n_1, n_2, nonce, φ).


### Dual Receiver Decryption: DRDec(pk_1, pk_2, sk_i, γ):

1. Parse γ to retrieve components γ = (u_11, u_21, e_1, v_1, u_12, u_22, e_2, v_2, L, n_1, n_2, nonce, φ).
2. Verify NIZKPKi: 
  1. for j ∈ {1,2} compute:
    1. α'_j = decodeIntEd448_big-endian(SHA-3_512(u1_j ∥ u_2j ∥ e_j))
    2. T'_1j = (g1⊗n_j) ⊕ (u_1j⊗L)
    3. T'_2j = (g2⊗n_j) ⊕ (u_2j⊗L)
    4. T'_3j = (c_j ⊕ (d_j⊗a'_j))⊗n_j ⊕ (v_j⊗L)
  2. T'_4 = ((h1⊗n1) ⊖ ( h2⊗n2)) ⊕ ((e1 ⊖ e2)⊗L)
  3. Compute L' = decodeIntEd448_big-endian(SHA-3_512(g1 ∥ g2 ∥ q ∥ pk_1 ∥ pk_2 ∥ u_11 ∥ u_21 ∥ e_1 ∥ v_1 ∥ α'_1 ∥ u_12 ∥ u_22 ∥ e_2 ∥ v_2 ∥ α'_2 ∥ T'_11 ∥ T'_21 ∥ T'_31 ∥ T'_12 ∥ T'_22 ∥ T'_32 ∥ T'_4 )).
  4. Verify L ≟ L.
  5. for i ∈ {1,2}:
    1. Verify ((u_1i⊗x_1i) ⊕ (u_2i⊗x_2i)) ⊕ (((u_1i⊗y_1i) ⊕ (u_2i⊗y_2i))⊗α'_i) ≟ v_i.
3. Recover secret key K_enc = (e_i) ⊖ (u1_i⊗z_i).
4. Decrypt m = XSalsa20-Poly1305_K_enc(φ, nonce).


================================================================
## ROM-based Authentication

The Authentication scheme consists of two functions:

1. `σ = Auth(A_i,a_i,{A_1,A_2,A_3}, m)`, an authentication function

2. `Verif({A_1,A_2,A_3}, σ, m)`, a verification function


## Setup

We reuse the previously defined generator in Cramer-Shoup of DRE:

g = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160).

### Authentication: Auth(A_2, a_i, {A_1,A_2,A_3}, m):

a_i is one of the secret key of the three public keys {A_1,A_2,A_3}.

m is the message to be signed.

1. Choose t_1, c_2, c_3, r_2, r_3 randomly from Z_ℓ.
2. Compute T_1 = g⊗t_1.
3. Compute T_2 = (g⊗r_2) ⊕ (A_2⊗c_2), and T_3 = (g⊗r_3) ⊕ (A_3⊗c_3).
4. Compute c = decodeIntEd448_big-endian(SHA3-512(g ∥ q ∥ A_1 ∥ A_2 ∥ A_3 ∥ T_1 ∥ T_2 ∥ T_3 ∥ m )).
5. Compute c_1 = c - c_2 - c_3 (mod ℓ).
6. Compute r_1 = t_1 - c_1 * a_1 (mod ℓ). 
7. Send σ = (c_1, r_1, c_2, r_2, c_3, r_3).

### Verification: Verif({A_1,A_2,A_3},σ,m)

1. Parse σ to retrive components (c_1, r_1, c_2, r_2, c_3, r_3).
2. Compute c' = decodeIntEd448_big-endian(SHA3-256(g ∥ q ∥ A_1 ∥ A_2 ∥ A_3 ∥ (g⊗r_1) ⊕ (A_1⊗c_1) ∥ (g⊗r_2) ⊕ (A_2⊗c_2) ∥ (g⊗r_3) ⊕ (A_3⊗c_3) ∥ m )).
3. Check if c' ≟ c_1 + c_2 + c_3 (mod ℓ).

