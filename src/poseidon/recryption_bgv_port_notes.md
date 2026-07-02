# BGV Recryption Port Notes

The file copied from HElib, `HElib/src/recryption.cpp`, implements HElib BGV
recryption/bootstrapping. It is not CKKS bootstrapping. In Poseidon terms this
port must target the BGV scheme.

Current implemented pieces in `poseidon/src/poseidon/recryption.cpp`:

- HElib-style level reduction before bootstrapping.
- Key switching from the normal secret key to the bootstrapping secret key.
- BGV NTT-to-coefficient conversion before raw modulus switching.
- Raw modulus switch to `q = p^e + 1`.
- `makeDivisible` by adding small multiples of `q`.
- Division by `p^e'`.
- Per-ciphertext BGV plaintext-space metadata: `bgv_plaintext_space` and
  `bgv_int_factor`, modeled after HElib `Ctxt::ptxtSpace` and `intFactor`.
- HElib-style `divideByP`, `multByP`, `reducePtxtSpace`, and
  `effectiveR` primitives for BGV ciphertexts.
- A basic thin digit-extraction primitive for already-unpacked BGV slots when
  the plaintext base is `p=2` or `p=3`.
- BGV `multiply_by_diag_matrix_bsgs`, needed by slot linear maps, is no longer
  an empty stub.
- `Recryptor::recrypt` now follows the HElib thin BGV order once maps are
  supplied: `slotToCoeff`, bootstrapping key-switch/preprocess/compose,
  `coeffToSlot`, then `extractDigitsThin`. It fails explicitly if the maps or
  their Galois keys are absent.
- `RecryptionData::set_linear_maps` and
  `bgv_recryption_required_galois_steps` provide the plumbing needed to attach
  generated BGV EvalMap/ThinEvalMap matrices and build their rotation keys.
- `bgv_build_thin_recryption_maps` is now the public construction point for
  BGV thin-recryption maps. The current implementation builds Poseidon
  BatchEncoder-style coefficient/slot DWT maps; this is useful plumbing, but it
  is not yet a verified HElib `ThinEvalMap` equivalent.

Pieces still missing for a real public BGV bootstrap:

- A bootstrapping plaintext-space path for `p^(e-e'+r)`. HElib creates an
  auxiliary `PAlgebraMod` and `EncryptedArray` over this space in
  `RecryptData::init`. Poseidon currently stores one `plain_modulus` in
  `ParametersLiteral` and builds `plain_ntt_tables` for it at context creation.
- HElib bootstrapping expects a small plaintext base `p` and ciphertexts whose
  plaintext space can be `p^r`, `p^(r-1)`, and so on. Poseidon's default BGV
  parameters use a batching prime, for example `786433` at degree 16384. Treating
  that batching prime as HElib's small `p` would make digit-extraction
  polynomial degrees unusably large and is not the intended HElib parameter
  model.
- Conversely, forcing the recryption metadata to `p=2` while the Poseidon BGV
  context still has `plain_modulus=786433` is also not a faithful HElib setup:
  arithmetic, `correction_factor`, `BatchEncoder`, and decryption still live
  modulo `786433`.
- A Poseidon equivalent of HElib `PowerfulDCRT`. HElib performs raw
  mod-switch and make-divisible in powerful basis; the current Poseidon code
  uses coefficient order, which is only equivalent for special/simple rings and
  still needs an explicit audited mapping.
- BGV slot linear-map generation equivalent to HElib `EvalMap` and
  `ThinEvalMap` from `HElib/src/EvalMap.cpp`. Poseidon now has the BGV
  diagonal-matrix multiplication primitive and the recryption plumbing for
  maps, but still needs generated sparse `LinearMatrixGroup` matrices
  corresponding to HElib's coefficient/powerful-to-slot and
  slot-to-coefficient maps. For thin bootstrapping this must include the
  `ThinEvalMap::apply` trace/inflate behavior; CKKS DFT matrices and identity
  maps are not valid substitutes.
- Encrypted digit extraction equivalent to HElib `extractDigitsPacked` and
  full `extractDigitsThin`. A basic thin path exists
  for `p=2` and `p=3`; still missing are the `p>3` digit polynomial path,
  Chen-Han path, packed unpack/repack, and integration into `Recryptor::recrypt`.
- Bootstrap-key semantics matching HElib `SecKey::genRecryptData`: the
  encrypted bootstrapping key must be encrypted under the original key but in
  the auxiliary plaintext space, not just encoded under the normal batching
  modulus.

Do not replace these pieces with decrypt-and-encrypt refresh. That is not
public bootstrapping.
