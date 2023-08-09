# ProvableMerkleTrees

## Introduction

This repo provides Rust code to build Merkle Trees, equipped with a `Provable` interface to generate Zero Knowledge proofs
attesting for the correctness of the underlying Merkle Tree structure. That is, the provided root is generated via recursive hashes of parent and child nodes.

We use Plonky2 as our proof system, as we rely heavily on recursion to generate proofs. Our approach works by recursively proving that each `parent_hash` corresponds to the `Poseidon` hash of its child hashes `(left_child_hash, right_child_hash)`.

## Implementation considerations:

0. Merkle Trees are encapsulated in a `MerkleTree` struct.
1. We use `PoseidonHash` as our native hash function. We use the `Goldilocks` field, as our natural choice of field.
2. We define a `Provable` interface, which `MerkleTree` implements to generate proof data directly (to be verified later).
This has the advantage to abstract away the creation and use of circuits and witnesses. Leaving the user, with simple to use methods
to generate/verify proofs.
3. We make auxiliary use of a `CircuitCompiler` interface, that allows to evaluate a type (think of the evaluation of a `MerkleTree` to be its root), compile its value to a circuit and to fill the circuit targets with the corresponding type values.
4. We use a structure `PairwiseHash` to encapsulate the logic of a parent hash generated from a pair of left and right child hashes.
5. The `PairwiseHash` struct also implements the `Provable` (and `CircuitCompiler`) interface, which then is used to recursively
verify the `MerkleTree` hashing generation.
6. We provide extensive testing. Our tests cover the examples in which a given well generated Merkle Tree is proved and verified correctly, as well, failure case for ill formed Merkle Trees (by changing data, root and digests).

## Other remarks

We decided to use `PoseidonHash::hash_or_noop` as the default hash method (it acts as the identity, on values that fit in 256-bit memory), to be consistent with Plonky2's `MerkleTree` default behavior.
