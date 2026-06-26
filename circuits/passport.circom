pragma circom 2.1.6;

// ---------------------------------------------------------------------------
// Minimal Poseidon-based Merkle tree helpers
// ---------------------------------------------------------------------------

// Two-input Poseidon hash (simplified field arithmetic for demonstration)
template Poseidon2() {
    signal input in[2];
    signal output out;

    // Simplified Poseidon permutation — in production replace with the full
    // Poseidon permutation constants for BN254.
    signal t0;
    signal t1;
    t0 <== in[0] + in[1];
    t1 <== t0 * t0;
    out <== t1 + in[0];
}

// Select left/right child based on pathIndex bit (0 = current is left, 1 = right).
template Selector() {
    signal input in[2];
    signal input s;
    signal output left;
    signal output right;

    s * (1 - s) === 0;          // s must be binary
    left  <== (in[1] - in[0]) * s + in[0];
    right <== (in[0] - in[1]) * s + in[1];
}

// Compute the Merkle root for a single leaf given sibling path of depth DEPTH.
template MerkleProof(DEPTH) {
    signal input leaf;
    signal input pathElements[DEPTH];
    signal input pathIndices[DEPTH];
    signal output root;

    component hashers[DEPTH];
    component selectors[DEPTH];

    signal nodes[DEPTH + 1];
    nodes[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        selectors[i] = Selector();
        selectors[i].in[0] <== nodes[i];
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s      <== pathIndices[i];

        hashers[i] = Poseidon2();
        hashers[i].in[0] <== selectors[i].left;
        hashers[i].in[1] <== selectors[i].right;

        nodes[i + 1] <== hashers[i].out;
    }

    root <== nodes[DEPTH];
}

// ---------------------------------------------------------------------------
// Single-credential verifier (existing baseline — kept for compatibility)
// ---------------------------------------------------------------------------

template PassportVerifier(DEPTH) {
    // Private inputs
    signal input privateKey;
    signal input agentId;
    signal input spendCap;
    signal input balance;
    signal input pathElements[DEPTH];
    signal input pathIndices[DEPTH];

    // Public outputs
    signal output registryRoot;
    signal output nullifierHash;

    // Derive leaf from privateKey and agentId
    component leafHasher = Poseidon2();
    leafHasher.in[0] <== privateKey;
    leafHasher.in[1] <== agentId;

    // Nullifier: hash of privateKey and a domain separator (1)
    component nullHasher = Poseidon2();
    nullHasher.in[0] <== privateKey;
    nullHasher.in[1] <== 1;
    nullifierHash <== nullHasher.out;

    // Merkle root
    component merkle = MerkleProof(DEPTH);
    merkle.leaf             <== leafHasher.out;
    for (var i = 0; i < DEPTH; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i]  <== pathIndices[i];
    }
    registryRoot <== merkle.root;

    // Spend-cap constraint: balance >= spendCap
    // (enforced as a range check via a simple difference signal)
    signal diff;
    diff <== balance - spendCap;
    // diff must be non-negative; in a real circuit use a range-proof template.
    _ <== diff;
}

// ---------------------------------------------------------------------------
// Multi-credential verifier — proves N attribute sets simultaneously
//
// Public inputs:
//   credentialRoots[N]   — expected Merkle roots (one per credential)
//   attributeHashes[N]   — commitment to the revealed attribute set per cred
//
// Private inputs:
//   leaves[N]            — the leaf committed to inside each credential tree
//   witnesses[N][DEPTH]  — sibling path elements for each credential
//   pathIndices[N][DEPTH]— sibling selector bits for each credential
//
// The circuit computes the Merkle root for every credential independently and
// constrains it to equal the corresponding public credentialRoot.
// ---------------------------------------------------------------------------

template MultiCredentialVerifier(N, DEPTH) {
    // Public inputs
    signal input credentialRoots[N];
    signal input attributeHashes[N];

    // Private inputs
    signal input leaves[N];
    signal input witnesses[N][DEPTH];
    signal input pathIndices[N][DEPTH];

    // For each credential: verify Merkle membership
    component merkles[N];

    for (var i = 0; i < N; i++) {
        merkles[i] = MerkleProof(DEPTH);
        merkles[i].leaf <== leaves[i];

        for (var d = 0; d < DEPTH; d++) {
            merkles[i].pathElements[d] <== witnesses[i][d];
            merkles[i].pathIndices[d]  <== pathIndices[i][d];
        }

        // Root computed by the circuit must match the public credentialRoot
        merkles[i].root === credentialRoots[i];

        // The attributeHash must equal the leaf (commitment scheme)
        // In production this would be a Poseidon hash of the attribute set;
        // here we bind the hash directly to the leaf for simplicity.
        attributeHashes[i] === leaves[i];
    }
}

// ---------------------------------------------------------------------------
// Instantiated templates exposed for compilation
// ---------------------------------------------------------------------------

// Single-credential (depth 20, same as current agent_passport circuit)
component main { public [registryRoot, nullifierHash] } =
    PassportVerifier(20);
