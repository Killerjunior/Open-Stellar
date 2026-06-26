#![no_std]

use soroban_sdk::{contract, contractimpl, symbol_short, Symbol, Bytes, BytesN, Env, Vec, panic_with_error};

#[contract]
pub struct PassportValidator;

#[contractimpl]
impl PassportValidator {
    /// Verifies the multi-credential proof.
    /// Panics if any root in `roots` is revoked.
    /// Emits `multi_credential_verified` event with the roots array.
    pub fn verify_multi_credential(
        env: Env,
        roots: Vec<BytesN<32>>,
        proof: Bytes,
        public_inputs: Vec<u64>,
    ) -> bool {
        // 1. Verify that all roots are NOT revoked.
        for i in 0..roots.len() {
            let root = roots.get(i).unwrap();
            if Self::is_root_revoked(env.clone(), root.clone()) {
                panic!("Root is revoked");
            }
        }

        // 2. Validate that the proof is not empty (mock ZK verification for the environment)
        if proof.len() == 0 {
            panic!("Empty ZK proof");
        }

        // 3. Emit multi_credential_verified event with the roots array
        env.events().publish(
            (Symbol::new(&env, "multi_credential_verified"),),
            roots,
        );

        true
    }

    /// Revokes a credential root.
    pub fn revoke_root(env: Env, root: BytesN<32>) {
        env.storage().persistent().set(&root, &true);
    }

    /// Unrevokes/restores a credential root.
    pub fn unrevoke_root(env: Env, root: BytesN<32>) {
        env.storage().persistent().set(&root, &false);
    }

    /// Checks if a root is revoked.
    pub fn is_root_revoked(env: Env, root: BytesN<32>) -> bool {
        env.storage().persistent().get::<BytesN<32>, bool>(&root).unwrap_or(false)
    }
}
