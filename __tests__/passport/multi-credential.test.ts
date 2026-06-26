import { describe, expect, it } from "vitest";
import { buildMultiCredentialProof, verifyMultiCredentialOnChain, type Credential } from "@/lib/passport/passport";

describe("ZK Multi-Credential Proofs", () => {
  // Test data for 2 mock credentials
  const credential1: Credential = {
    root: "12345678901234567890",
    attributeHash: "98765432109876543210",
    leaf: "11111111111111111111",
    witness: Array.from({ length: 20 }, (_, i) => String(i)),
    pathIndices: Array.from({ length: 20 }, (_, i) => i % 2),
  };

  const credential2: Credential = {
    root: "22345678901234567890",
    attributeHash: "88765432109876543210",
    leaf: "22222222222222222222",
    witness: Array.from({ length: 20 }, (_, i) => String(i * 2)),
    pathIndices: Array.from({ length: 20 }, (_, i) => (i + 1) % 2),
  };

  it("builds a combined proof correctly for 2 credentials", async () => {
    const credentials = [credential1, credential2];
    const { proof, publicInputs } = await buildMultiCredentialProof(credentials);

    expect(proof).toBeInstanceOf(Buffer);
    expect(proof.length).toBeGreaterThan(0);
    expect(publicInputs).toHaveLength(4); // 2 roots + 2 attribute hashes
    expect(publicInputs[0]).toBe(BigInt(credential1.root));
    expect(publicInputs[1]).toBe(BigInt(credential2.root));
    expect(publicInputs[2]).toBe(BigInt(credential1.attributeHash));
    expect(publicInputs[3]).toBe(BigInt(credential2.attributeHash));
  });

  it("passes verification for two valid credentials", async () => {
    const credentials = [credential1, credential2];
    const { proof, publicInputs } = await buildMultiCredentialProof(credentials);

    // Mock contract validator client
    const revokedRoots = new Set<string>();
    const mockClient = {
      async verify_multi_credential({ roots, proof: proofArg, public_inputs }) {
        // Roots are passed as buffer array
        for (const rootBuf of roots) {
          const rootHex = rootBuf.toString("hex");
          const rootBigInt = BigInt("0x" + rootHex).toString();
          if (revokedRoots.has(rootBigInt)) {
            throw new Error("Contract Error: Root is revoked");
          }
        }
        return true;
      }
    };

    const roots = credentials.map((c) => c.root);
    const result = await verifyMultiCredentialOnChain(roots, proof, publicInputs, mockClient);
    expect(result.ok).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("fails verification if one of the credential roots is revoked", async () => {
    const credentials = [credential1, credential2];
    const { proof, publicInputs } = await buildMultiCredentialProof(credentials);

    // Mock contract validator client with credential2 root revoked
    const revokedRoots = new Set<string>([credential2.root]);
    const mockClient = {
      async verify_multi_credential({ roots, proof: proofArg, public_inputs }) {
        for (const rootBuf of roots) {
          const rootHex = rootBuf.toString("hex");
          // Parse back to BigInt decimal string to match original root
          const rootBigInt = BigInt("0x" + rootHex).toString();
          if (revokedRoots.has(rootBigInt)) {
            throw new Error("Contract Error: Root is revoked");
          }
        }
        return true;
      }
    };

    const roots = credentials.map((c) => c.root);
    const result = await verifyMultiCredentialOnChain(roots, proof, publicInputs, mockClient);
    expect(result.ok).toBe(false);
    expect(result.error).toContain("Root is revoked");
  });
});
