const verifyAnonAadhaarProof = async (proof) => {
  // 1. Verify the proof structure
  if (!isValidProofStructure(proof)) {
    return false;
  }

  // 2. Verify timestamp is not too old (e.g., within last 24 hours)
  const proofTimestamp = parseInt(proof.timestamp);
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const maxAge = 24 * 60 * 60; // 24 hours in seconds
  
  if (currentTimestamp - proofTimestamp > maxAge) {
    return false;
  }

  // 3. Verify the Groth16 proof
  if (!isValidGroth16Proof(proof.groth16Proof)) {
    return false;
  }

  // 4. Verify the signal hash matches the expected format
  if (!isValidSignalHash(proof.signalHash)) {
    return false;
  }

  // 5. Verify the public key hash
  if (!isValidPublicKeyHash(proof.pubkeyHash)) {
    return false;
  }

  // 6. Verify the revealed attributes are within valid ranges
  if (!areAttributesValid(proof)) {
    return false;
  }

  return true;
};

function isValidProofStructure(proof) {
  return (
    proof.groth16Proof !== undefined &&
    proof.pubkeyHash !== undefined &&
    proof.timestamp !== undefined &&
    proof.nullifierSeed !== undefined &&
    proof.nullifier !== undefined &&
    proof.signalHash !== undefined &&
    proof.ageAbove18 !== undefined &&
    proof.gender !== undefined &&
    proof.pincode !== undefined &&
    proof.state !== undefined
  );
}

function isValidGroth16Proof(proof) {
  return (
    Array.isArray(proof.pi_a) &&
    Array.isArray(proof.pi_b) &&
    Array.isArray(proof.pi_c) &&
    proof.protocol === "groth16" &&
    proof.curve === "bn254"
  );
}

function isValidSignalHash(signalHash) {
  return /^0x[a-fA-F0-9]{64}$/.test(signalHash);
}

function isValidPublicKeyHash(pubkeyHash) {
  return /^0x[a-fA-F0-9]{64}$/.test(pubkeyHash);
}

function areAttributesValid(proof) {
  if (proof.ageAbove18 !== "1") {
    return false;
  }

  const validGenders = ["1", "2", "3"];
  if (!validGenders.includes(proof.gender)) {
    return false;
  }

  if (!/^\d{6}$/.test(proof.pincode)) {
    return false;
  }

  if (proof.state.length !== 2) {
    return false;
  }

  return true;
}

const go = async () => {
  const proof = JSON.parse(Lit.Actions.pubsubRequest("message").response);
  const isValid = await verifyAnonAadhaarProof(proof);
  Lit.Actions.setResponse({ response: JSON.stringify({ isValid }) });
};

go(); 