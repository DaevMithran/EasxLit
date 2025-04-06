export const accessControlConditions: {
  name: string
  condition: any
}[] = [
  {
    name: "Proof of Humanity",
    condition: {
      conditionType: "evmBasic",
      contractAddress: "0xC5E9dDebb09Cd64DfaCab4011A0D5cEDaf7c9BDb",
      standardContractType: "ProofOfHumanity",
      chain: "amoy",
      method: "isRegistered",
      parameters: [":userAddress"],
      returnValueTest: {
        comparator: "=",
        value: "true",
      },
    },
  },
  {
    name: "NFT Owner",
    condition: {
      conditionType: "evmBasic",
      contractAddress: "0xCd2AE5e5371A6f667726A76B36D5CC161a5fB3e6",
      standardContractType: "ERC721",
      chain: "amoy",
      method: "ownerOf",
      parameters: ["1"],
      returnValueTest: {
        comparator: "=",
        value: ":userAddress",
      },
    },
  },
  {
    name: "Burning Man 2021 POAP",
    condition: {
      conditionType: "evmBasic",
      contractAddress: "0x22C1f6050E56d2876009903609a2cC3fEf83B415",
      standardContractType: "POAP",
      chain: "amoy",
      method: "tokenURI",
      parameters: [],
      returnValueTest: {
        comparator: "contains",
        value: "Burning Man 2021",
      },
    },
  },
  {
    name: "Timelock",
    condition: {
      conditionType: "evmBasic",
      contractAddress: "",
      standardContractType: "timestamp",
      chain: "amoy",
      method: "eth_getBlockByNumber",
      parameters: ["latest"],
      returnValueTest: {
        comparator: ">=",
        value: "1733600192",
      },
    },
  },
  {
    name: "Token Holder",
    condition: {
      contractAddress: "",
      standardContractType: "",
      conditionType: "evmBasic",
      chain: "amoy",
      method: "eth_getBalance",
      parameters: [":userAddress"],
      returnValueTest: {
        comparator: ">",
        value: "0",
      },
    },
  },
  {
    name: "AnonAadhaar",
    condition: {
      conditionType: "evmContract",
      contractAddress: "0x6bE8Cec7a06BA19c39ef328e8c8940cEfeF7E281",
      functionName: "verifyAnonAadhaarProof",
      functionParams: [
        ":litParam:nullifierSeed",
        ":litParam:nullifier",
        ":litParam:timestamp",
        "1",
        ":litParam:revealArray",
        ":litParam:groth16Proof",
      ],
      functionAbi: {
        inputs: [
          {
            internalType: "uint256",
            name: "nullifierSeed",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "nullifier",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "timestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "signal",
            type: "uint256",
          },
          {
            internalType: "uint256[4]",
            name: "revealArray",
            type: "uint256[4]",
          },
          {
            internalType: "uint256[8]",
            name: "groth16Proof",
            type: "uint256[8]",
          },
        ],
        name: "verifyAnonAadhaarProof",
        outputs: [
          {
            internalType: "bool",
            name: "",
            type: "bool",
          },
        ],
        stateMutability: "view",
        type: "function",
      },
      chain: "sepolia",
      returnValueTest: {
        key: "",
        comparator: "=",
        value: "false",
      },
    },
  },
  {
    name: "AnonAadhaar Lit Action",
    condition: {
      conditionType: "LitAction",
      contractAddress: "",
      standardContractType: "",
      chain: "sepolia",
      method: "verifyAnonAadhaarProof",
      parameters: [":litParam:proof"],
      returnValueTest: {
        comparator: "=",
        value: "true",
      },
      litActionCode: `
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

          if (!/^\\d{6}$/.test(proof.pincode)) {
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
      `,
    },
  },
]
