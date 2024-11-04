// merkleProofExperiment.js

const { Trie } = require('@ethereumjs/trie');
const { keccak256 } = require('ethereum-cryptography/keccak');
const { bytesToHex, utf8ToBytes } = require('ethereum-cryptography/utils');
const { KECCAK256_RLP } = require('ethereumjs-util');
const RLP = require('rlp');

const rlpEncodedEmptyString = RLP.encode([]);
const emptyHash = keccak256(rlpEncodedEmptyString);

async function generateTrie() {
    // Initialize a new trie
    const trie = new Trie();

    // Sample accounts with balances
    const accounts = {
        '0x1111111111111111111111111111111111111111': { balance: '1000' },
        '0x2222222222222222222222222222222222222222': { balance: '2000' },
        '0x3333333333333333333333333333333333333333': { balance: '3000' },
    };

    // Add accounts to the trie
    for (const [address, accountData] of Object.entries(accounts)) {
        const addressBuffer = Buffer.from(address.slice(2), 'hex');
        const key = keccak256(addressBuffer);
        console.log('Adding account with key:', bytesToHex(key));

        // Encode the balance as a BigInt
        const balanceValue = BigInt(accountData.balance);

        // Create the account RLP encoding (nonce, balance, storageRoot, codeHash)
        const accountRLP = RLP.encode([
            Buffer.from([]), // nonce
            RLP.encode(balanceValue), // balance
            KECCAK256_RLP, // storageRoot
            KECCAK256_RLP, // codeHash
        ]);

        // Put the account into the trie
        await trie.put(key, accountRLP);
    }

    // Get the root hash of the trie
    const rootHash = trie.root();
    console.log('Trie Root Hash:', bytesToHex(rootHash));

    // Choose an account to generate a proof for
    const targetAddress = '0x1111111111111111111111111111111111111111';

    // Generate Merkle proof
    const { proof, value } = await generateProof(trie, targetAddress);

    // Verify the proof
    const verifiedValue = await verifyProof(rootHash, targetAddress, proof);

    // Decode the RLP data
    const decodedAccount = RLP.decode(verifiedValue);
    console.log('Decoded Account Data:', decodedAccount);

    // Display the balance
    const balanceBuffer = RLP.decode(decodedAccount[1]);
    const balance = BigInt('0x' + Buffer.from(balanceBuffer).toString('hex'));
    console.log('Account Balance:', balance.toString());
}


async function generateProof(trie, address) {
    const addressBuffer = Buffer.from(address.slice(2), 'hex');
    const key = keccak256(addressBuffer);
    console.log('Generating proof for key:', bytesToHex(key));

    // Generate proof
    const proof = await trie.createProof(key);
    console.log('Merkle Proof:', proof);

    // Get the value (account data)
    const value = await trie.get(key);
    console.log('Account RLP:', value);

    return { proof, value };
}


async function verifyProof(rootHash, address, proof) {
    const addressBuffer = Buffer.from(address.slice(2), 'hex');
    const key = keccak256(addressBuffer);

    console.log('Verifying proof for key:', bytesToHex(key));

    // Ensure that rootHash, key, and proof are the correct types
    // rootHash: Uint8Array
    // key: Uint8Array
    // proof: Uint8Array[]

    // Verify proof
    const value = await Trie.verifyProof(key, proof);
    console.log('Verified Account RLP:', value);

    return value;
}

(async () => {
    await generateTrie();
})();
