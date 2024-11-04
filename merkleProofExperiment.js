// merkleProofExperiment.js

const { Trie } = require('@ethereumjs/trie'); // => Trie class from ethereumjs/trie
const { keccak256 } = require('ethereum-cryptography/keccak'); // => For Keccak-256 hashing
const { bytesToHex, utf8ToBytes } = require('ethereum-cryptography/utils');
const { KECCAK256_RLP } = require('ethereumjs-util'); // => Precomputed hash of empty RLP string
const RLP = require('rlp'); // => Recursive Length Prefix encoding/decoding

// RLP encoding of an empty array (used since in these experiment there are empty account fields)
const rlpEncodedEmptyString = RLP.encode([]);
// Hash of the empty RLP-encoded string (used as default storageRoot and codeHash)
const emptyHash = keccak256(rlpEncodedEmptyString);

async function generateTrie() {
    // Initializing a new trie
    const trie = new Trie();

    // Sample accounts with balances
    const accounts = {
        '0x1111111111111111111111111111111111111111': { balance: '1000' }, // => Account 1
        '0x2222222222222222222222222222222222222222': { balance: '2000' }, // => Account 2
        '0x3333333333333333333333333333333333333333': { balance: '3000' }, // => Account 3
    };

    // Add accounts to the trie
    for (const [address, accountData] of Object.entries(accounts)) {
        // Convert address from hex string to buffer also remove '0x' prefix
        const addressBuffer = Buffer.from(address.slice(2), 'hex');
        // Hash the address to get the trie key
        const key = keccak256(addressBuffer);
        console.log('Adding account with key:', bytesToHex(key));

        // Encode the balance as a BigInt
        const balanceValue = BigInt(accountData.balance);

        // Create the account RLP encoding
        const accountRLP = RLP.encode([
            Buffer.from([]),    // => nonce (empty)
            RLP.encode(balanceValue), // => balance (encoded as RLP)
            KECCAK256_RLP,            // => storageRoot (empty trie root hash)
            KECCAK256_RLP,            // => codeHash (empty code hash)
        ]);

        // Inserting the account created above into the trie
        await trie.put(key, accountRLP);
    }

    // Get the root hash of the trie (represents the current state)
    const rootHash = trie.root();
    console.log('Trie Root Hash:', bytesToHex(rootHash));

    // Choose an arbitrary account to generate a proof for
    const targetAddress = '0x1111111111111111111111111111111111111111';

    // Generate Merkle proof for the targetAddress
    const { proof, value } = await generateProof(trie, targetAddress);

    // Verify the proof to retrieve account data
    const verifiedValue = await verifyProof(targetAddress, proof);

    // Decode the RLP data to get account details
    const decodedAccount = RLP.decode(verifiedValue);
    console.log('Decoded Account Data:', decodedAccount);

    // Balance
    const balanceBuffer = RLP.decode(decodedAccount[1]);
    const balance = BigInt('0x' + Buffer.from(balanceBuffer).toString('hex'));
    console.log('Account Balance:', balance.toString());
}


async function generateProof(trie, address) {
    // Convert address to buffer and hash the address to get the key in the trie
    const addressBuffer = Buffer.from(address.slice(2), 'hex');
    const key = keccak256(addressBuffer);
    console.log('Generating proof for key:', bytesToHex(key));

    // Generate the Merkle Proof for the given key
    const proof = await trie.createProof(key);
    console.log('Merkle Proof:', proof);

    // Get the account data from the trie
    const value = await trie.get(key);
    console.log('Account RLP:', value);

    return { proof, value };
}


async function verifyProof(address, proof) {
    // Convert address to buffer and hash the address to get the key in the trie
    const addressBuffer = Buffer.from(address.slice(2), 'hex');
    const key = keccak256(addressBuffer);

    console.log('Verifying proof for key:', bytesToHex(key));

    try {
        // Use the static verifyProof method to check the proof
        const value = await Trie.verifyProof(key, proof);
        console.log('Verified Account RLP:', value);

        return value;
    } catch (error) {
        console.error('Proof verification failed:', error);
        return null;
    }
}

// Executing generateTrie function
(async () => {
    await generateTrie();
})();
