const TxBuilder = require('./lib/transaction_builder')
const API = require('./lib/api')
const Crypto = require('./lib/crypto')
const { uint8ArrayToHex} = require('./lib/utils')
const { randomBytes } = require("crypto")

module.exports = {
    
    /**
     * Create a new TransactionBuilder instance to forge transaction
     * @param {String} type Transaction type ("identity", "keychain", "transfer", "hosting", "code_proposal", "code_approval", "nft")
     */
    newTransactionBuilder: function (type) {
        return new TxBuilder(type)
    },

    /**
     * Send the transaction to a node
     * @param {Object} tx Transaction to send
     * @param {String} endpoint Node endpoint
     */
    sendTransaction: function(tx, endpoint) {
        return API.sendTx(tx, endpoint)
    },

    /**
     * Derive a keypair
     * @param {String} seed TransactionChain seed
     * @param {Integer} index Number of transaction in the chain
     * @param {String} curve  Elliptic curve to use ("ed25519", "P256", "secp256k1")
     */
    deriveKeyPair(seed, index, curve = "ed25519") {
        const { privateKey, publicKey}  = Crypto.deriveKeyPair(seed, index, curve)
        return {
            privateKey: uint8ArrayToHex(privateKey),
            publicKey: uint8ArrayToHex(publicKey)
        }
    },

    /**
     * Derive an address
     * @param {String} seed TransactionChain seed
     * @param {Integer} index Number of transaction in the chain
     * @param {String} curve  Elliptic curve to use ("ed25519", "P256", "secp256k1")
     * @param {String} hashAlgo  Hash algorithm ("sha256", "sha512", "sha3-256", "sha3-512", "blake2b")
     */
    deriveAddress(seed, index, curve = "ed25519", hashAlgo = "sha256") {
        const { publicKey } = Crypto.deriveKeyPair(seed, index, curve)
        return uint8ArrayToHex(Crypto.hash(publicKey, hashAlgo))
    },

    /**
     * Encrypt a data for a given public key using ECIES algorithm
     * @param {String | Uint8Array} data Data to encrypt
     * @param {String | Uint8Array} publicKey Public key for the shared secret encryption
     */
    ecEncrypt: function (data, publicKey) {
        const ciphertext = Crypto.ecEncrypt(data, publicKey)
        return uint8ArrayToHex(ciphertext)
    },

    /**
     * Encrypt a data for a given public key using AES algorithm
     * @param {String | Uint8Array} data Data to encrypt
     * @param {String | Uint8Array} key Symmetric key
     */
    aesEncrypt: function (data, key) {
        const ciphertext = Crypto.aesEncrypt(data, key)
        return uint8ArrayToHex(ciphertext)
    },

    /**
     * Retrieve the index of transaction in a specific chain. (aka. the number of transaction on the chain)
     * @param {String} address Transaction address
     * @param {String} endpoint Node endpoint
     */
    getTransactionIndex: function (address, endpoint) {
        return API.getTransactionIndex(address, endpoint)
    },

    /**
     * Generate a random secret key of 32 bytes
     */
    randomSecretKey: function() {
        return new Uint8Array(randomBytes(32))
    },

    /**
     * Retrieve the storage nonce public key to encrypt data towards nodes
     * @param {String} endpoint Node endpoint
     */
    getStorageNoncePublicKey: function (endpoint) {
        return API.getStorageNoncePublicKey(endpoint)
    },

    /**
     * Create a keychain and an access keychain using the initial passphrase
     * @param {String | Uint8Array} passphrase Initial access passphrase
     * @param {*} originPrivateKey Origin private key
     * @returns Keychain transaction address
     */
    createKeychain: async function(passphrase, originPrivateKey) {
        access_keychain_seed = Crypto.hash(passphrase)
        const { publicKey } = Crypto.deriveKeyPair(access_keychain_seed, 0)

        const keychain_seed = randomBytes(32)
        const keychain_address = this.deriveAddress(keychain_seed, 0)

        const access_keychain_aes_key = randomBytes(32)

        const access_keychain_tx = this.newTransactionBuilder("keychain_access")
            .setSecret(Crypto.aesEncrypt(keychain_address), access_keychain_aes_key)
            .addAuthorizedKey(publicKey, Crypto.ecEncrypt(publicKey, access_keychain_aes_key))
            .build(access_keychain_seed, 0)
            .originSign(originPrivateKey)

        const { publicKey: keychainPublicKey } = Crypto.deriveKeyPair(keychain_seed, 0)

        const keychain_aes_key = randomBytes(32)

        const keychain_tx = this.newTransactionBuilder("keychain")
            .setSecret(Crypto.aesEncrypt(JSON.stringify({ keychain_seed: keychain_seed }), keychain_aes_key))
            .addAuthorizedKey(publicKey, Crypto.ecEncrypt(keychain_aes_key), publicKey)
            .addAuthorizedKey(keychainPublicKey, Crypto.ecEncrypt(keychain_aes_key, keychainPublicKey))
            .build(keychain_seed, 0)
            .originSign(originPrivateKey)


        const [access_keychain_res, keychain_res] = await Promise.all([this.sendTransaction(access_keychain_tx), this.sendTransaction(keychain_tx)])
        if (access_keychain_res.status == "ok" && keychain_res.status == "ok") {
            return keychain_tx.address
        } else {
            throw "Something goes wrong !"
        }
    }
}
