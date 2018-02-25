// OpenCrypto RSA Unit Test
const crypto = new OpenCrypto();
let _keyPair = null;
let _pemPrivateKey = null;
let _pemPublicKey = null;
let _encryptedPrivateKey = null;
let _asymmetricallyEncryptedData = null;
let _asymmetricallyEncryptedSharedKey = null;

describe('RSA', function() {
    describe('generate keys', function() {
        it('should return 1024 bit key pair', function(done) {
            this.timeout(10000);
            crypto.getKeyPair(1024, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], 'SHA-256').then(function(keyPair) {
                _keyPair = keyPair;
                done();
            })
        })
    })

    describe('convert keys', function() {
        it('should return PEM private key', function(done) {
            crypto.cryptoPrivateToPem(_keyPair.privateKey).then(function(pemPrivateKey) {
                _pemPrivateKey = pemPrivateKey;
                done();
            })
        })

        it('should return CryptoKey private key', function(done) {
            crypto.pemPrivateToCrypto(_pemPrivateKey).then(function(cryptoPrivateKey) {
                done();
            })
        })

        it('should return PEM public key', function(done) {
            crypto.cryptoPublicToPem(_keyPair.publicKey).then(function(pemPublicKey) {
                _pemPublicKey = pemPublicKey;
                done();
            })
        })

        it('should return CryptoKey public key', function(done) {
            crypto.pemPublicToCrypto(_pemPublicKey).then(function(cryptoPublicKey) {
                done();
            });
        })
    })

    describe('encrypt and decrypt data asymmetrically', function() {
        it('should return asymmetrically encrypted data', function(done) {
            crypto.encryptPublic(_keyPair.publicKey, 'confidential').then(function(asymmetricallyEncryptedData) {
                _asymmetricallyEncryptedData = asymmetricallyEncryptedData;
                done();
            })
        })

        it('should return asymmetrically decrypted data', function(done) {
            crypto.decryptPrivate(_keyPair.privateKey, _asymmetricallyEncryptedData).then(function(asymmetricallyDecryptedData) {
                done();
            })
        })
    })

    describe('encrypt and decrypt shared key', function() {
        it('should return asymmetrically encrypted shared key', function(done) {
            crypto.getSessionKey(256).then(function(sharedKey) {
                crypto.encryptKey(_keyPair.publicKey, sharedKey, 'SHA-512').then(function(asymmetricallyEncryptedSharedKey) {
                    _asymmetricallyEncryptedSharedKey = asymmetricallyEncryptedSharedKey;
                    done();
                })
            })
        })

        it('should return asymmetrically decrypted shared key', function(done) {
            crypto.decryptKey(_keyPair.privateKey, _asymmetricallyEncryptedSharedKey, 'AES-GCM', 256, 1024, 'SHA-512').then(function(asymmetricallyDecryptedSharedKey) {
                done();
            })
        })
    })

    describe('encrypt and decrypt private key', function() {
        it('should return encrypted private key PKCS8', function(done) {
            crypto.encryptPrivateKey(_keyPair.privateKey, 'securepassphrase', 1000, 'SHA-512', 'AES-CBC', 256).then(function(encryptedPrivateKey) {
                _encryptedPrivateKey = encryptedPrivateKey;
                done();
            })
        })

        it('should return decrypted private key PKCS8', function(done) {
            crypto.decryptPrivateKey(_encryptedPrivateKey, 'securepassphrase').then(function(decryptedPrivateKey) {
                done();
            })
        })
    })

    describe('get key fingerprint', function() {
        it('should return key fingerprint', function(done) {
            crypto.cryptoKeyToFingerprint(_keyPair.publicKey, 'SHA-512').then(function(keyFingerprint) {
                done();
            })
        })
    })
})