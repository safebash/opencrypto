// OpenCrypto AES Unit Test

let _sharedKey = null;
let _encryptedData = null;

describe('AES', function() {
    describe('generate keys', function() {
        it('should return shared key', function(done) {
            crypto.getSessionKey(256, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], true, 'AES-GCM').then(function(sharedKey) {
                _sharedKey = sharedKey;
                done();
            })
        })
    })

    describe('encrypt and decrypt data', function() {
        it('should encrypt data using the shared key', function(done) {
            crypto.encrypt(_sharedKey, 'confidential').then(function(encryptedData) {
                _encryptedData = encryptedData;
                done();
            })
        })

        it('should decrypt data using the shared key', function(done) {
            crypto.decrypt(_sharedKey, _encryptedData).then(function(decryptedData) {
                done();
            })
        })
    })
})