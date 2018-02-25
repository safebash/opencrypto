// OpenCrypto PBKDF2 Unit Test

describe('derive keys', function() {
    it('should return derived key', function(done) {
        crypto.keyFromPassphrase('randompassphrase', 'someone@example.com', 1000, 'SHA-512').then(function(derivedKey) {
            done();
        })
    })
})