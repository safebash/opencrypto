// OpenCrypto ECC Unit Test

describe('ECC', function() {
    describe('generate keys', function() {
        it('should return key pair', function(done) {
            crypto.getEcKeyPair('P-256').then(function(keyPair) {
                done();
            })
        })
    })
})