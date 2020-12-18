// OpenCrypto PBKDF2 Test

describe('password hashing', function () {
  it('should return hashed passphrase', function (done) {
    crypto.getRandomBytes(16).then(function (salt) {
      crypto.hashPassphrase('passphrase', salt, 1000).then(function (derivedHash) {
        done()
      })
    })
  })
})
