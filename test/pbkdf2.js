// OpenCrypto PBKDF2 Test

describe('password hashing', function () {
  it('should return hashed passphrase', function (done) {
    crypto.getRandomBytes(16).then(function (salt) {
      crypto.hashPassphrase('randompassphrase', salt, 1000, 'SHA-512', 256).then(function (hashedPassphrase) {
        done()
      })
    })
  })
})
