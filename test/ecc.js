// OpenCrypto ECC Unit Test

let _ecKeyPair = null
let _ecEncryptedPrivateKey = null

describe('ECC', function () {
  describe('generate keys', function () {
    it('should return key pair', function (done) {
      crypto.getECKeyPair().then(function (keyPair) {
        _ecKeyPair = keyPair
        done()
      }).catch(function (err) {
        done(err)
      })
    })
  })

  describe('encrypt and decrypt private key', function () {
    it('should encrypt private key', function (done) {
      crypto.encryptPrivateKey(_ecKeyPair.privateKey, 'passphrase').then(function (encryptedPrivateKey) {
        _ecEncryptedPrivateKey = encryptedPrivateKey
        done()
      }).catch(function (err) {
        done(err)
      })
    })

    it('should decrypt encrypted private key', function (done) {
      crypto.decryptPrivateKey(_ecEncryptedPrivateKey, 'passphrase').then(function (decryptedPrivateKey) {
        done()
      }).catch(function (err) {
        done(err)
      })
    })
  })
})
