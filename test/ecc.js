// OpenCrypto ECC Unit Test

let _ecKeyPair = null
let _ecEncryptedPrivateKey = null

describe('ECC', function () {
  describe('generate keys', function () {
    it('should return key pair', function (done) {
      crypto.getECKeyPair('P-256').then(function (keyPair) {
        _ecKeyPair = keyPair
        done()
      })
    })
  })

  describe('encrypt and decrypt private key', function () {
    it('should encrypt private key', function (done) {
      crypto.encryptPrivateKey(_ecKeyPair.privateKey, 'passphrase', 1000).then(function (encryptedPrivateKey) {
        _ecEncryptedPrivateKey = encryptedPrivateKey
        done()
      })
    })

    it('should decrypt encrypted private key', function (done) {
      crypto.decryptPrivateKey(_ecEncryptedPrivateKey, 'passphrase', { name: 'ECDH', namedCurve: 'P-256' }, [ 'deriveKey', 'deriveBits' ]).then(function (decryptedPrivateKey) {
        done()
      })
    })
  })
})
