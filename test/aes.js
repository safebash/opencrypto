// OpenCrypto AES Unit Test

let _sharedKey = null
let _encryptedData = null

describe('AES', function () {
  describe('generate keys', function () {
    it('should return shared key', function (done) {
      crypto.getSharedKey(256, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], true, 'AES-GCM').then(function (sharedKey) {
        _sharedKey = sharedKey
        done()
      })
    })
  })

  describe('encrypt and decrypt data', function () {
    it('should encrypt data using the shared key', function (done) {
      let encodedData = crypto.stringToArrayBuffer('confidential')
      crypto.encrypt(_sharedKey, encodedData).then(function (encryptedData) {
        _encryptedData = encryptedData
        done()
      })
    })

    it('should decrypt data using the shared key', function (done) {
      crypto.decrypt(_sharedKey, _encryptedData).then(function (decryptedData) {
        done()
      })
    })
  })
})
