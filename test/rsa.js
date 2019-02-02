// OpenCrypto RSA Unit Test
const crypto = new OpenCrypto()
let _rsaKeyPair = null
let _rsaPemPrivateKey = null
let _rsaPemPublicKey = null
let _rsaEncryptedPrivateKey = null
let _rsaAsymmetricallyEncryptedData = null
let _rsaAsymmetricallyEncryptedSharedKey = null

describe('RSA', function () {
  describe('generate keys', function () {
    it('should return 1024 bit key pair', function (done) {
      this.timeout(10000)
      crypto.getRSAKeyPair(1024, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], 'SHA-256').then(function (keyPair) {
        _rsaKeyPair = keyPair
        done()
      })
    })
  })

  describe('convert keys', function () {
    it('should return PEM private key', function (done) {
      crypto.cryptoPrivateToPem(_rsaKeyPair.privateKey).then(function (pemPrivateKey) {
        _rsaPemPrivateKey = pemPrivateKey
        done()
      })
    })

    it('should return CryptoKey private key', function (done) {
      crypto.pemPrivateToCrypto(_rsaPemPrivateKey).then(function (cryptoPrivateKey) {
        done()
      })
    })

    it('should return PEM public key', function (done) {
      crypto.cryptoPublicToPem(_rsaKeyPair.publicKey).then(function (pemPublicKey) {
        _rsaPemPublicKey = pemPublicKey
        done()
      })
    })

    it('should return CryptoKey public key', function (done) {
      crypto.pemPublicToCrypto(_rsaPemPublicKey).then(function (cryptoPublicKey) {
        done()
      });
    })
  })

  describe('encrypt and decrypt data asymmetrically', function () {
    it('should return asymmetrically encrypted data', function (done) {
      let encodedData = crypto.stringToArrayBuffer('confidential')
      crypto.rsaEncrypt(_rsaKeyPair.publicKey, encodedData).then(function (asymmetricallyEncryptedData) {
        _rsaEncryptedPrivateKey = asymmetricallyEncryptedData
        done()
      })
    })

    it('should return asymmetrically decrypted data', function (done) {
      crypto.rsaDecrypt(_rsaKeyPair.privateKey, _rsaEncryptedPrivateKey).then(function (asymmetricallyDecryptedData) {
        if (crypto.arrayBufferToString(asymmetricallyDecryptedData) === 'confidential') {
          done()
        }
      })
    })
  })

  describe('encrypt and decrypt shared key', function () {
    it('should return asymmetrically encrypted shared key', function (done) {
      crypto.getSharedKey(256).then(function (sharedKey) {
        crypto.encryptKey(_rsaKeyPair.publicKey, sharedKey, 'SHA-512').then(function (asymmetricallyEncryptedSharedKey) {
          _rsaAsymmetricallyEncryptedSharedKey = asymmetricallyEncryptedSharedKey
          done()
        })
      })
    })

    it('should return asymmetrically decrypted shared key', function (done) {
      crypto.decryptKey(_rsaKeyPair.privateKey, _rsaAsymmetricallyEncryptedSharedKey, 'AES-GCM', 256, 1024, 'SHA-512').then(function (asymmetricallyDecryptedSharedKey) {
        done()
      })
    })
  })

  describe('encrypt and decrypt private key', function () {
    it('should return encrypted private key PKCS8', function (done) {
      crypto.encryptPrivateKey(_rsaKeyPair.privateKey, 'securepassphrase', 1000, 'SHA-512', 'AES-CBC', 256).then(function (encryptedPrivateKey) {
        _rsaEncryptedPrivateKey = encryptedPrivateKey
        done()
      })
    })

    it('should return decrypted private key PKCS8', function (done) {
      crypto.decryptPrivateKey(_rsaEncryptedPrivateKey, 'securepassphrase').then(function (decryptedPrivateKey) {
        done()
      })
    })
  })

  describe('get key fingerprint', function () {
    it('should return key fingerprint', function (done) {
      crypto.cryptoKeyToFingerprint(_rsaKeyPair.publicKey, 'SHA-512').then(function (keyFingerprint) {
        done()
      })
    })
  })
})
