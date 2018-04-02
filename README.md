# OpenCrypto
[![Build Status](https://travis-ci.org/safebash/opencrypto.svg?branch=master)](https://travis-ci.org/safebash/opencrypto)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://raw.githubusercontent.com/safebash/opencrypto/master/LICENSE.md)

OpenCrypto is a lightweight JavaScript library built on top of WebCryptography API. The purpose of this library is to make it easier for a developer to implement cryptography in the browser with less code and without having to deal with ASN.1, PEM or other formats manually.

## Code Usage
### Load OpenCrypto into your web app
```javascript
<script type="text/javascript" src="OpenCrypto.min.js"></script>
```
### Examples
```javascript
// Initialize new OpenCrypto instance
const crypto = new OpenCrypto()

// Asymmetric Encryption (RSA)
// Generate asymmetric key pair
crypto.getKeyPair().then(function (keyPair) {
  console.log(keyPair.publicKey)
  console.log(keyPair.privateKey)
})

// Convert CryptoKey of type public to PEM
crypto.cryptoPublicToPem(keyPair.publicKey).then(function (publicPem) {
  console.log(publicPem)
})

// Convert CryptoKey of type private to PEM
crypto.cryptoPrivateToPem(keyPair.privateKey).then(function (privatePem) {
  console.log(privatePem)
})

// Convert PEM public key to CryptoKey
crypto.pemPublicToCrypto(publicPem).then(function (cryptoPublic) {
  console.log(cryptoPublic)
})

// Convert PEM private key to CryptoKey
crypto.pemPrivateToCrypto(privatePem).then(function (cryptoPrivate) {
  console.log(cryptoPrivate)
})

// Encrypt CryptoKey of type private into PEM Encrypted Private Key
crypto.encryptPrivateKey(cryptoPrivate, 'securepassphrase').then(function (encryptedPrivateKey) {
  // This PEM Encrypted Private Key is fully compatiable with OpenSSL
  console.log(encryptedPrivateKey)
})

// Decrypt PEM Encrypted Private Key
crypto.decryptPrivateKey(encryptedPrivateKey, 'securepassphrase').then(function (decryptedPrivateKey) {
  console.log(decryptedPrivateKey)
})

// Encrypt data using public key
crypto.encryptPublic(publicKey, data).then(function (encryptedDataAsymmetric) {
  console.log(encryptedDataAsymmetric)
})

// Decrypt data using private key
crypto.decryptPrivate(privateKey, encryptedDataAsymmetric).then(function (decryptedDataAsymmetric) {
  console.log(decryptedDataAsymmetric)
})

// Encrypt shared key
crypto.encryptKey(publicKey, sharedKey).then(function (encryptedSharedKey) {
  console.log(encryptedSharedKey)
})

// Decrypt shared key
crypto.decryptKey(privateKey, encryptedSharedKey).then(function (decryptedSharedKey) {
  console.log(decryptedSharedKey)
})

// Symmetric Encryption (AES)
// Generate new symmetric / shared Key
crypto.getSharedKey().then(function (sharedKey) {
  console.log(sharedKey)
})

// Encrypt data using shared key
crypto.encrypt(sharedKey, data).then(function (encryptedData) {
  console.log(encryptedData)
})

// Decrypt data using shared key
crypto.decrypt(sharedKey, encryptedData).then(function (decryptedData) {
  console.log(decryptedData)
})

// Other Crypto Features
// Derive key from passphrase
crypto.keyFromPassphrase('securepassword', 'uniquesalt', 300000).then(function (derivedKey) {
  console.log(derivedKey)
})

```

## Standards Compliance
[RFC 5958](https://tools.ietf.org/html/rfc5958)<br>
[RFC 8018](https://tools.ietf.org/html/rfc8018)<br>
[RFC 3394](https://tools.ietf.org/html/rfc3394)<br>
[RFC 5480](https://tools.ietf.org/html/rfc5480)<br>
[RFC 5915](https://tools.ietf.org/html/rfc5915)<br>
[RFC 6090](https://tools.ietf.org/html/rfc6090)<br>
[NIST SP 800-38D](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)<br>
[NIST SP 800-38A](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

## Contributors
Peter Bielak<br>
Andrew Kozlik, Ph.D.

## License
MIT
