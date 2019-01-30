# OpenCrypto
[![npm](https://img.shields.io/npm/v/opencrypto.svg)](https://www.npmjs.com/package/opencrypto)
[![Build Status](https://travis-ci.org/safebash/opencrypto.svg?branch=master)](https://travis-ci.org/safebash/opencrypto)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://raw.githubusercontent.com/safebash/opencrypto/master/LICENSE.md)
[![Patreon](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://patreon.com/safebash)

OpenCrypto is a lightweight JavaScript library built on top of WebCryptography API. The purpose of this library is to make it easier for a developer to implement cryptography in the browser with less code and without having to deal with ASN.1, PEM or other formats manually.

## Code Usage
### Load OpenCrypto into your web application
```javascript
<script type="text/javascript" src="OpenCrypto.min.js"></script>
```
or
```javascript
import OpenCrypto from 'opencrypto'
```
### Examples
```javascript
// Initialize new OpenCrypto instance
const crypt = new OpenCrypto()

// Asymmetric Encryption (RSA)
// Generate RSA key pair
/*
 * bits: 1024 or 2048 or 4096 | default: 2048
 * usage: 
 *   for OAEP = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
 *   for PSS = ['sign', 'verify']
 *   default: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
 * alg: 'SHA1' or 'SHA-256' or 'SHA-384' or 'SHA-512' | default: 'SHA-512'
 * paddingScheme: 'RSA-OAEP' or 'RSA-PSS' | default: 'RSA-OAEP'
 * extractable: true or false | default: true
 */
crypt.getRSAKeyPair(bits, usage, alg, paddingScheme, extractable).then(function (keyPair) {
  console.log(keyPair.publicKey)
  console.log(keyPair.privateKey)
})

// Generate EC key pair
/*
 * curve: P-256 or P-384 or P-521 | default: P-256
 * usage: default: ['deriveKey', 'deriveBits']
 * type: 'ECDH' or 'ECDSA' | default: 'ECDH'
 * extractable: true or false | default: true
 */
crypt.getECKeyPair(curve, usage, type, extractable).then(function (keyPair) {
  console.log(keyPair.privateKey)
  console.log(keyPair.publicKey)
})

// Convert CryptoKey of type private to PEM
/*
 * privateKey: CryptoKey | default: undefined
 */
crypt.cryptoPrivateToPem(privateKey).then(function (privatePem) {
  console.log(privatePem)
})

// Convert PEM private key to CryptoKey
/*
 * pem: PEM RSA Private Key (String) | default: undefined
 * isSignature: true of false | default: false
 * hash: 'SHA-1' or 'SHA-256' or 'SHA-384' or 'SHA-512' | default: 'SHA-512'
 */
crypt.pemPrivateToCrypto(pem, isSignature, hash).then(function (cryptoPrivate) {
  console.log(cryptoPrivate)
})

// Convert CryptoKey of type public to PEM
/*
 * publicKey: CryptoKey | default: undefined
 */
crypt.cryptoPublicToPem(publicKey).then(function (publicPem) {
  console.log(publicPem)
})

// Convert PEM public key to CryptoKey
/*
 * pem: PEM RSA Public Key (String) | default: undefined
 * isSignature: true or false | default: false
 * hash: 'SHA-1' or 'SHA-256' or 'SHA-384' or 'SHA-512' | default: 'SHA-512'
 */
crypt.pemPublicToCrypto(pem, isSignature, hash).then(function (cryptoPublic) {
  console.log(cryptoPublic)
})

// Encrypt CryptoKey of type private into PEM Encrypted Private Key
/*
 * privateKey: CryptoKey | default: undefined
 * passphrase: String | default: undefined
 * iterations: Integer | default: 64000
 * hash: 'SHA-1' or 'SHA-256' or 'SHA-384' or 'SHA-512' | default: 'SHA-512'
 * cipher: 'AES-CBC' or 'AES-GCM' or 'AES-CFB' | default: 'AES-CBC'
 * keyLength: default: 256
 */
crypt.encryptPrivateKey(privateKey, passphrase, iterations, hash, cipher, keyLength).then(function (encryptedPrivateKey) {
  // This PEM Encrypted Private Key is fully compatiable with OpenSSL
  console.log(encryptedPrivateKey)
})

// Decrypt PEM Encrypted Private Key
/*
 * encryptedPrivateKey: PEM PKCS #8 | default: undefined
 * passphrase: String | default: undefined
 * options:
 *   for OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' } }
 *   for PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' } }
 *   for ECDH: { name: 'ECDH', namedCurve: 'P-256' }
 *   for ECDSA: { name: 'ECDSA', namedCurve: 'P-256' }
 *   default: { name: 'RSA-OAEP', hash: { name: 'SHA-512' } }
 * usage:
 *   for OAEP: ['decrypt', 'unwrapKey']
 *   for PSS: ['sign']
 *   for ECDH: ['deriveKey', 'deriveBits']
 *   for ECDSA: ['sign']
 *   default: ['decrypt', 'unwrapKey']
 */
crypt.decryptPrivateKey(encryptedPrivateKey, passphrase, options, usage).then(function (decryptedPrivateKey) {
  console.log(decryptedPrivateKey)
})

// Encrypt data using public key
/*
 * publicKey: CryptoKey | default: undefined
 * data: ArrayBuffer | default: undefined
 */
crypt.rsaEncrypt(publicKey, data).then(function (encryptedDataAsymmetric) {
  console.log(encryptedDataAsymmetric)
})

// Decrypt data using private key
/*
 * privateKey: CryptoKey | default: undefined
 * encryptedData: base64 String | default: undefined
 */
crypt.rsaDecrypt(privateKey, encryptedData).then(function (decryptedDataAsymmetric) {
  console.log(decryptedDataAsymmetric)
})

// Encrypt shared key
/*
 * publicKey: CryptoKey | default: undefined
 * sharedKey: CryptoKey | default: undefined
 * publicKeyHash: 'SHA-1' or 'SHA-256' or 'SHA-384' or 'SHA-512' | default: 'SHA-512'
 */
crypt.encryptKey(publicKey, sharedKey).then(function (encryptedSharedKey) {
  console.log(encryptedSharedKey)
})

// Decrypt shared key
/*
 * privateKey: CryptoKey | default: undefined
 * encryptedSharedKey: CryptoKey | default: undefined
 * cipher: AES-GCM or 'AES-CBC' or 'AES-CFB' | default: 'AES-GCM'
 * keyLength: default: 256
 * privateKeyLength: 1024 or 2048 or 4096 default: 2048
 * privateKeyHash: 'SHA-1' or 'SHA-256' or 'SHA-384' or 'SHA-512' | default: 'SHA-512'
 */
crypt.decryptKey(privateKey, encryptedSharedKey, cipher, keyLength, privateKeyLength, privateKeyHash).then(function (decryptedSharedKey) {
  console.log(decryptedSharedKey)
})

// Sign data
/*
 * privateKey: CryptoKey | default: undefined
 * data: ArrayBuffer | default: undefined
 */
crypt.sign(privateKey, data).then(function (signature) {
  console.log(signature)
})

// Verify signature
/*
 * privateKey: CryptoKey | default: undefined
 * signature: base64 String | default: undefined
 * data: ArrayBuffer | default: undefined
 */
crypt.verify(publicKey, signature, data).then(function (isValid) {
  console.log(isValid)
})

// Symmetric Encryption (AES)
// Generate new symmetric key
/*
 * bits: 128 or 256 | default: 256
 * usage: default: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
 * extractable: true or false | default: true
 * cipherMode: 'AES-GCM' or 'AES-CBC' or 'AES-CFB' | default: 'AES-GCM'
 */
crypt.getSharedKey(bits, usage, extractable, cipherMode).then(function (sharedKey) {
  console.log(sharedKey)
})

// Encrypt data using shared key
/*
 * sharedKey: CryptoKey | default: undefined
 * data: ArrayBuffer | default: undefined
 */
crypt.encrypt(sharedKey, data).then(function (encryptedData) {
  console.log(encryptedData)
})

// Decrypt data using shared key
/*
 * sharedKey: CryptoKey | default: undefined
 * encryptedData: base64 String | default: undefined
 */
crypt.decrypt(sharedKey, encryptedData).then(function (decryptedData) {
  console.log(decryptedData)
})

// Other Crypto Features
// Derive key from passphrase
/*
 * passphrase: String | default: undefined
 * salt: String | default: undefined
 * iterations: Integer | default: 64000
 * hash: 'SHA-1' or 'SHA-256' or 'SHA-384' or 'SHA-512' | default: 'SHA-512'
 */
crypt.keyFromPassphrase(passphrase, salt, iterations, hash).then(function (derivedKey) {
  console.log(derivedKey)
})

// Get key fingerprint
/*
 * key: CryptoKey | default: undefined
 * hash: 'SHA-1' or 'SHA-256' or 'SHA-384' or 'SHA-512' | default: 'SHA-512'
 */
crypt.cryptoKeyToFingerprint(key, hash).then(function (fingerprint) {
  console.log(fingerprint)
})

// Generate random salt
/*
 * size: Integer | default: 16
 */
crypt.getRandomSalt(size).then(function (salt) {
  console.log(salt)
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
