# OpenCrypto
[![npm](https://img.shields.io/npm/v/opencrypto.svg)](https://www.npmjs.com/package/opencrypto)
[![Build Status](https://travis-ci.org/safebash/opencrypto.svg?branch=master)](https://travis-ci.org/safebash/opencrypto)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://raw.githubusercontent.com/safebash/opencrypto/master/LICENSE.md)
[![Become a Patron](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://patreon.com/safebash)

OpenCrypto is a lightweight, high performance, standard-compliant JavaScript library built on top of [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/). This library makes it easier to implement cryptography in a browser with less code. It can convert and encode ASN.1, PEM and CryptoKey. OpenCrypto is created and maintained by [SafeBash](https://safebash.com).

## Instructions
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
 * modulusLength: 1024 or 2048 or 4096 | default: 2048
 * hash: 'SHA1' or 'SHA-256' or 'SHA-384' or 'SHA-512' | default: 'SHA-512'
 * paddingScheme: 'RSA-OAEP' or 'RSA-PSS' | default: 'RSA-OAEP'
 * usages:
 *   for OAEP = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
 *   for PSS = ['sign', 'verify']
 *   default: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
 * isExtractable: true or false | default: true
 */
crypt.getRSAKeyPair(modulusLength, hash, paddingScheme, usages, isExtractable).then(function (keyPair) {
  console.log(keyPair.publicKey)
  console.log(keyPair.privateKey)
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

// Generate EC key pair
/*
 * curve: P-256 or P-384 or P-521 | default: P-256
 * type: 'ECDH' or 'ECDSA' | default: 'ECDH'
 * usages: default: ['deriveKey', 'deriveBits']
 * isExtractable: true or false | default: true
 */
crypt.getECKeyPair(curve, type, usages, isExtractable).then(function (keyPair) {
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
 * pem: PEM Private Key (String) | default: undefined
 * options:
 *   for ECDH: { name: 'ECDH', usages: ['deriveKey', 'deriveBits'], isExtractable: true }
 *   for ECDSA: { name: 'ECDSA', usages: ['sign'], isExtractable: true }
 *   for RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['decrypt', 'unwrapKey'], isExtractable: true }
 *   for RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['sign'], isExtractable: true }
 */
crypt.pemPrivateToCrypto(pem, options).then(function (cryptoPrivate) {
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
 * pem: PEM Public Key (String) | default: undefined
 * options:
 *   for ECDH: { name: 'ECDH', usages: [], isExtractable: true }
 *   for ECDSA: { name: 'ECDSA', usages: ['verify'], isExtractable: true }
 *   for RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['encrypt', 'wrapKey'], isExtractable: true }
 *   for RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['verify'], isExtractable: true }
 */
crypt.pemPublicToCrypto(pem, options).then(function (cryptoPublic) {
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
 *   for ECDH: { name: 'ECDH', namedCurve: 'P-256', keyUsages: ['deriveKey', 'deriveBits'], isExtractable: true }
 *   for ECDSA: { name: 'ECDSA', namedCurve: 'P-256', keyUsages: ['sign'], isExtractable: true }
 *   for RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, keyUsages: ['decrypt', 'unwrapKey'], isExtractable: true }
 *   for RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, keyUsages: ['sign'], isExtractable: true }
 *   default: { name: 'ECDH', namedCurve: 'P-256', keyUsages: ['deriveKey', 'deriveBits'], isExtractable: true }
 */
crypt.decryptPrivateKey(encryptedPrivateKey, passphrase, options).then(function (decryptedPrivateKey) {
  console.log(decryptedPrivateKey)
})

// Encrypt shared key
/*
 * wrappingKey: CryptoKey | default: undefined
 * sharedKey: CryptoKey | default: undefined
 * options:
 *   for ECDH: { publicKey: "undefined", derivedKeyCipher: 'AES-GCM', derivedKeyLength: 256 }
 *   for RSA-OAEP: {}
 *   for AES-GCM: {}
 */
crypt.encryptKey(publicKey, sharedKey, options).then(function (encryptedSharedKey) {
  console.log(encryptedSharedKey)
})

// Decrypt shared key
/*
 * unwrappingKey: CryptoKey | default: undefined
 * encryptedSharedKey: CryptoKey | default: undefined
 * options:
 *   for ECDH: { publicKey: "undefined", derivedKeyCipher: 'AES-GCM', derivedKeyLength: 256, keyCipher: 'AES-GCM', keyLength: 256, keyUsages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 *   for RSA-OAEP: { keyCipher: 'AES-GCM', keyLength: 256, keyUsages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 *   for AES-GCM: { keyCipher: 'AES-GCM', keyLength: 256, keyUsages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 */
crypt.decryptKey(privateKey, encryptedSharedKey, options).then(function (decryptedSharedKey) {
  console.log(decryptedSharedKey)
})

// Sign data
/*
 * privateKey: CryptoKey | default: undefined
 * data: ArrayBuffer | default: undefined
 * options:
 *   for ECDSA: { hash: 'SHA-512' }
 *   for RSA-PSS: { saltLength: 128 }
 */
crypt.sign(privateKey, data, options).then(function (signature) {
  console.log(signature)
})

// Verify signature
/*
 * publicKey: CryptoKey | default: undefined
 * signature: base64 String | default: undefined
 * data: ArrayBuffer | default: undefined
 * options:
 *   for ECDSA: { hash: 'SHA-512' }
 *   for RSA-PSS: { saltLength: 128 }
 */
crypt.verify(publicKey, signature, data, options).then(function (isValid) {
  console.log(isValid)
})

// Symmetric Encryption (AES)
// Generate new symmetric key
/*
 * keyLength: 128, 192 or 256 | default: 256
 * options: { keyCipher: 'AES-GCM', keyUsages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 */
crypt.getSharedKey(keyLength, options).then(function (sharedKey) {
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
 * length: default: 256
 */
crypt.keyFromPassphrase(passphrase, salt, iterations, hash, length).then(function (derivedKey) {
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

// Generate random data
/*
 * size: Integer | default: 16
 */
crypt.getRandomData(size).then(function (salt) {
  console.log(salt)
})

```

## Standards Compliance
[RFC 5958](https://tools.ietf.org/html/rfc5958)<br>
[RFC 6090](https://tools.ietf.org/html/rfc6090)<br>
[RFC 5480](https://tools.ietf.org/html/rfc5480)<br>
[RFC 5915](https://tools.ietf.org/html/rfc5915)<br>
[RFC 8018](https://tools.ietf.org/html/rfc8018)<br>
[RFC 3394](https://tools.ietf.org/html/rfc3394)<br>
[NIST SP 800-38A](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)<br>
[NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf)<br>
[NIST SP 800-38D](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)<br>
[NIST SP 800-56A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56ar.pdf)<br>
[NIST SP 800-56C](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56c.pdf)<br>
[NIST FIPS 180-4](https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf)

## Contributors
Peter Bielak<br>
Andrew Kozlik, Ph.D.

## License
MIT
