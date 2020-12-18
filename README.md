# OpenCrypto
[![npm](https://img.shields.io/npm/v/opencrypto.svg)](https://www.npmjs.com/package/opencrypto)
[![Build Status](https://travis-ci.org/safebash/opencrypto.svg?branch=master)](https://travis-ci.org/safebash/opencrypto)
[![npm](https://img.shields.io/npm/dt/opencrypto)](https://npmcharts.com/compare/opencrypto?minimal=true)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://raw.githubusercontent.com/safebash/opencrypto/master/LICENSE.md)
[![Become a Patron](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://patreon.com/safebash)

OpenCrypto is a lightweight, high performance, standard-compliant JavaScript library built on top of [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/). This library makes it easier to implement cryptography in a browser with less code. It can convert and encode ASN.1, PEM and CryptoKey. OpenCrypto is created and maintained by [SafeBash](https://safebash.com).

## Import into your web application
```javascript
<script type="text/javascript" src="OpenCrypto.min.js"></script>

// Initialize new OpenCrypto instance
const crypt = new OpenCrypto()
```
or
```javascript
import OpenCrypto from 'opencrypto'

// Initialize new OpenCrypto instance
const crypt = new OpenCrypto()
```

## Conversion of CryptoKey, PEM and Base64
```javascript
/**
 * Method that converts asymmetric private key from CryptoKey to PEM format
 * @param {CryptoKey} privateKey default: "undefined"
 */
crypt.cryptoPrivateToPem(privateKey).then(privatePem => {
  console.log(privatePem)
})

/**
 * Method that converts asymmetric private key from PEM to CryptoKey format
 * @param {String} pem default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- ECDH: { name: 'ECDH', usages: ['deriveKey', 'deriveBits'], isExtractable: true }
 * -- ECDSA: { name: 'ECDSA', usages: ['sign'], isExtractable: true }
 * -- RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['decrypt', 'unwrapKey'], isExtractable: true }
 * -- RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['sign'], isExtractable: true }
 */
crypt.pemPrivateToCrypto(pem, options).then(cryptoPrivate => {
  console.log(cryptoPrivate)
})

/**
 * Method that converts asymmetric public key from CryptoKey to PEM format
 * @param {CryptoKey} publicKey default: "undefined"
 */
crypt.cryptoPublicToPem(publicKey).then(publicPem => {
  console.log(publicPem)
})

/**
 * Method that converts asymmetric public key from PEM to CryptoKey format
 * @param {String} publicKey default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- ECDH: { name: 'ECDH', usages: [], isExtractable: true }
 * -- ECDSA: { name: 'ECDSA', usages: ['verify'], isExtractable: true }
 * -- RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['encrypt', 'wrapKey'], isExtractable: true }
 * -- RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['verify'], isExtractable: true }
 */
crypt.pemPublicToCrypto(pem, options).then(cryptoPublic => {
  console.log(cryptoPublic)
})

/**
 * Method that converts CryptoKey to base64
 * @param {CryptoKey} key default: "undefined"
 * @param {String} type default: "secret: 'raw'; private: 'pkcs8'; public: 'spki'"
 */
crypt.cryptoToBase64(key, type).then(base64Key => {
  console.log(base64Key)
})

/**
 * Method that converts base64 encoded key to CryptoKey
 * @param {String} key default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- AES-GCM: { name: 'AES-GCM', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 * -- AES-CBC: { name: 'AES-CBC', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 * -- ECDH: { name: 'ECDH', namedCurve: 'P-256', usages: ['deriveKey', 'deriveBits'], isExtractable: true }
 * -- ECDSA: { name: 'ECDSA', namedCurve: 'P-256', usages: ['sign', 'verify'], isExtractable: true }
 * -- RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 * -- RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['sign', 'verify'], isExtractable: true }
 */
crypt.base64ToCrypto(key, options).then(cryptoKey => {
  console.log(cryptoKey)
})
```

## Asymmetric Encryption
```javascript
/**
 * Method that generates asymmetric RSA-OAEP key pair
 * @param {Integer} modulusLength default: "2048"
 * @param {String} hash default: "SHA-512"
 * @param {String} paddingScheme default: "RSA-OAEP"
 * @param {Array} usages default: "['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']"
 * @param {Boolean} isExtractable default: "true"
 */
crypt.getRSAKeyPair(modulusLength, hash, paddingScheme, usages, isExtractable).then(keyPair => {
  console.log(keyPair.publicKey)
  console.log(keyPair.privateKey)
})

/**
 * Method that encrypts data using asymmetric encryption
 * @param {CryptoKey} publicKey default: "undefined"
 * @param {ArrayBuffer} data default: "undefined"
 */
crypt.rsaEncrypt(publicKey, data).then(encryptedData => {
  console.log(encryptedData)
})

/**
 * Method that decrypts data using asymmetric encryption
 * @param {CryptoKey} privateKey default: "undefined"
 * @param {String} encryptedData default: "undefined"
 */
crypt.rsaDecrypt(privateKey, encryptedData).then(decryptedData => {
  console.log(decryptedData)
})

/**
 * Method that generates asymmetric Elliptic Curve Diffie-Hellman key pair
 * @param {String} curve default: "P-256"
 * @param {String} type default: "ECDH"
 * @param {Array} usages default: "['deriveKey', 'deriveBits']"
 * @param {Boolean} isExtractable default: "true"
 */
crypt.getECKeyPair(curve, type, usages, isExtractable).then(keyPair => {
  console.log(keyPair.privateKey)
  console.log(keyPair.publicKey)
})

/**
 * Method that encrypts asymmetric private key using passphrase to enable storage in unsecure environment
 * @param {CryptoKey} privateKey default: "undefined"
 * @param {String} passphrase default: "undefined"
 * @param {Number} iterations default: "64000"
 * @param {String} hash default: "SHA-512"
 * @param {String} cipher default: "AES-GCM"
 * @param {Number} length default: "256"
 */
crypt.encryptPrivateKey(privateKey, passphrase, iterations, hash, cipher, length).then(encryptedPrivateKey => {
  console.log(encryptedPrivateKey)
})

/**
 * Method that decrypts asymmetric private key using passphrase
 * @param {String} encryptedPrivateKey default: "undefined"
 * @param {String} passphrase default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- ECDH: { name: 'ECDH', namedCurve: 'P-256', usages: ['deriveKey', 'deriveBits'], isExtractable: true }
 * -- ECDSA: { name: 'ECDSA', namedCurve: 'P-256', usages: ['sign'], isExtractable: true }
 * -- RSA-OAEP: { name: 'RSA-OAEP', hash: 'SHA-512', usages: ['decrypt', 'unwrapKey'], isExtractable: true }
 * -- RSA-PSS: { name: 'RSA-PSS', hash: 'SHA-512', usages: ['sign'], isExtractable: true }
 */
crypt.decryptPrivateKey(encryptedPrivateKey, passphrase, options).then(decryptedPrivateKey => {
  console.log(decryptedPrivateKey)
})

/**
 * Method that performs ECDH key agreement
 * @param {CryptoKey} privateKey default: "undefined"
 * @param {CryptoKey} publicKey default: "undefined"
 * @param {Object} options default: "{ bitLength: 256, hkdfHash: 'SHA-512', hkdfSalt: "new UInt8Array()", hkdfInfo: "new UInt8Array()", cipher: 'AES-GCM', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
 */
crypt.keyAgreement(privateKey, publicKey, options).then(sharedKey => {
  console.log(sharedKey)
})
```

## Symmetric Encryption
```javascript
/**
 * Method that generates symmetric/shared key for AES encryption
 * @param {Integer} length default: "256"
 * @param {Object} options default: "{ cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
 */
crypt.getSharedKey(length, options).then(sharedKey => {
  console.log(sharedKey)
})

/**
 * Method that encrypts keys
 * @param {CryptoKey} wrappingKey default: "undefined"
 * @param {CryptoKey} key default: "undefined"
 */
crypt.encryptKey(wrappingKey, key).then(encryptedKey => {
  console.log(encryptedKey)
})

/**
 * Method that decrypts keys
 * @param {CryptoKey} unwrappingKey default: "undefined"
 * @param {String} encryptedKey default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- AES-GCM: { type: 'raw', name: 'AES-GCM', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 * -- AES-CBC: { type: 'raw', name: 'AES-CBC', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 * -- ECDH: { type: "'pkcs8' or 'spki'", name: 'ECDH', namedCurve: 'P-256', usages: ['deriveKey', 'deriveBits'], isExtractable: true }
 * -- ECDSA: { type: "'pkcs8' or 'spki'", name: 'ECDSA', namedCurve: 'P-256', usages: ['sign', 'verify'], isExtractable: true }
 * -- RSA-OAEP: { type: "'pkcs8' or 'spki'", name: 'RSA-OAEP', hash: 'SHA-512', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
 * -- RSA-PSS: { type: "'pkcs8' or 'spki'", name: 'RSA-PSS', hash: 'SHA-512', usages: ['sign', 'verify'], isExtractable: true }
 */
crypt.decryptKey(unwrappingKey, encryptedKey, options).then(decryptedKey => {
  console.log(decryptedKey)
})

/**
 * Method that generates key signature using ECDSA or RSA-PSS
 * @param {CryptoKey} privateKey default: "undefined"
 * @param {CryptoKey} key default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- ECDSA: { hash: 'SHA-512' }
 * -- RSA-PSS: { saltLength: 128 }
 */
crypt.signKey(privateKey, key, options).then(keySignature => {
  console.log(keySignature)
})

/**
 * Method that verifies key signature using ECDSA or RSA-PSS
 * @param {CryptoKey} publicKey default: "undefined"
 * @param {CryptoKey} key default: "undefined"
 * @param {String} signature default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- ECDSA: { hash: 'SHA-512' }
 * -- RSA-PSS: { saltLength: 128 }
 */
crypt.verifyKey(publicKey, key, signature, options).then(isValid => {
  console.log(isValid)
})

/**
 * Method that generates signature of data using ECDSA or RSA-PSS
 * @param {CryptoKey} privateKey default: "undefined"
 * @param {ArrayBuffer} data default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- ECDSA: { hash: 'SHA-512' }
 * -- RSA-PSS: { saltLength: 128 }
 */
crypt.sign(privateKey, data, options).then(signature => {
  console.log(signature)
})

/**
 * Method that verifies data signature using ECDSA or RSA-PSS
 * @param {CryptoKey} publicKey default: "undefined"
 * @param {ArrayBuffer} data default: "undefined"
 * @param {String} signature default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- ECDSA: { hash: 'SHA-512' }
 * -- RSA-PSS: { saltLength: 128 }
 */
crypt.verify(publicKey, data, signature, options).then(isValid => {
  console.log(isValid)
})

/**
 * Method that encrypts data using symmetric/shared key
 * @param {CryptoKey} sharedKey default: "undefined"
 * @param {ArrayBuffer} data default: "undefined"
 */
crypt.encrypt(sharedKey, data).then(encryptedData => {
  console.log(encryptedData)
})

/**
 * Method that decrypts data using symmetric/shared key
 * @param {CryptoKey} sharedKey default: "undefined"
 * @param {String} encryptedData default: "undefined"
 * @param {Object} options default: depends on algorithm below
 * -- AES-GCM: { cipher: 'AES-GCM' }
 * -- AES-CBC: { cipher: 'AES-CBC' }
 */
crypt.decrypt(sharedKey, encryptedData, options).then(decryptedData => {
  console.log(decryptedData)
})
```

## Passphrase derivation
```javascript
/**
 * Method that derives shared key from passphrase
 * @param {String} passphrase default: "undefined"
 * @param {ArrayBuffer} salt default: "undefined"
 * @param {Number} iterations default: "64000"
 * @param {Object} options default: "{ hash: 'SHA-512', length: 256, cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
 */
crypt.derivePassphraseKey(passphrase, salt, iterations, options).then(derivedKey => {
  console.log(derivedKey)
})

/**
 * Method that derives hash from passphrase
 * @param {String} passphrase default: "undefined"
 * @param {ArrayBuffer} salt default: "undefined" salt
 * @param {Number} iterations default: "64000"
 * @param {Object} options default: "{ hash: 'SHA-512', length: 256, cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
 */
crypt.hashPassphrase(passphrase, salt, iterations, options).then(hashedPassphrase => {
  console.log(derivedHash)
})

/**
 * Method that generates fingerprint of EC, RSA and AES keys
 * @param {CryptoKey} key default: "undefined"
 * @param {Object} options default: { hash: 'SHA-512', isBuffer: false }
 */
crypt.getFingerprint(key, options).then(fingerprint => {
  console.log(fingerprint)
})
```

## Other
```javascript
/**
 * Method that generates random bytes using cryptographically secure PRNG
 * @param {Number} size default: "16"
 */
crypt.getRandomBytes(size).then(data => {
  console.log(data)
})
```

## Standards Compliance
[RFC 5280](https://tools.ietf.org/html/rfc5280)<br>
[RFC 6090](https://tools.ietf.org/html/rfc6090)<br>
[RFC 5208](https://tools.ietf.org/html/rfc5208)<br>
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
