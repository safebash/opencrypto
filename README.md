# OpenCrypto
[![Build Status](https://travis-ci.org/safebash/OpenCrypto.svg?branch=master)](https://travis-ci.org/safebash/OpenCrypto)
[![license: MIT](https://img.shields.io/badge/License-IPL%201.0-blue.svg)](https://opensource.org/licenses/IPL-1.0)

OpenCrypto is a JavaScript library built on top of WebCryptography API that helps you smoothly implement
crypto features into your secure web app. This library performs all of its crypto functions using WebCryptography API only.

## Code Usage
### Load OpenCrypto into your web app
```javascript
<script type="text/javascript" src="OpenCrypto.js"></script>
```
### Examples
```javascript
// Initialize new OpenCrypto instance
var crypt = new OpenCrypto();

// Asymmetric Encryption (RSA)
// Generate asymmetric key pair
crypt.getKeyPair().then(function(keyPair) {
    console.log(keyPair.publicKey);
    console.log(keyPair.privateKey);
});

// Convert CryptoKey of type public to PEM
crypt.cryptoPublicToPem(keyPair.publicKey).then(function(publicPem) {
    console.log(publicPem);
});

// Convert CryptoKey of type private to PEM
crypt.cryptoPrivateToPem(keyPair.privateKey).then(function(privatePem) {
    console.log(privatePem);
});

// Convert PEM public key to CryptoKey
crypt.pemPublicToCrypto(publicPem).then(function(cryptoPublic) {
    console.log(cryptoPublic);
});

// Convert PEM private key to CryptoKey
crypt.pemPrivateToCrypto(privatePem).then(function(cryptoPrivate) {
    console.log(cryptoPrivate);
});

// Encrypt CryptoKey of type private into PEM Encrypted Private Key
crypt.encryptPrivateKey(cryptoPrivate, 'securepassphrase').then(function(encryptedPrivateKey) {
    // This PEM Encrypted Private Key is fully compatiable with OpenSSL
    console.log(encryptedPrivateKey);
});

// Decrypt PEM Encrypted Private Key
crypt.decryptPrivateKey(encryptedPrivateKey, 'securepassphrase').then(function(decryptedPrivateKey) {
    console.log(decryptedPrivateKey);
});

// Encrypt data using public key
crypt.encryptPublic(publicKey, data).then(function(encryptedDataAsymmetric) {
    console.log(encryptedDataAsymmetric);
});

// Decrypt data using private key
crypt.decryptPrivate(privateKey, encryptedDataAsymmetric).then(function(decryptedDataAsymmetric) {
    console.log(decryptedDataAsymmetric);
});

// Encrypt session key
crypt.encryptKey(publicKey, sessionKey).then(function(encryptedSessionKey) {
    console.log(encryptedSessionKey);
});

// Decrypt session key
crypt.sessionKey(privateKey, encryptedSessionKey).then(function(decryptedSessionKey) {
    console.log(decryptedSessionKey);
});

// Symmetric Encryption (AES)
// Generate new symmetric / session Key
crypt.getSessionKey().then(function(sessionKey) {
    console.log(sessionKey);
});

// Encrypt data using session key
crypt.encrypt(sessionKey, data).then(function(encryptedData) {
    console.log(encryptedData);
});

// Decrypt data using session key
crypt.decrypt(sessionKey, encryptedData).then(function(decryptedData) {
    console.log(decryptedData);
});

// Other Crypto Features
// Derive key from passphrase
crypt.keyFromPassphrase('securepassword', 'uniquesalt', 300000).then(function(derivedKey) {
    console.log(derivedKey);
});

```

## Standards Compliance
[RFC 5208](https://tools.ietf.org/html/rfc5208)<br>
[RFC 2898](https://tools.ietf.org/html/rfc2898)<br>
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
