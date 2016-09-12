# OpenCrypto
[![Build Status](https://travis-ci.org/PeterBielak/OpenCrypto.svg?branch=master)](https://travis-ci.org/PeterBielak/OpenCrypto)
<a href="https://github.com/PeterBielak/OpenCrypto/blob/master/LICENSE.md"><img src="https://img.shields.io/github/license/mashape/apistatus.svg" alt="License"></a>

OpenCrypto is a JavaScript library built on top of WebCrypto API that helps you smoothly implement
crypto features into your secure web app. This library performs all of its crypto functions using WebCrypto API only and is compatible with OpenSSL.

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
crypt.encryptPrivateKey(cryptoPrivate, 'securepassword').then(function(encryptedPrivateKey) {
    // This PEM Encrypted Private Key is fully compatiable with OpenSSL
    console.log(encryptedPrivateKey);
});

// Decrypt PEM Encrypted Private Key
crypt.decryptPrivateKey(encryptedPrivateKey).then(function(decryptedPrivateKey) {
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
[RFC 5208](http://tools.ietf.org/html/rfc5208)<br>
[RFC 2898](http://tools.ietf.org/html/rfc2898)<br>
[RFC 5280](http://tools.ietf.org/html/rfc5280)<br>
[RFC 3279](http://tools.ietf.org/html/rfc3279)<br>
[NIST SP 800-38D](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)<br>
[NIST SP 800-38A](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

## License
Copyright 2016 Peter Bielak<br>
Cryptographic Consultancy Andrew Kozlik, Ph.D.<br>
Licensed under the MIT license.
