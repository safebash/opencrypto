# OpenCrypto
[![Build Status](https://travis-ci.org/PeterBielak/OpenCrypto.svg?branch=master)](https://travis-ci.org/PeterBielak/OpenCrypto)
<a href="http://mit-license.org"><img src="https://img.shields.io/github/license/mashape/apistatus.svg" alt="License"></a>

OpenCrypto is a JavaScript library built on top of WebCrypto API that helps you smoothly implement
crypto features into your web app including various encoding types.

## Code Usage
### Load OpenCrypto into your web app
```javascript
<script type="text/javascript" src="OpenCrypto.js"></script>
```
### Examples
```javascript
// Initialize new OpenCrypto instance
var crypt = new OpenCrypto();

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
```


## License
Copyright 2016 Peter Bielak

Licensed under the MIT license.
