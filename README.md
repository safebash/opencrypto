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
### Generate asymmetric key pair
```javascript
var crypt = new OpenCrypto();

crypt.getKeyPair().then(function(keyPair) {
    console.log(keyPair.publicKey);
    console.log(keyPair.privateKey);
});
```


## License
Copyright 2016 Peter Bielak

Licensed under the MIT license.
