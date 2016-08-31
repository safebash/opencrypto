/**
 *
 * Copyright (c) 2016 Peter Bielak
 *
 * OpenCrypto is a library written on top of WebCrypto API that allows
 * you to quickly and effectively use cryptographic functions that
 * are built-in natively in the browser.
 */

/**
 * MIT License
 * 
 * Copyright (c) 2016 Peter Bielak
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict';
var cryptoApi = window.crypto.subtle || window.crypto.webkitSubtle;
var securePRNG = window.crypto;
var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var lookup = new Uint8Array(256);

/**
 *
 * @param {Object} [options = {}] - An object to customize OpenCrypto behaviour
 * possible parameters are:
 * - parameter_name        {number}  default: 1024 description here
 * - parameter_name        {string}  default: '010001' description here
 * - parameter_name        {boolean} default: false description here
 * @constructor
 */
var OpenCrypto = function(options) {
    options = options || {};
    this.keyPair = {};
    initB64();
};

function initB64() {
    for (var i = 0; i < chars.length; i++) {
        lookup[chars.charCodeAt(i)] = i;
    }
}

function encodeAb(arrayBuffer) {
    var bytes = new Uint8Array(arrayBuffer),
    i, len = bytes.length, base64 = '';
    
    for (i = 0; i < len; i+=3) {
        base64 += chars[bytes[i] >> 2];
        base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64 += chars[bytes[i + 2] & 63];
    }
    
    if ((len % 3) === 2) {
        base64 = base64.substring(0, base64.length - 1) + '=';
    } else if (len % 3 === 1) {
        base64 = base64.substring(0, base64.length - 2) + '==';
    }
    
    return base64;
}

function decodeAb(base64) {
    var bufferLength = base64.length * 0.75,
    len = base64.length, i, p = 0,
    encoded1, encoded2, encoded3, encoded4;
    
    if (base64[base64.length - 1] === '=') {
        bufferLength--;
        if (base64[base64.length - 2] === '=') {
            bufferLength--;
        }
    }
    
    var arrayBuffer = new ArrayBuffer(bufferLength),
    bytes = new Uint8Array(arrayBuffer);
    
    for (i = 0; i < len; i+=4) {
        encoded1 = lookup[base64.charCodeAt(i)];
        encoded2 = lookup[base64.charCodeAt(i+1)];
        encoded3 = lookup[base64.charCodeAt(i+2)];
        encoded4 = lookup[base64.charCodeAt(i+3)];
        
        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }
    
    return arrayBuffer;
}

function addNewLines(str) {
    var finalString = '';
    while (str.length > 0) {
        finalString += str.substring(0, 64) + '\r\n';
        str = str.substring(64);
    }
    
    return finalString;
}

function removeLines(str) {
    return str.replace(/\r?\n|\r/g, '');
}

function toAsn1(arrayBuffer, salt, iv, crypt) {
    var key = crypt.arrayBufferToHexString(arrayBuffer);
    
    var KEY_OCTET = '04820' + (key.length / 2).toString(16) + key;
    var PBES2_OID = '06092a864886f70d01050d';
    var PBKDF2_OID = '06092a864886f70d01050c';
    var AESCBC_OID = '060960864801650304012a';
    var SALT_OCTET = '0410' + crypt.arrayBufferToHexString(salt);
    var ITER_INTEGER = '02020800';
    var IV_OCTET = '0410' + crypt.arrayBufferToHexString(iv);
    var SEQUENCE_LENGTH = (87 + (key.length / 2)).toString(16);
    var SEQUENCE = '30820' + SEQUENCE_LENGTH + '3051' + PBES2_OID + '30443023' + PBKDF2_OID + '3016' + SALT_OCTET + ITER_INTEGER + '301d' + AESCBC_OID + IV_OCTET + KEY_OCTET;
    
    console.log(SEQUENCE);
    var result = crypt.hexStringToArrayBuffer(SEQUENCE);
    return crypt.arrayBufferToBase64(result);
}

function fromAsn1(pem, crypt) {
    pem = removeLines(pem);
    pem = pem.replace('-----BEGIN ENCRYPTED PRIVATE KEY-----', '');
    pem = pem.replace('-----END ENCRYPTED PRIVATE KEY-----', '');
    pem = crypt.base64ToArrayBuffer(pem);
    var hex = crypt.arrayBufferToHexString(pem);
    
    var PBKDF2_OID = hex.indexOf('06092a864886f70d01050c');
    var AESCBC_OID = hex.indexOf('060960864801650304012a');
    var AESGCM_OID = hex.indexOf('060960864801650304012e');
    var AESCFB_OID = hex.indexOf('060960864801650304012c');
    
    var ivLength = null;
    var iv = null;
    var cipherSuite = null;
    var saltLength = parseInt(hex.substring(PBKDF2_OID + 28, PBKDF2_OID + 30), 16);
    var salt = hex.substring(PBKDF2_OID + 30, PBKDF2_OID + (saltLength * 2) + 30);
    var sequenceLength = parseInt(hex.substring(10, 12), 16);
    var keyLength = parseInt(hex.substring((sequenceLength + 8) * 2, ((sequenceLength + 8) * 2) + 4), 16);
    var encryptedData = hex.substring((sequenceLength + 10) * 2, ((sequenceLength + 10) * 2) + (keyLength * 2));
    
    if(AESCBC_OID > 0) {
        ivLength = parseInt(hex.substring(AESCBC_OID + 24, AESCBC_OID + 26), 16);
        iv = hex.substring(AESCBC_OID + 26, AESCBC_OID + (ivLength * 2) + 26);
        cipherSuite = 'AES-CBC';
    } else if(AESGCM_OID > 0) {
        ivLength = parseInt(hex.substring(AESGCM_OID + 24, AESGCM_OID + 26), 16);
        iv = hex.substring(AESGCM_OID + 26, AESGCM_OID + (ivLength * 2) + 26);
        cipherSuite = 'AES-GCM';
    } else if(AESCFB_OID > 0) {
        ivLength = parseInt(hex.substring(AESCFB_OID + 24, AESCFB_OID + 26), 16);
        iv = hex.substring(AESCFB_OID + 26, AESCFB_OID + (ivLength * 2) + 26);
        cipherSuite = 'AES-CFB';
    }
    
    var res = {
        salt: crypt.hexStringToArrayBuffer(salt),
        iterations: 2048,
        cipherSuite: cipherSuite,
        iv: crypt.hexStringToArrayBuffer(iv),
        encryptedData: crypt.hexStringToArrayBuffer(encryptedData)
    };
    
    return res;
}

/**
 *
 * Utility methods for OpenCrypto lib operations
 */
OpenCrypto.prototype.arrayBufferToString = function(arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
        throw new TypeError('Expected input to be an ArrayBuffer Object');
    }
    
    var decoder = new TextDecoder('utf-8');
    return decoder.decode(arrayBuffer);
};
 
OpenCrypto.prototype.stringToArrayBuffer = function(str) {
    if (typeof str !== 'string') {
        throw new TypeError('Expected input to be a String');
    }
    
    var encoder = new TextEncoder('utf-8');
    var byteArray = encoder.encode(str);
    return byteArray.buffer;
};
 
OpenCrypto.prototype.arrayBufferToHexString = function(arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
        throw new TypeError('Expected input to be an ArrayBuffer Object');
    }
    
    var byteArray = new Uint8Array(arrayBuffer);
    var hexString = '';
    var nextHexByte;

    for (var i = 0; i < byteArray.byteLength; i++) {
        nextHexByte = byteArray[i].toString(16);
        if (nextHexByte.length < 2) {
            nextHexByte = '0' + nextHexByte;
        }
        hexString += nextHexByte;
    }
    
    return hexString;
};

OpenCrypto.prototype.hexStringToArrayBuffer = function(hexString) {
    if (typeof hexString !== 'string') {
        throw new TypeError('Expected input of hexString to be a String');
    }
    
    if ((hexString.length % 2) !== 0) {
        throw new RangeError('Expected string to be an even number of characters');
    }
    
    var byteArray = new Uint8Array(hexString.length / 2);
    for (var i = 0; i < hexString.length; i += 2) {
        byteArray[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
    }
    
    return byteArray.buffer;
};

OpenCrypto.prototype.arrayBufferToBase64 = function(arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
        throw new TypeError('Expected input to be an ArrayBuffer Object');
    }
    
    return encodeAb(arrayBuffer);
};

OpenCrypto.prototype.base64ToArrayBuffer = function(b64) {
    if (typeof b64 !== 'string') {
        throw new TypeError('Expected input to be a base64 String');
    }
    
    return decodeAb(b64);
};

/**
 *
 * Method for generating asymmetric RSA-OAEP keypair
 * - bits        {Integer}  default: "2048" 2048 bits key pair
 * - usage       {Array}    default: "['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']" contains all available options at default
 * - algo        {String}   default: "SHA-256" uses SHA-256 hash algorithm as default
 * - extractable {Boolean}  default: "true" whether the key is extractable
 */
OpenCrypto.prototype.getKeyPair = function(bits, usage, algo, extractable) {
    bits = bits | 2048;
    usage = usage | ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
    algo = algo | 'SHA-256';
    extractable = extractable | true;
    
    var self = this;
    return new Promise(function(resolve, reject) {
        if (typeof bits !== 'number') {
            throw new TypeError('Expected input of bits to be a Number');
        }
        
        if (typeof usage !== 'object') {
            throw new TypeError('Expected input of usage to be an Array');
        }
        
        if (typeof algo !== 'string') {
            throw new TypeError('Expected input of algo expected to be a String');
        }
        
        if (typeof extractable !== 'boolean') {
            throw new TypeError('Expected input of extractable to be a Boolean');
        }
        
        cryptoApi.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: bits,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: {name: algo}
            },
            extractable,
            usage
        ).then(function(keyPair) {
            resolve(keyPair);
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Converts asymmetric private key from CryptoKey to PEM format
 * - privateKey        {CryptoKey}  default: "undefined" CryptoKey generated by WebCrypto API
 */
 OpenCrypto.prototype.cryptoPrivateToPem = function(privateKey) {
     var self = this;
     return new Promise(function(resolve, reject) {
         if (typeof privateKey !== 'object') {
             throw new TypeError('Expected input to be a CryptoKey Object');
         }
         
         cryptoApi.exportKey(
             'pkcs8',
             privateKey
         ).then(function(exportedPrivateKey) {
             var b64 = self.arrayBufferToBase64(exportedPrivateKey);
             var pem = addNewLines(b64);
             pem = '-----BEGIN PRIVATE KEY-----\r\n' + pem + '-----END PRIVATE KEY-----';
             
             resolve(pem);
         }).catch(function(err) {
             reject(err);
         });
     });
 };

/**
 *
 * Converts asymmetric private key from PEM to CryptoKey format
 * - privateKey        {String}  default: "undefined" private key in PEM format
 */
OpenCrypto.prototype.pemPrivateToCrypto = function(pem) {
    var self = this;
    return new Promise(function(resolve, reject) {
        if (typeof pem !== 'string') {
            throw new TypeError('Expected input of PEM to be a String');
        }
        
        pem = pem.replace('-----BEGIN PRIVATE KEY-----', '');
        var b64 = pem.replace('-----END PRIVATE KEY-----', '');
        b64 = removeLines(b64);
        var arrayBuffer = self.base64ToArrayBuffer(b64);
        
        cryptoApi.importKey(
            'pkcs8',
            arrayBuffer,
            {
                name: 'RSA-OAEP',
                hash: {name: 'SHA-256'}
            },
            true,
            ['decrypt', 'unwrapKey']
        ).then(function(importedPrivateKey) {
            resolve(importedPrivateKey);
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Converts asymmetric public key from CryptoKey to PEM format
 * - publicKey        {CryptoKey}  default: "undefined" CryptoKey generated by WebCrypto API
 */
OpenCrypto.prototype.cryptoPublicToPem = function(publicKey) {
    var self = this;
    return new Promise(function(resolve, reject) {
        if (typeof publicKey !== 'object') {
            throw new TypeError('Expected input to be a CryptoKey Object');
        }
        
        cryptoApi.exportKey(
            'spki',
            publicKey
        ).then(function(exportedPublicKey) {
            var b64 = self.arrayBufferToBase64(exportedPublicKey);
            var pem = addNewLines(b64);
            pem = '-----BEGIN PUBLIC KEY-----\r\n' + pem + '-----END PUBLIC KEY-----';
            
            resolve(pem);
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Converts asymmetric public key from PEM to CryptoKey
 * - publicKey        {String}  default: "undefined" PEM public key
 */
OpenCrypto.prototype.pemPublicToCrypto = function(pem) {
    var self = this;
    return new Promise(function(resolve, reject) {
        if (typeof pem !== 'string') {
            throw new TypeError('Expected input of PEM to be a String');
        }
        
        pem = removeLines(pem);
        pem = pem.replace('-----BEGIN PUBLIC KEY-----', '');
        var b64 = pem.replace('-----END PUBLIC KEY-----', '');
        var arrayBuffer = self.base64ToArrayBuffer(b64);
        
        cryptoApi.importKey(
            'spki',
            arrayBuffer,
            {
                name: 'RSA-OAEP',
                hash: {name: 'SHA-256'}
            },
            true,
            ['encrypt', 'wrapKey']
        ).then(function(importedKey) {
            resolve(importedKey);
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Encrypts asymmetric private key based on passphrase to enable storage in unsecure environment
 * - privateKey        {CryptoKey}  default: "undefined" private key in CryptoKey format
 * - passphrase        {String}     default: "undefined" any passphrase string
 */
OpenCrypto.prototype.encryptPrivateKey = function(privateKey, passphrase) {
    var self = this;
    return new Promise(function(resolve, reject) {
        if (typeof privateKey !== 'object') {
            throw new TypeError('Expected input of privateKey to be a CryptoKey Object');
        }
        
        if (typeof passphrase !== 'string') {
            throw new TypeError('Expected input of passphrase to be a String');
        }
        
        var salt = securePRNG.getRandomValues(new Uint8Array(16));
        var iv = securePRNG.getRandomValues(new Uint8Array(16));
        
        cryptoApi.importKey(
            'raw',
            self.stringToArrayBuffer(passphrase),
            {
                name: 'PBKDF2'
            },
            false,
            ['deriveKey']
        ).then(function(baseKey) {
            cryptoApi.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 2048,
                    hash: 'SHA-1'
                },
                baseKey,
                {
                    name: 'AES-CBC',
                    length: 256
                },
                true,
                ['wrapKey']
            ).then(function(derivedKey) {
                cryptoApi.wrapKey(
                    'pkcs8',
                    privateKey,
                    derivedKey,
                    {
                        name: 'AES-CBC',
                        iv: iv
                    }
                ).then(function(wrappedKey) {
                    var asnKey = toAsn1(wrappedKey, salt, iv, self);
                    var pemKey = addNewLines(asnKey);
                    pemKey = '-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n' + pemKey + '-----END ENCRYPTED PRIVATE KEY-----';
                    resolve(pemKey);
                }).catch(function(err) {
                    reject(err);
                });
            }).catch(function(err) {
                reject(err);
            });
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Decrypts asymmetric private key by passphrase and salt
 * - encryptedPrivateKey        {base64 String}  default: "undefined" private key in PKCS #8 format
 * - passphrase                 {String}         default: "undefined" any passphrase string
 */
OpenCrypto.prototype.decryptPrivateKey = function(encryptedPrivateKey, passphrase) {
    var self = this;
    return new Promise(function(resolve, reject) {
        if (typeof encryptedPrivateKey !== 'string') {
            throw new TypeError('Expected input of encryptedPrivateKey to be a base64 String');
        }
        
        if (typeof passphrase !== 'string') {
            throw new TypeError('Expected input of passphrase to be a String');
        }
        
        encryptedPrivateKey = fromAsn1(encryptedPrivateKey, self);
        cryptoApi.importKey(
            'raw',
            self.stringToArrayBuffer(passphrase),
            {
                name: 'PBKDF2'
            },
            false,
            ['deriveKey']
        ).then(function(baseKey) {
            cryptoApi.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: encryptedPrivateKey.salt,
                    iterations: encryptedPrivateKey.iterations,
                    hash: 'SHA-1'
                },
                baseKey,
                {
                    name: encryptedPrivateKey.cipherSuite,
                    length: 256
                },
                true,
                ['unwrapKey']
            ).then(function(derivedKey) {
                cryptoApi.unwrapKey(
                    'pkcs8',
                    encryptedPrivateKey.encryptedData,
                    derivedKey,
                    {
                        name: encryptedPrivateKey.cipherSuite,
                        iv: encryptedPrivateKey.iv
                    },
                    {
                        name: 'RSA-OAEP',
                        hash: {name: 'SHA-256'}
                    },
                    true,
                    ['decrypt', 'unwrapKey']
                ).then(function(unwrappedKey) {
                    resolve(unwrappedKey);
                }).catch(function(err) {
                    reject(err);
                });
            }).catch(function(err) {
                reject(err);
            });
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Encrypts data using asymmetric encryption
 * Uses RSA-OAEP for asymmetric key as default.
 * - publicKey               {CryptoKey} default: "undefined"
 * - data                    {String} default: "undefined"
 */
OpenCrypto.prototype.encryptPublic = function(publicKey, data) {
    var self = this;
    return new Promise(function(resolve, reject) {
        if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
            throw new TypeError('Expected input of privateKey to be a CryptoKey of type public');
        }
        
        if (typeof data !== 'string') {
            throw new TypeError('Expected input of data to be a String');
        }
        
        cryptoApi.encrypt(
            {
                name: 'RSA-OAEP'
            },
            publicKey,
            self.stringToArrayBuffer(data)
        ).then(function(encrypted) {
            resolve(self.arrayBufferToBase64(encrypted));
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Decrypts data using asymmetric encryption
 * Uses RSA-OAEP for asymmetric key as default.
 * - privateKey              {CryptoKey} default: "undefined"
 * - encryptedData           {base64 String} default: "undefined"
 */
OpenCrypto.prototype.decryptPrivate = function(privateKey, encryptedData) {
    var self = this;
    return new Promise(function(resolve, reject) {
        if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
            throw new TypeError('Expected input of privateKey to be a CryptoKey of type private');
        }
        
        if (typeof encryptedData !== 'string') {
            throw new TypeError('Expected input of encryptedData to be a String');
        }
        
        cryptoApi.decrypt(
            {
                name: 'RSA-OAEP'
            },
            privateKey,
            self.base64ToArrayBuffer(encryptedData)
        ).then(function(decrypted) {
            resolve(self.arrayBufferToString(decrypted));
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Encrypts symmetric / session key
 * Uses RSA-OAEP for asymmetric key as default.
 * - publicKey               {CryptoKey} default: "undefined"
 * - sessionKey              {CryptoKey} default: "undefined"
 * - publicKeyHash           {String} default: "SHA-256"
 */
OpenCrypto.prototype.encryptKey = function(publicKey, sessionKey, publicKeyHash) {
    publicKeyHash = publicKeyHash | 'SHA-256';
    
    var self = this;
    return new Promise(function(resolve, reject) {
        if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
            throw new TypeError('Expected input of publicKey to be a CryptoKey of type public');
        }
        
        if (Object.prototype.toString.call(sessionKey) !== '[object CryptoKey]' && sessionKey.type !== 'secret') {
            throw new TypeError('Expected input of sessionKey to be a CryptoKey of type secret');
        }
        
        cryptoApi.wrapKey(
            'raw',
            sessionKey,
            publicKey,
            {
                name: 'RSA-OAEP',
                hash: {name: publicKeyHash}
            }
        ).then(function(encryptedKey) {
            resolve(self.arrayBufferToBase64(encryptedKey));
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Decrypts symmetric / session key
 * Uses RSA-OAEP for asymmetric key as default.
 * - privateKey              {CryptoKey} default: "undefined"
 * - encryptedSessionKey     {base64 String} default: "undefined"
 * - cipherSuite             {String} default: "AES-GCM"
 * - keyLength               {Number} default: "256"
 * - privateKeyLength        {Number} default: "2048"
 * - privateKeyHash          {String} default: "SHA-256"
 */
OpenCrypto.prototype.decryptKey = function(privateKey, encryptedSessionKey, cipherSuite, keyLength, privateKeyLength, privateKeyHash) {
    cipherSuite = cipherSuite | 'AES-GCM';
    keyLength = keyLength | 256;
    privateKeyLength = privateKeyLength | 2048;
    privateKeyHash = privateKeyHash | 'SHA-256';
    
    var self = this;
    return new Promise(function(resolve, reject) {
        if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
            throw new TypeError('Expected input of privateKey to be a CryptoKey of type private');
        }
        
        if (typeof encryptedSessionKey !== 'string') {
            throw new TypeError('Expected input of encryptedSessionKey to be a base64 String');
        }
        
        if (typeof cipherSuite !== 'string') {
            throw new TypeError('Expected input of cipherSuite to be a String');
        }
        
        if (typeof keyLength !== 'number') {
            throw new TypeError('Expected input of keyLength to be a Number');
        }
        
        if (typeof privateKeyLength !== 'number') {
            throw new TypeError('Expected input of privateKeyLength to be a Number');
        }
        
        if (typeof privateKeyHash !== 'string') {
            throw new TypeError('Expected input of privateKeyHash to be a String');
        }
        
        cryptoApi.unwrapKey(
            'raw',
            encryptedSessionKey,
            privateKey,
            {
                name: 'RSA-OAEP',
                modulusLength: privateKeyLength,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: {name: privateKeyHash}
            },
            {
                name: cipherSuite,
                length: keyLength
            },
            true,
            ['encrypt', 'decrypt']
        ).then(function(decryptedKey) {
            resolve(decryptedKey);
        }).catch(function(err) {
            reject(err);
        });
    });
};

/**
 *
 * Generates symmetric / session key for AES encryption
 * Uses Galois/Counter Mode (GCM) for operation by default.
 * - bits              {Integer} default: "256" accepts 128 and 256
 * - usage             {Array}   default: "['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']" default contains all accepted values
 * - extractable       {Boolean} default: "false" whether the key can be exported
 * - cipherMode        {String}  default: "AES-GCM" Cipher block mode operation
 */
 OpenCrypto.prototype.getSessionKey = function(bits, usage, extractable, cipherMode) {
     bits = bits | 256;
     usage = usage | ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
     extractable = extractable | true;
     cipherMode = cipherMode | 'AES-GCM';
     
     var self = this;
     return new Promise(function(resolve, reject) {
         if (typeof bits !== 'number') {
             throw new TypeError('Expected input of bits to be a Number');
         }
         
         if (typeof usage !== 'object') {
             throw new TypeError('Expected input of usage to be an Array');
         }
         
         if (typeof extractable !== 'boolean') {
             throw new TypeError('Expected input of extractable expected to be a Boolean');
         }
         
         if (typeof cipherMode !== 'string') {
             throw new TypeError('Expected input of cipherMode expected to be a String');
         }
         
         cryptoApi.generateKey(
             {
                 name: cipherMode,
                 length: bits
             },
             extractable,
             usage
         ).then(function(sessionKey) {
             resolve(sessionKey);
         }).catch(function(err) {
             reject(err);
         });
     });
 };
 
 /**
 *
 * Encrypts data using symmetric / session key, converts them to
 * base64 format and prepends IV in front of the encrypted data.
 * Uses Galois/Counter Mode (GCM) for operation.
 * - sessionKey        {CryptoKey}  default: "undefined" symmetric or session key
 * - data              {String}     default: "undefined" any data to be encrypted
 */
 OpenCrypto.prototype.encrypt = function(sessionKey, data) {
     var self = this;
     return new Promise(function(resolve, reject) {
         if (typeof sessionKey !== 'object') {
             throw new TypeError('Expected input of sessionKey to be a CryptoKey Object');
         }
         
         if (typeof data !== 'string') {
             throw new TypeError('Expected input of data to be a String');
         }
         
         var ivAb = securePRNG.getRandomValues(new Uint8Array(12));
         cryptoApi.encrypt(
             {
                 name: 'AES-GCM',
                 iv: ivAb,
                 tagLength: 128
             },
             sessionKey,
             self.base64ToArrayBuffer(data)
         ).then(function(encrypted) {
             var ivB64 = self.arrayBufferToBase64(ivAb);
             var encryptedB64 = self.arrayBufferToBase64(encrypted);
             resolve(ivB64 + encryptedB64);
         }).catch(function(err) {
             reject(err);
         });
     });
 };
 
 /**
 *
 * Decrypts data using symmetric / session key, extracts IV from
 * the front of the encrypted data and converts decrypted data
 * to base64. Uses Galois/Counter Mode (GCM) for operation.
 * - sessionKey        {CryptoKey}      default: "undefined" symmetric or session key
 * - encryptedData     {base64 String}  default: "undefined" any data to be decrypted
 */
 OpenCrypto.prototype.decrypt = function(sessionKey, encryptedData) {
     var self = this;
     return new Promise(function(resolve, reject) {
         if (typeof sessionKey !== 'object') {
             throw new TypeError('Expected input of sessionKey to be a CryptoKey Object');
         }
         
         if (typeof encryptedData !== 'string') {
             throw new TypeError('Expected input of encryptedData to be a String');
         }
         
         var ivB64 = encryptedData.substring(0, 16);
         var encryptedB64 = encryptedData.substring(16);
         var ivAb = self.base64ToArrayBuffer(ivB64);
         var encryptedAb = self.base64ToArrayBuffer(encryptedB64);
         
         cryptoApi.decrypt(
             {
                 name: 'AES-GCM',
                 iv: ivAb,
                 tagLength: 128
             },
             sessionKey,
             encryptedAb
         ).then(function(decrypted) {
             resolve(self.arrayBufferToBase64(decrypted));
         }).catch(function(err) {
             reject(err);
         });
     });
 };

/**
 *
 * Method for generating symmetric AES 256 bit key derived from passphrase and salt
 * - passphrase        {String}  default: "undefined" any passphrase string
 * - salt              {String}  default: "undefined" any salt, may be unique user ID for example
 * - iterations        {Number}  default: "300000"    number of iterations is 300 000 (Recommended)
 */
OpenCrypto.prototype.keyFromPassphrase = function(passphrase, salt, iterations) {
    iterations = iterations | 300000;
    
    var self = this;
    return new Promise(function(resolve, reject) {
        if (typeof passphrase !== 'string') {
            throw new TypeError('Expected input of passphrase to be a String');
        }
        
        if (typeof salt !== 'string') {
            throw new TypeError('Expected input of salt to be a String');
        }
        
        if (typeof iterations !== 'number') {
            throw new TypeError('Expected input of iterations to be a number');
        }
        
        cryptoApi.importKey(
            'raw',
            self.stringToArrayBuffer(passphrase),
            {
                name: 'PBKDF2'
            },
            false,
            ['deriveKey']
        ).then(function(baseKey) {
            cryptoApi.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: self.stringToArrayBuffer(salt),
                    iterations: iterations,
                    hash: 'SHA-256'
                },
                baseKey,
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true,
                ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
            ).then(function(derivedKey) {
                cryptoApi.exportKey(
                    'raw',
                    derivedKey
                ).then(function(exportedKey) {
                    resolve(exportedKey);
                }).catch(function(err) {
                    reject(err);
                });
            }).catch(function(err) {
                reject(err);
            });
        }).catch(function(err) {
            reject(err);
        });
    });
};