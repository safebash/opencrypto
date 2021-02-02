export default class OpenCrypto {
  /**
   * BEGIN
   * base64-arraybuffer
   * GitHub @niklasvh
   * Copyright (c) 2012 Niklas von Hertzen
   * MIT License
   */
  encodeAb(arrayBuffer: any): string;
  decodeAb(base64: any): ArrayBuffer;
  /**
   * END
   * base64-arraybuffer
   */
  /**
   * Method for encoding ArrayBuffer into UTF-8 String
   */
  arrayBufferToString(arrayBuffer: any): string;
  /**
   * Method for decoding String to ArrayBuffer
   */
  stringToArrayBuffer(str: any): ArrayBufferLike;
  /**
   * Method for encoding ArrayBuffer to hexadecimal String
   */
  arrayBufferToHexString(arrayBuffer: any): string;
  /**
   * Method for decoding hexadecimal String to ArrayBuffer
   */
  hexStringToArrayBuffer(hexString: any): ArrayBufferLike;
  /**
   * Method for encoding ArrayBuffer to base64 String
   */
  arrayBufferToBase64(arrayBuffer: any): string;
  /**
   * Method for decoding base64 String to ArrayBuffer
   */
  base64ToArrayBuffer(b64: any): ArrayBuffer;
  /**
   * Method for encoding decimal Number to hexadecimal String
   */
  decimalToHex(d: any, unsigned: any): string;
  /**
   * Method for addition of new lines into PEM encoded key
   */
  addNewLines(str: any): string;
  /**
   * Method that removes lines from PEM encoded key
   */
  removeLines(str: any): any;
  /**
   * Method that encodes ASN.1 information into PEM encoded key
   */
  toAsn1(wrappedKey: any, salt: any, iv: any, iterations: any, hash: any, cipher: any, length: any): string;
  /**
   * Method that retrieves ASN.1 encoded information from PEM encoded key
   */
  fromAsn1(pem: any): {
      salt: ArrayBufferLike;
      iv: ArrayBufferLike;
      cipher: string;
      length: number;
      hash: string;
      iter: number;
      encryptedData: ArrayBufferLike;
  };
  /**
   * Method that converts asymmetric private key from CryptoKey to PEM format
   * @param {CryptoKey} privateKey default: "undefined"
   */
  cryptoPrivateToPem(privateKey: CryptoKey): Promise<any>;
  /**
   * Method that converts asymmetric private key from PEM to CryptoKey format
   * @param {String} pem default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDH: { name: 'ECDH', usages: ['deriveKey', 'deriveBits'], isExtractable: true }
   * -- ECDSA: { name: 'ECDSA', usages: ['sign'], isExtractable: true }
   * -- RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['decrypt', 'unwrapKey'], isExtractable: true }
   * -- RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['sign'], isExtractable: true }
   */
  pemPrivateToCrypto(pem: string, options: any): Promise<any>;
  /**
   * Method that converts asymmetric public key from CryptoKey to PEM format
   * @param {CryptoKey} publicKey default: "undefined"
   */
  cryptoPublicToPem(publicKey: CryptoKey): Promise<any>;
  /**
   * Method that converts asymmetric public key from PEM to CryptoKey format
   * @param {String} publicKey default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDH: { name: 'ECDH', usages: [], isExtractable: true }
   * -- ECDSA: { name: 'ECDSA', usages: ['verify'], isExtractable: true }
   * -- RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['encrypt', 'wrapKey'], isExtractable: true }
   * -- RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['verify'], isExtractable: true }
   */
  pemPublicToCrypto(pem: any, options: any): Promise<any>;
  /**
   * Method that converts CryptoKey to base64
   * @param {CryptoKey} key default: "undefined"
   * @param {String} type default: "secret: 'raw'; private: 'pkcs8'; public: 'spki'"
   */
  cryptoToBase64(key: CryptoKey, type: string): Promise<any>;
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
  base64ToCrypto(key: string, options: any): Promise<any>;
  /**
   * Method that generates asymmetric RSA-OAEP key pair
   * @param {Integer} modulusLength default: "2048"
   * @param {String} hash default: "SHA-512"
   * @param {String} paddingScheme default: "RSA-OAEP"
   * @param {Array} usages default: "['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']"
   * @param {Boolean} isExtractable default: "true"
   */
  getRSAKeyPair(modulusLength: any, hash: string, paddingScheme: string, usages: any[], isExtractable: boolean): Promise<any>;
  /**
   * Method that encrypts data using asymmetric encryption
   * @param {CryptoKey} publicKey default: "undefined"
   * @param {ArrayBuffer} data default: "undefined"
   */
  rsaEncrypt(publicKey: CryptoKey, data: ArrayBuffer): Promise<any>;
  /**
   * Method that decrypts data using asymmetric encryption
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {String} encryptedData default: "undefined"
   */
  rsaDecrypt(privateKey: CryptoKey, encryptedData: string): Promise<any>;
  /**
   * Method that generates asymmetric Elliptic Curve Diffie-Hellman key pair
   * @param {String} curve default: "P-256"
   * @param {String} type default: "ECDH"
   * @param {Array} usages default: "['deriveKey', 'deriveBits']"
   * @param {Boolean} isExtractable default: "true"
   */
  getECKeyPair(curve: string, type: string, usages: any[], isExtractable: boolean): Promise<any>;
  /**
   * Method that retrieves public key from private key
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDH: { usages: ['deriveKey', 'deriveBits'], isExtractable: true }
   * -- ECDSA: { usages: ['sign', 'verify'], isExtractable: true }
   * -- RSA-OAEP: { usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
   * -- RSA-PSS: { usages: ['sign', 'verify'], isExtractable: true }
   */
  getPublicKey(privateKey: CryptoKey, options: any): Promise<any>;
  /**
   * Method that encrypts asymmetric private key using passphrase to enable storage in unsecure environment
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {String} passphrase default: "undefined"
   * @param {Number} iterations default: "64000"
   * @param {String} hash default: "SHA-512"
   * @param {String} cipher default: "AES-GCM"
   * @param {Number} length default: "256"
   */
  encryptPrivateKey(privateKey: CryptoKey, passphrase: string, iterations: number, hash: string, cipher: string, length: number): Promise<any>;
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
  decryptPrivateKey(encryptedPrivateKey: string, passphrase: string, options: any): Promise<any>;
  /**
   * Method that performs ECDH key agreement
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {CryptoKey} publicKey default: "undefined"
   * @param {Object} options default: "{ bitLength: 256, hkdfHash: 'SHA-512', hkdfSalt: "new UInt8Array()", hkdfInfo: "new UInt8Array()", cipher: 'AES-GCM', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
   */
  keyAgreement(privateKey: CryptoKey, publicKey: CryptoKey, options: any): Promise<any>;
  /**
   * Method that generates symmetric/shared key for AES encryption
   * @param {Integer} length default: "256"
   * @param {Object} options default: "{ cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
   */
  getSharedKey(length: any, options: any): Promise<any>;
  /**
   * Method that encrypts keys
   * @param {CryptoKey} wrappingKey default: "undefined"
   * @param {CryptoKey} key default: "undefined"
   */
  encryptKey(wrappingKey: CryptoKey, key: CryptoKey): Promise<any>;
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
  decryptKey(unwrappingKey: CryptoKey, encryptedKey: string, options: any): Promise<any>;
  /**
   * Method that generates key signature using ECDSA or RSA-PSS
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {CryptoKey} key default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDSA: { hash: 'SHA-512' }
   * -- RSA-PSS: { saltLength: 128 }
   */
  signKey(privateKey: CryptoKey, key: CryptoKey, options: any): Promise<any>;
  /**
   * Method that verifies key signature using ECDSA or RSA-PSS
   * @param {CryptoKey} publicKey default: "undefined"
   * @param {CryptoKey} key default: "undefined"
   * @param {String} signature default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDSA: { hash: 'SHA-512' }
   * -- RSA-PSS: { saltLength: 128 }
   */
  verifyKey(publicKey: CryptoKey, key: CryptoKey, signature: string, options: any): Promise<any>;
  /**
   * Method that generates signature of data using ECDSA or RSA-PSS
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {ArrayBuffer} data default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDSA: { hash: 'SHA-512' }
   * -- RSA-PSS: { saltLength: 128 }
   */
  sign(privateKey: CryptoKey, data: ArrayBuffer, options: any): Promise<any>;
  /**
   * Method that verifies data signature using ECDSA or RSA-PSS
   * @param {CryptoKey} publicKey default: "undefined"
   * @param {ArrayBuffer} data default: "undefined"
   * @param {String} signature default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDSA: { hash: 'SHA-512' }
   * -- RSA-PSS: { saltLength: 128 }
   */
  verify(publicKey: CryptoKey, data: ArrayBuffer, signature: string, options: any): Promise<any>;
  /**
   * Method that encrypts data using symmetric/shared key
   * @param {CryptoKey} sharedKey default: "undefined"
   * @param {ArrayBuffer} data default: "undefined"
   */
  encrypt(sharedKey: CryptoKey, data: ArrayBuffer): Promise<any>;
  /**
   * Method that decrypts data using symmetric/shared key
   * @param {CryptoKey} sharedKey default: "undefined"
   * @param {String} encryptedData default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- AES-GCM: { cipher: 'AES-GCM' }
   * -- AES-CBC: { cipher: 'AES-CBC' }
   */
  decrypt(sharedKey: CryptoKey, encryptedData: string, options: any): Promise<any>;
  /**
   * Method that derives shared key from passphrase
   * @param {String} passphrase default: "undefined"
   * @param {ArrayBuffer} salt default: "undefined"
   * @param {Number} iterations default: "64000"
   * @param {Object} options default: "{ hash: 'SHA-512', length: 256, cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
   */
  derivePassphraseKey(passphrase: string, salt: ArrayBuffer, iterations: number, options: any): Promise<any>;
  /**
   * Method that derives hash from passphrase
   * @param {String} passphrase default: "undefined"
   * @param {ArrayBuffer} salt default: "undefined" salt
   * @param {Number} iterations default: "64000"
   * @param {Object} options default: "{ hash: 'SHA-512', length: 256, cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
   */
  hashPassphrase(passphrase: string, salt: ArrayBuffer, iterations: number, options: any): Promise<any>;
  /**
   * Method that generates fingerprint of EC, RSA and AES keys
   * @param {CryptoKey} key default: "undefined"
   * @param {Object} options default: { hash: 'SHA-512', isBuffer: false }
   */
  getFingerprint(key: CryptoKey, options: any): Promise<any>;
  /**
   * Method that generates random bytes using cryptographically secure PRNG
   * @param {Number} size default: "16"
   */
  getRandomBytes(size: number): Promise<any>;
}
