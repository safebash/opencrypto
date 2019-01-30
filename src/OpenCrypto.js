/**
 *
 * Copyright (c) 2016 Peter Bielak
 * Cryptography Consultancy by Andrew Kozlik, Ph.D.
 *
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

const cryptoLib = window.crypto || window.msCrypto
const cryptoApi = cryptoLib.subtle || cryptoLib.webkitSubtle
const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const lookup = new Uint8Array(256)

const PBES2_OID = '06092a864886f70d01050d'
const PBKDF2_OID = '06092a864886f70d01050c'

const AES256GCM_OID = '060960864801650304012e'
const AES192GCM_OID = '060960864801650304011a'
const AES128GCM_OID = '0609608648016503040106'

const AES256CBC_OID = '060960864801650304012a'
const AES192CBC_OID = '0609608648016503040116'
const AES128CBC_OID = '0609608648016503040102'

const AES256CFB_OID = '060960864801650304012c'
const AES192CFB_OID = '0609608648016503040118'
const AES128CFB_OID = '06086086480165030404'

const SHA512_OID = '06082a864886f70d020b0500'
const SHA384_OID = '06082a864886f70d020a0500'
const SHA256_OID = '06082a864886f70d02090500'
const SHA1_OID = '06082a864886f70d02070500'

const RSA_OID = '06092a864886f70d010101'
const EC_OID = '06072a8648ce3d0201'
const P256_OID = '06082a8648ce3d030107'
const P384_OID = '06052b81040022'
const P521_OID = '06052b81040023'

export default class OpenCrypto {
  constructor () {
    for (let i = 0; i < chars.length; i++) {
      lookup[chars.charCodeAt(i)] = i
    }
  }

  /**
    * BEGIN
    * base64-arraybuffer
    * GitHub @niklasvh
    * Copyright (c) 2012 Niklas von Hertzen
    * MIT License
    */
  encodeAb (arrayBuffer) {
    let bytes = new Uint8Array(arrayBuffer)
    let len = bytes.length
    let base64 = ''

    for (let i = 0; i < len; i += 3) {
      base64 += chars[bytes[i] >> 2]
      base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)]
      base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)]
      base64 += chars[bytes[i + 2] & 63]
    }

    if ((len % 3) === 2) {
      base64 = base64.substring(0, base64.length - 1) + '='
    } else if (len % 3 === 1) {
      base64 = base64.substring(0, base64.length - 2) + '=='
    }

    return base64
  }

  decodeAb (base64) {
    let bufferLength = base64.length * 0.75
    let len = base64.length
    let p = 0
    let encoded1
    let encoded2
    let encoded3
    let encoded4

    if (base64[base64.length - 1] === '=') {
      bufferLength--
      if (base64[base64.length - 2] === '=') {
        bufferLength--
      }
    }

    let arrayBuffer = new ArrayBuffer(bufferLength)
    let bytes = new Uint8Array(arrayBuffer)

    for (let i = 0; i < len; i += 4) {
      encoded1 = lookup[base64.charCodeAt(i)]
      encoded2 = lookup[base64.charCodeAt(i + 1)]
      encoded3 = lookup[base64.charCodeAt(i + 2)]
      encoded4 = lookup[base64.charCodeAt(i + 3)]

      bytes[p++] = (encoded1 << 2) | (encoded2 >> 4)
      bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2)
      bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63)
    }

    return arrayBuffer
  }
  /**
    * END
    * base64-arraybuffer
    */

  /**
    * Encoding / Decoding
    */
  arrayBufferToString (arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
      throw new TypeError('Expected input to be an ArrayBuffer Object')
    }

    let decoder = new TextDecoder('utf-8') // eslint-disable-line
    return decoder.decode(arrayBuffer)
  }

  stringToArrayBuffer (str) {
    if (typeof str !== 'string') {
      throw new TypeError('Expected input to be a String')
    }

    let encoder = new TextEncoder('utf-8') // eslint-disable-line
    let byteArray = encoder.encode(str)
    return byteArray.buffer
  }

  arrayBufferToHexString (arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
      throw new TypeError('Expected input to be an ArrayBuffer Object')
    }

    let byteArray = new Uint8Array(arrayBuffer)
    let hexString = ''
    let nextHexByte

    for (let i = 0; i < byteArray.byteLength; i++) {
      nextHexByte = byteArray[i].toString(16)

      if (nextHexByte.length < 2) {
        nextHexByte = '0' + nextHexByte
      }

      hexString += nextHexByte
    }

    return hexString
  }

  hexStringToArrayBuffer (hexString) {
    if (typeof hexString !== 'string') {
      throw new TypeError('Expected input of hexString to be a String')
    }

    if ((hexString.length % 2) !== 0) {
      throw new RangeError('Expected string to be an even number of characters')
    }

    let byteArray = new Uint8Array(hexString.length / 2)
    for (let i = 0; i < hexString.length; i += 2) {
      byteArray[i / 2] = parseInt(hexString.substring(i, i + 2), 16)
    }

    return byteArray.buffer
  }

  arrayBufferToBase64 (arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
      throw new TypeError('Expected input to be an ArrayBuffer Object')
    }

    return this.encodeAb(arrayBuffer)
  }

  base64ToArrayBuffer (b64) {
    if (typeof b64 !== 'string') {
      throw new TypeError('Expected input to be a base64 String')
    }

    return this.decodeAb(b64)
  }

  decimalToHex (d, unsigned) {
    unsigned = (typeof unsigned !== 'undefined') ? unsigned : false

    let h = null
    if (typeof d === 'number') {
      if (unsigned) {
        h = (d).toString(16)
        return h.length % 2 ? '000' + h : '00' + h
      } else {
        h = (d).toString(16)
        return h.length % 2 ? '0' + h : h
      }
    } else if (typeof d === 'string') {
      h = (d.length / 2).toString(16)
      return h.length % 2 ? '0' + h : h
    }
  }

  addNewLines (str) {
    let finalString = ''
    while (str.length > 0) {
      finalString += str.substring(0, 64) + '\r\n'
      str = str.substring(64)
    }

    return finalString
  }

  removeLines (str) {
    return str.replace(/\r?\n|\r/g, '')
  }

  toAsn1 (wrappedKey, salt, iv, iterations, hash, cipher, keyLength) {
    wrappedKey = this.arrayBufferToHexString(wrappedKey)
    salt = this.arrayBufferToHexString(salt)
    iv = this.arrayBufferToHexString(iv)
    iterations = this.decimalToHex(iterations, true)
    let opt = {}

    switch (hash) {
      case 'SHA-512' :
        opt.HASH_OID = SHA512_OID
        break
      case 'SHA-384' :
        opt.HASH_OID = SHA384_OID
        break
      case 'SHA-256' :
        opt.HASH_OID = SHA256_OID
        break
      case 'SHA-1' :
        opt.HASH_OID = SHA1_OID
    }

    switch (cipher) {
      case 'AES-GCM' :
        if (keyLength === 256) {
          opt.CIPHER_OID = AES256GCM_OID
        } else if (keyLength === 192) {
          opt.CIPHER_OID = AES192GCM_OID
        } else if (keyLength === 128) {
          opt.CIPHER_OID = AES128GCM_OID
        }
        break
      case 'AES-CBC' :
        if (keyLength === 256) {
          opt.CIPHER_OID = AES256CBC_OID
        } else if (keyLength === 192) {
          opt.CIPHER_OID = AES192CBC_OID
        } else if (keyLength === 128) {
          opt.CIPHER_OID = AES128CBC_OID
        }
        break
      case 'AES-CFB' :
        if (keyLength === 256) {
          opt.CIPHER_OID = AES256CFB_OID
        } else if (keyLength === 192) {
          opt.CIPHER_OID = AES192CFB_OID
        } else if (keyLength === 128) {
          opt.CIPHER_OID = AES128CFB_OID
        }
    }

    let ITER_INTEGER = '02' + this.decimalToHex(iterations.length / 2) + iterations
    let SALT_OCTET = '04' + this.decimalToHex(salt) + salt
    let IV_OCTET = '04' + this.decimalToHex(iv) + iv
    let KEY_OCTET_PADDING = this.decimalToHex(wrappedKey).length / 2 === 2 ? '82' : '81'
    let KEY_OCTET = '04' + KEY_OCTET_PADDING + this.decimalToHex(wrappedKey) + wrappedKey

    opt.SEQUENCE_AES_CONTAINER = '30' + this.decimalToHex(opt.CIPHER_OID + IV_OCTET)
    opt.SEQUENCE_HASH_CONTAINER = '30' + this.decimalToHex(opt.HASH_OID)
    opt.SEQUENCE_PBKDF2_INNER_CONTAINER = '30' + this.decimalToHex(SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID)
    opt.SEQUENCE_PBKDF2_CONTAINER = '30' + this.decimalToHex(PBKDF2_OID + opt.SEQUENCE_PBKDF2_INNER_CONTAINER + SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID)
    opt.SEQUENCE_PBES2_INNER_CONTAINER = '30' + this.decimalToHex(opt.SEQUENCE_PBKDF2_CONTAINER + PBKDF2_OID + opt.SEQUENCE_PBKDF2_INNER_CONTAINER + SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID + opt.SEQUENCE_AES_CONTAINER + opt.CIPHER_OID + IV_OCTET)
    opt.SEQUENCE_PBES2_CONTAINER = '30' + this.decimalToHex(PBES2_OID + opt.SEQUENCE_PBES2_INNER_CONTAINER + opt.SEQUENCE_PBKDF2_CONTAINER + PBKDF2_OID + opt.SEQUENCE_PBKDF2_INNER_CONTAINER + SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID + opt.SEQUENCE_AES_CONTAINER + opt.CIPHER_OID + IV_OCTET)

    let SEQUENCE_PARAMETERS = opt.SEQUENCE_PBES2_CONTAINER + PBES2_OID + opt.SEQUENCE_PBES2_INNER_CONTAINER + opt.SEQUENCE_PBKDF2_CONTAINER + PBKDF2_OID + opt.SEQUENCE_PBKDF2_INNER_CONTAINER + SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID + opt.SEQUENCE_AES_CONTAINER + opt.CIPHER_OID + IV_OCTET
    let SEQUENCE_LENGTH = this.decimalToHex(SEQUENCE_PARAMETERS + KEY_OCTET)
    let SEQUENCE = '30' + KEY_OCTET_PADDING + SEQUENCE_LENGTH + SEQUENCE_PARAMETERS + KEY_OCTET

    let asnKey = this.hexStringToArrayBuffer(SEQUENCE)
    let pemKey = this.arrayBufferToBase64(asnKey)
    pemKey = this.addNewLines(pemKey)
    pemKey = '-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n' + pemKey + '-----END ENCRYPTED PRIVATE KEY-----'

    return pemKey
  }

  fromAsn1 (pem) {
    let opt = {}
    pem = this.removeLines(pem)
    pem = pem.replace('-----BEGIN ENCRYPTED PRIVATE KEY-----', '')
    pem = pem.replace('-----END ENCRYPTED PRIVATE KEY-----', '')
    pem = this.base64ToArrayBuffer(pem)

    let hex = this.arrayBufferToHexString(pem)
    opt.data = hex

    if (opt.data.includes(PBES2_OID) && opt.data.includes(PBKDF2_OID)) {
      opt.valid = true
    }

    opt.saltBegin = opt.data.indexOf(PBKDF2_OID) + 28

    if (opt.data.includes(AES256GCM_OID)) {
      opt.cipher = 'AES-GCM'
      opt.keyLength = 256
      opt.ivBegin = opt.data.indexOf(AES256GCM_OID) + 24
    } else if (opt.data.includes(AES192GCM_OID)) {
      opt.cipher = 'AES-GCM'
      opt.keyLength = 192
      opt.ivBegin = opt.data.indexOf(AES192GCM_OID) + 24
    } else if (opt.data.includes(AES128GCM_OID)) {
      opt.cipher = 'AES-GCM'
      opt.keyLength = 128
      opt.ivBegin = opt.data.indexOf(AES128GCM_OID) + 24
    } else if (opt.data.includes(AES256CBC_OID)) {
      opt.cipher = 'AES-CBC'
      opt.keyLength = 256
      opt.ivBegin = opt.data.indexOf(AES256CBC_OID) + 24
    } else if (opt.data.includes(AES192CBC_OID)) {
      opt.cipher = 'AES-CBC'
      opt.keyLength = 192
      opt.ivBegin = opt.data.indexOf(AES192CBC_OID) + 24
    } else if (opt.data.includes(AES128CBC_OID)) {
      opt.cipher = 'AES-CBC'
      opt.keyLength = 128
      opt.ivBegin = opt.data.indexOf(AES128CBC_OID) + 24
    } else if (opt.data.includes(AES256CFB_OID)) {
      opt.cipher = 'AES-CFB'
      opt.keyLength = 256
      opt.ivBegin = opt.data.indexOf(AES256CFB_OID) + 24
    } else if (opt.data.includes(AES192CFB_OID)) {
      opt.cipher = 'AES-CFB'
      opt.keyLength = 192
      opt.ivBegin = opt.data.indexOf(AES192CFB_OID) + 24
    } else if (opt.data.includes(AES128CFB_OID)) {
      opt.cipher = 'AES-CFB'
      opt.keyLength = 128
      opt.ivBegin = opt.data.indexOf(AES128CFB_OID) + 22
    }

    if (opt.data.includes(SHA512_OID)) {
      opt.hash = 'SHA-512'
    } else if (opt.data.includes(SHA384_OID)) {
      opt.hash = 'SHA-384'
    } else if (opt.data.includes(SHA256_OID)) {
      opt.hash = 'SHA-256'
    } else if (opt.data.includes(SHA1_OID)) {
      opt.hash = 'SHA-1'
    }

    opt.saltLength = parseInt(opt.data.substr(opt.saltBegin, 2), 16)
    opt.ivLength = parseInt(opt.data.substr(opt.ivBegin, 2), 16)

    opt.salt = opt.data.substr(opt.saltBegin + 2, opt.saltLength * 2)
    opt.iv = opt.data.substr(opt.ivBegin + 2, opt.ivLength * 2)

    opt.iterBegin = opt.saltBegin + 4 + (opt.saltLength * 2)
    opt.iterLength = parseInt(opt.data.substr(opt.iterBegin, 2), 16)
    opt.iter = parseInt(opt.data.substr(opt.iterBegin + 2, opt.iterLength * 2), 16)

    opt.sequencePadding = opt.data.substr(2, 2) === '81' ? 8 : 10
    opt.encryptedDataPadding = opt.data.substr(2, 2) === '81' ? 12 : 16
    opt.sequenceLength = parseInt(opt.data.substr(opt.sequencePadding, 2), 16)
    opt.encryptedDataBegin = opt.encryptedDataPadding + (opt.sequenceLength * 2)
    opt.encryptedDataLength = parseInt(opt.data.substr(opt.encryptedDataBegin, 6), 16)
    opt.encryptedData = opt.data.substr(opt.encryptedDataBegin + 4, (opt.encryptedDataLength * 2))

    let res = {
      salt: this.hexStringToArrayBuffer(opt.salt),
      iv: this.hexStringToArrayBuffer(opt.iv),
      cipher: opt.cipher,
      keyLength: opt.keyLength,
      hash: opt.hash,
      iter: opt.iter,
      encryptedData: this.hexStringToArrayBuffer(opt.encryptedData)
    }

    return res
  }

  /**
    *
    * Method for generating asymmetric RSA-OAEP key pair
    * - bits            {Integer}     default: "2048" 2048 bits key pair
    * - usage           {Array}       default: "['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']" contains all available options at default
    * - hash            {String}      default: "SHA-512" uses SHA-512 hash algorithm as default
    * - paddingScheme   {String}      default: "RSA-OAEP" uses RSA-OAEP padding scheme
    * - extractable     {Boolean}     default: "true" whether the key is extractable
    */
  getRSAKeyPair (bits, usage, hash, paddingScheme, extractable) {
    bits = (typeof bits !== 'undefined') ? bits : 2048
    usage = (typeof usage !== 'undefined') ? usage : ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    hash = (typeof hash !== 'undefined') ? hash : 'SHA-512'
    paddingScheme = (typeof paddingScheme !== 'undefined') ? paddingScheme : 'RSA-OAEP'
    extractable = (typeof extractable !== 'undefined') ? extractable : true

    return new Promise(function (resolve, reject) {
      if (typeof bits !== 'number') {
        throw new TypeError('Expected input of bits to be a Number')
      }

      if (typeof usage !== 'object') {
        throw new TypeError('Expected input of usage to be an Array')
      }

      if (typeof hash !== 'string') {
        throw new TypeError('Expected input of hash expected to be a String')
      }

      if (typeof paddingScheme !== 'string') {
        throw new TypeError('Expected input of paddingScheme to be a String')
      }

      if (typeof extractable !== 'boolean') {
        throw new TypeError('Expected input of extractable to be a Boolean')
      }

      cryptoApi.generateKey(
        {
          name: paddingScheme,
          modulusLength: bits,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: hash }
        },
        extractable,
        usage
      ).then(function (keyPair) {
        resolve(keyPair)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Method for generating asymmetric Elliptic Curve Diffie-Hellman key pair
    * - curve           {String}      default: "P-256" uses P-256 curve
    * - usage           {Array}       default: "['deriveKey', 'deriveBits']" contains all available options at default
    * - type            {String}      default: "ECDH" uses Elliptic Curve Diffie-Hellman
    * - extractable     {Boolean}     default: "true" whether the key is extractable
    */
  getECKeyPair (curve, usage, type, extractable) {
    curve = (typeof curve !== 'undefined') ? curve : 'P-256'
    usage = (typeof usage !== 'undefined') ? usage : ['deriveKey', 'deriveBits']
    type = (typeof type !== 'undefined') ? type : 'ECDH'
    extractable = (typeof extractable !== 'undefined') ? extractable : true

    return new Promise(function (resolve, reject) {
      if (typeof curve !== 'string') {
        throw new TypeError('Expected input of curve to be a String')
      }

      if (typeof usage !== 'object') {
        throw new TypeError('Expected input of usage to be an Array')
      }

      if (typeof type !== 'string') {
        throw new TypeError('Expected input of type to be a String')
      }

      if (typeof extractable !== 'boolean') {
        throw new TypeError('Expected input of extractable to be a Boolean')
      }

      cryptoApi.generateKey(
        {
          name: type,
          namedCurve: curve
        },
        extractable,
        usage
      ).then(function (keyPair) {
        resolve(keyPair)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Converts asymmetric private key from CryptoKey to PEM format
    * - privateKey    {CryptoKey}     default: "undefined" CryptoKey generated by WebCrypto API
    */
  cryptoPrivateToPem (privateKey) {
    let self = this
    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input to be a CryptoKey Object')
      }

      cryptoApi.exportKey(
        'pkcs8',
        privateKey
      ).then(function (exportedPrivateKey) {
        let b64 = self.arrayBufferToBase64(exportedPrivateKey)
        let pem = self.addNewLines(b64)
        pem = '-----BEGIN PRIVATE KEY-----\r\n' + pem + '-----END PRIVATE KEY-----'

        resolve(pem)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Converts asymmetric private key from PEM to CryptoKey format
    * - pem              {String}     default: "undefined" private key in PEM format
    * - isSignature      {Boolean}    default: "false"
    * - hash             {String}     default: "SHA-512"
    */
  pemPrivateToCrypto (pem, isSignature, hash) {
    let self = this
    isSignature = (typeof isSignature !== 'undefined') ? isSignature : false
    hash = (typeof hash !== 'undefined') ? hash : 'SHA-512'

    return new Promise(function (resolve, reject) {
      if (typeof pem !== 'string') {
        throw new TypeError('Expected input of PEM to be a String')
      }

      if (typeof isSignature !== 'boolean') {
        throw new TypeError('Expected input of isSingature to be a Boolean')
      }

      if (typeof hash !== 'string') {
        throw new TypeError('Expected input of hash to be a String')
      }

      pem = pem.replace('-----BEGIN PRIVATE KEY-----', '')
      let b64 = pem.replace('-----END PRIVATE KEY-----', '')
      b64 = self.removeLines(b64)
      let arrayBuffer = self.base64ToArrayBuffer(b64)
      let hex = self.arrayBufferToHexString(arrayBuffer)

      let opt = null
      let usages = null

      if (hex.includes(RSA_OID)) {
        if (isSignature) {
          opt = {
            name: 'RSA-PSS',
            hash: { name: hash }
          }
          
          usages = ['sign']
        } else {
          opt = {
            name: 'RSA-OAEP',
            hash: { name: hash }
          }

          usages = ['unwrapKey', 'decrypt']
        }
      } else if (hex.includes(EC_OID)) {
        let curve = null
        if (hex.includes(P256_OID)) {
          curve = 'P-256'
        } else if (hex.includes(P384_OID)) {
          curve = 'P-384'
        } else if (hex.includes(P521_OID)) {
          curve = 'P-521'
        }

        if (isSignature) {
          opt = {
            name: 'ECDSA',
            namedCurve: curve
          }

          usages = ['sign']
        } else {
          opt = {
            name: 'ECDH',
            namedCurve: curve
          }

          usages = ['deriveKey', 'deriveBits']
        }
      }

      cryptoApi.importKey(
        'pkcs8',
        arrayBuffer,
        opt,
        true,
        usages
      ).then(function (importedPrivateKey) {
        resolve(importedPrivateKey)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Converts asymmetric public key from CryptoKey to PEM format
    * - publicKey    {CryptoKey}    default: "undefined" CryptoKey generated by WebCrypto API
    */
  cryptoPublicToPem (publicKey) {
    let self = this
    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
        throw new TypeError('Expected input to be a CryptoKey Object')
      }

      cryptoApi.exportKey(
        'spki',
        publicKey
      ).then(function (exportedPublicKey) {
        let b64 = self.arrayBufferToBase64(exportedPublicKey)
        let pem = self.addNewLines(b64)
        pem = '-----BEGIN PUBLIC KEY-----\r\n' + pem + '-----END PUBLIC KEY-----'

        resolve(pem)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Converts asymmetric public key from PEM to CryptoKey
    * - publicKey       {String}      default: "undefined" PEM public key
    * - isSignature     {Boolean}     default: "false"
    * - hash            {String}      default: "SHA-512"
    */
  pemPublicToCrypto (pem, isSignature, hash) {
    let self = this
    isSignature = (typeof isSignature !== 'undefined') ? isSignature : false
    hash = (typeof hash !== 'undefined') ? hash : 'SHA-512'

    return new Promise(function (resolve, reject) {
      if (typeof pem !== 'string') {
        throw new TypeError('Expected input of PEM to be a String')
      }

      if (typeof isSignature !== 'boolean') {
        throw new TypeError('Expected input of isSingature to be a Boolean')
      }

      if (typeof hash !== 'string') {
        throw new TypeError('Expected input of hash to be a String')
      }

      pem = self.removeLines(pem)
      pem = pem.replace('-----BEGIN PUBLIC KEY-----', '')
      let b64 = pem.replace('-----END PUBLIC KEY-----', '')
      let arrayBuffer = self.base64ToArrayBuffer(b64)
      let hex = self.arrayBufferToHexString(arrayBuffer)

      let opt = null
      let usages = null

      if (hex.includes(RSA_OID)) {
        if (isSignature) {
          opt = {
            name: 'RSA-PSS',
            hash: { name: hash }
          }
          
          usages = ['verify']
        } else {
          opt = {
            name: 'RSA-OAEP',
            hash: { name: hash }
          }

          usages = ['wrapKey', 'encrypt']
        }
      } else if (hex.includes(EC_OID)) {
        let curve = null
        if (hex.includes(P256_OID)) {
          curve = 'P-256'
        } else if (hex.includes(P384_OID)) {
          curve = 'P-384'
        } else if (hex.includes(P521_OID)) {
          curve = 'P-521'
        }

        if (isSignature) {
          opt = {
            name: 'ECDSA',
            namedCurve: curve
          }

          usages = ['verify']
        } else {
          opt = {
            name: 'ECDH',
            namedCurve: curve
          }

          usages = []
        }
      }

      cryptoApi.importKey(
        'spki',
        arrayBuffer,
        opt,
        true,
        usages
      ).then(function (importedKey) {
        resolve(importedKey)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Encrypts asymmetric private key based on passphrase to enable storage in unsecure environment
    * - privateKey        {CryptoKey}     default: "undefined" private key in CryptoKey format
    * - passphrase        {String}        default: "undefined" any passphrase string
    * - iterations        {Number}        default: "300000"
    * - hash              {String}        default: "SHA-512"
    * - cipher            {String}        default: "AES-CBC"
    * - keyLength         {Number}        default: "256"
    */
  encryptPrivateKey (privateKey, passphrase, iterations, hash, cipher, keyLength) {
    iterations = (typeof iterations !== 'undefined') ? iterations : 64000
    hash = (typeof hash !== 'undefined') ? hash : 'SHA-512'
    cipher = (typeof cipher !== 'undefined') ? cipher : 'AES-CBC'
    keyLength = (typeof keyLength !== 'undefined') ? keyLength : 256
    let self = this

    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey Object')
      }

      if (typeof passphrase !== 'string') {
        throw new TypeError('Expected input of passphrase to be a String')
      }

      if (typeof iterations !== 'number') {
        throw new TypeError('Expected input of iterations to be a Number')
      }

      if (typeof hash !== 'string') {
        throw new TypeError('Expected input of hash to be a String')
      }

      if (typeof cipher !== 'string') {
        throw new TypeError('Expected input of cipher to be a String')
      }

      if (typeof keyLength !== 'number') {
        throw new TypeError('Expected input of keyLength to be a Number')
      }

      let ivLength = null
      if (cipher === 'AES-GCM') {
        ivLength = 12
      } else if (cipher === 'AES-CBC') {
        ivLength = 16
      } else if (cipher === 'AES-CFB') {
        ivLength = 16
      }

      let salt = cryptoLib.getRandomValues(new Uint8Array(16))
      let iv = cryptoLib.getRandomValues(new Uint8Array(ivLength))

      cryptoApi.importKey(
        'raw',
        self.stringToArrayBuffer(passphrase),
        {
          name: 'PBKDF2'
        },
        false,
        ['deriveKey']
      ).then(function (baseKey) {
        cryptoApi.deriveKey(
          {
            name: 'PBKDF2',
            salt: salt,
            iterations: iterations,
            hash: hash
          },
          baseKey,
          {
            name: cipher,
            length: keyLength
          },
          true,
          ['wrapKey']
        ).then(function (derivedKey) {
          cryptoApi.wrapKey(
            'pkcs8',
            privateKey,
            derivedKey,
            {
              name: cipher,
              iv: iv
            }
          ).then(function (wrappedKey) {
            let pemKey = self.toAsn1(wrappedKey, salt, iv, iterations, hash, cipher, keyLength)
            resolve(pemKey)
          }).catch(function (err) {
            reject(err)
          })
        }).catch(function (err) {
          reject(err)
        })
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Decrypts asymmetric private key by passphrase
    * - encryptedPrivateKey     {base64}     default: "undefined" private key in PKCS #8 format
    * - passphrase              {String}     default: "undefined" any passphrase string
    * - options                 {Object}     default: "{ name: 'RSA-OAEP', hash: { name: epki.hash } }"
    */
  decryptPrivateKey (encryptedPrivateKey, passphrase, options, usage) {
    let epki = this.fromAsn1(encryptedPrivateKey)
    options = (typeof options !== 'undefined') ? options : { name: 'RSA-OAEP', hash: { name: 'SHA-512' } }
    usage = (typeof usage !== 'undefined') ? usage : ['decrypt', 'unwrapKey']
    let self = this

    return new Promise(function (resolve, reject) {
      if (typeof encryptedPrivateKey !== 'string') {
        throw new TypeError('Expected input of encryptedPrivateKey to be a base64 String')
      }

      if (typeof passphrase !== 'string') {
        throw new TypeError('Expected input of passphrase to be a String')
      }

      if (typeof options !== 'object') {
        throw new TypeError('Expected input of options to be an Object')
      }

      if (typeof usage !== 'object') {
        throw new TypeError('Expected input of usage to be an Array')
      }

      cryptoApi.importKey(
        'raw',
        self.stringToArrayBuffer(passphrase),
        {
          name: 'PBKDF2'
        },
        false,
        ['deriveKey']
      ).then(function (baseKey) {
        cryptoApi.deriveKey(
          {
            name: 'PBKDF2',
            salt: epki.salt,
            iterations: epki.iter,
            hash: epki.hash
          },
          baseKey,
          {
            name: epki.cipher,
            length: epki.keyLength
          },
          true,
          ['unwrapKey']
        ).then(function (derivedKey) {
          cryptoApi.unwrapKey(
            'pkcs8',
            epki.encryptedData,
            derivedKey,
            {
              name: epki.cipher,
              iv: epki.iv
            },
            options,
            true,
            usage
          ).then(function (unwrappedKey) {
            resolve(unwrappedKey)
          }).catch(function (err) {
            reject(err)
          })
        }).catch(function (err) {
          reject(err)
        })
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Encrypts data using asymmetric encryption
    * Uses RSA-OAEP for asymmetric key as default.
    * - publicKey    {CryptoKey}      default: "undefined"
    * - data         {ArrayBuffer}    default: "undefined"
    */
  rsaEncrypt (publicKey, data) {
    let self = this
    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey of type public')
      }

      if (typeof data !== 'object') {
        throw new TypeError('Expected input of data to be an ArrayBuffer')
      }

      cryptoApi.encrypt(
        {
          name: 'RSA-OAEP'
        },
        publicKey,
        data
      ).then(function (encrypted) {
        resolve(self.arrayBufferToBase64(encrypted))
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Decrypts data using asymmetric encryption
    * Uses RSA-OAEP for asymmetric key as default.
    * - privateKey        {CryptoKey}     default: "undefined"
    * - encryptedData     {base64}        default: "undefined"
    */
  rsaDecrypt (privateKey, encryptedData) {
    let self = this
    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey of type private')
      }

      if (typeof encryptedData !== 'string') {
        throw new TypeError('Expected input of encryptedData to be a String')
      }

      cryptoApi.decrypt(
        {
          name: 'RSA-OAEP'
        },
        privateKey,
        self.base64ToArrayBuffer(encryptedData)
      ).then(function (decrypted) {
        resolve(self.arrayBufferToString(decrypted))
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Encrypts symmetric / shared key
    * Uses RSA-OAEP for asymmetric key as default.
    * - publicKey          {CryptoKey}    default: "undefined"
    * - sharedKey          {CryptoKey}    default: "undefined"
    * - publicKeyHash      {String}       default: "SHA-512"
    */
  encryptKey (publicKey, sharedKey, publicKeyHash) {
    publicKeyHash = (typeof publicKeyHash !== 'undefined') ? publicKeyHash : 'SHA-512'
    let self = this

    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
        throw new TypeError('Expected input of publicKey to be a CryptoKey of type public')
      }

      if (Object.prototype.toString.call(sharedKey) !== '[object CryptoKey]' && sharedKey.type !== 'secret') {
        throw new TypeError('Expected input of sharedKey to be a CryptoKey of type secret')
      }

      if (typeof publicKeyHash !== 'string') {
        throw new TypeError('Expected input of publicKeyHash to be a String')
      }

      cryptoApi.wrapKey(
        'raw',
        sharedKey,
        publicKey,
        {
          name: 'RSA-OAEP',
          hash: { name: publicKeyHash }
        }
      ).then(function (encryptedSharedKey) {
        resolve(self.arrayBufferToBase64(encryptedSharedKey))
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Decrypts symmetric / shared key
    * Uses RSA-OAEP for asymmetric key as default.
    * - privateKey              {CryptoKey}         default: "undefined"
    * - encryptedSharedKey      {base64 String}     default: "undefined"
    * - cipherSuite             {String}            default: "AES-GCM"
    * - keyLength               {Number}            default: "256"
    * - privateKeyLength        {Number}            default: "2048"
    * - privateKeyHash          {String}            default: "SHA-512"
    */
  decryptKey (privateKey, encryptedSharedKey, cipher, keyLength, privateKeyLength, privateKeyHash) {
    cipher = (typeof cipher !== 'undefined') ? cipher : 'AES-GCM'
    keyLength = (typeof keyLength !== 'undefined') ? keyLength : 256
    privateKeyLength = (typeof privateKeyLength !== 'undefined') ? privateKeyLength : 2048
    privateKeyHash = (typeof privateKeyHash !== 'undefined') ? privateKeyHash : 'SHA-512'
    let self = this

    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey of type private')
      }

      if (typeof encryptedSharedKey !== 'string') {
        throw new TypeError('Expected input of encryptedSharedKey to be a base64 String')
      }

      if (typeof cipher !== 'string') {
        throw new TypeError('Expected input of cipherSuite to be a String')
      }

      if (typeof keyLength !== 'number') {
        throw new TypeError('Expected input of keyLength to be a Number')
      }

      if (typeof privateKeyLength !== 'number') {
        throw new TypeError('Expected input of privateKeyLength to be a Number')
      }

      if (typeof privateKeyHash !== 'string') {
        throw new TypeError('Expected input of privateKeyHash to be a String')
      }

      cryptoApi.unwrapKey(
        'raw',
        self.base64ToArrayBuffer(encryptedSharedKey),
        privateKey,
        {
          name: 'RSA-OAEP',
          modulusLength: privateKeyLength,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: privateKeyHash }
        },
        {
          name: cipher,
          length: keyLength
        },
        true,
        ['encrypt', 'decrypt']
      ).then(function (decryptedKey) {
        resolve(decryptedKey)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Generates signature for data using RSA-PSS
    * - privateKey     {CryptoKey}      default: "undefined"
    * - data           {ArrayBuffer}    default: "undefined"
    */
  sign (privateKey, data) {
    let self = this

    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey Object')
      }

      if (typeof data !== 'object') {
        throw new TypeError('Expected input of data to be an ArrayBuffer')
      }

      cryptoApi.sign(
        {
          name: 'RSA-PSS',
          saltLength: 128
        },
        privateKey,
        data
      ).then(function (signature) {
        let b64Signature = self.arrayBufferToBase64(signature)
        resolve(b64Signature)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Verifies signature using RSA-PSS
    * - publicKey      {CryptoKey}       default: "undefined"
    * - signature      {base64}          default: "undefined"
    * - data           {ArrayBuffer}     default: "undefined"
    */
  verify (publicKey, signature, data) {
    let self = this

    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
        throw new TypeError('Expected input of publicKey to be a CryptoKey Object')
      }

      if (typeof signature !== 'string') {
        throw new TypeError('Expected input of signature to be a base64 String')
      }

      if (typeof data !== 'object') {
        throw new TypeError('Expected input of data to be an ArrayBuffer')
      }

      cryptoApi.verify(
        {
          name: 'RSA-PSS',
          saltLength: 128
        },
        publicKey,
        self.base64ToArrayBuffer(signature),
        data
      ).then(function (isValid) {
        resolve(isValid)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Generates symmetric / shared key for AES encryption
    * Uses Galois/Counter Mode (GCM) for operation by default.
    * - bits              {Integer}      default: "256" accepts 128 and 256
    * - usage             {Array}        default: "['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']" default contains all accepted values
    * - extractable       {Boolean}      default: "false" whether the key can be exported
    * - cipherMode        {String}       default: "AES-GCM" Cipher block mode operation
    */
  getSharedKey (bits, usage, extractable, cipher) {
    bits = (typeof bits !== 'undefined') ? bits : 256
    usage = (typeof usage !== 'undefined') ? usage : ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    extractable = (typeof extractable !== 'undefined') ? extractable : true
    cipher = (typeof cipher !== 'undefined') ? cipher : 'AES-GCM'

    return new Promise(function (resolve, reject) {
      if (typeof bits !== 'number') {
        throw new TypeError('Expected input of bits to be a Number')
      }

      if (typeof usage !== 'object') {
        throw new TypeError('Expected input of usage to be an Array')
      }

      if (typeof extractable !== 'boolean') {
        throw new TypeError('Expected input of extractable expected to be a Boolean')
      }

      if (typeof cipher !== 'string') {
        throw new TypeError('Expected input of cipherMode expected to be a String')
      }

      cryptoApi.generateKey(
        {
          name: cipher,
          length: bits
        },
        extractable,
        usage
      ).then(function (sessionKey) {
        resolve(sessionKey)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Encrypts data using symmetric / session key, converts them to
    * base64 format and prepends IV in front of the encrypted data.
    * Uses Galois/Counter Mode (GCM) for operation.
    * - sharedKey      {CryptoKey}      default: "undefined" symmetric / shared key
    * - data           {ArrayBuffer}    default: "undefined" any data to be encrypted
    */
  encrypt (sharedKey, data) {
    let self = this

    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(sharedKey) !== '[object CryptoKey]' && sharedKey.type !== 'secret') {
        throw new TypeError('Expected input of sharedKey to be a CryptoKey Object')
      }

      if (typeof data !== 'object') {
        throw new TypeError('Expected input of data to be an ArrayBuffer')
      }

      let ivAb = cryptoLib.getRandomValues(new Uint8Array(12))
      cryptoApi.encrypt(
        {
          name: 'AES-GCM',
          iv: ivAb,
          tagLength: 128
        },
        sharedKey,
        data
      ).then(function (encrypted) {
        let ivB64 = self.arrayBufferToBase64(ivAb)
        let encryptedB64 = self.arrayBufferToBase64(encrypted)
        resolve(ivB64 + encryptedB64)
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Decrypts data using symmetric / session key, extracts IV from
    * the front of the encrypted data and converts decrypted data
    * to base64. Uses Galois/Counter Mode (GCM) for operation.
    * - sharedKey           {CryptoKey}      default: "undefined" symmetric or session key
    * - encryptedData       {base64}         default: "undefined" any data to be decrypted
    */
  decrypt (sharedKey, encryptedData) {
    let self = this

    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(sharedKey) !== '[object CryptoKey]' && sharedKey.type !== 'secret') {
        throw new TypeError('Expected input of sharedKey to be a CryptoKey Object')
      }

      if (typeof encryptedData !== 'string') {
        throw new TypeError('Expected input of encryptedData to be a String')
      }

      let ivB64 = encryptedData.substring(0, 16)
      let encryptedB64 = encryptedData.substring(16)
      let ivAb = self.base64ToArrayBuffer(ivB64)
      let encryptedAb = self.base64ToArrayBuffer(encryptedB64)

      cryptoApi.decrypt(
        {
          name: 'AES-GCM',
          iv: ivAb,
          tagLength: 128
        },
        sharedKey,
        encryptedAb
      ).then(function (decrypted) {
        resolve(self.arrayBufferToBase64(decrypted))
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Method for generating symmetric AES 256 bit key derived from passphrase and salt
    * - passphrase        {String}      default: "undefined" any passphrase string
    * - salt              {String}      default: "undefined" any salt, may be unique user ID for example
    * - iterations        {Number}      default: "300000"    number of iterations is 300 000 (Recommended)
    * - hash              {String}      default: "SHA-512"   hash algorithm
    */
  keyFromPassphrase (passphrase, salt, iterations, hash) {
    iterations = (typeof iterations !== 'undefined') ? iterations : 64000
    hash = (typeof hash !== 'undefined') ? hash : 'SHA-512'
    let self = this

    return new Promise(function (resolve, reject) {
      if (typeof passphrase !== 'string') {
        throw new TypeError('Expected input of passphrase to be a String')
      }

      if (typeof salt !== 'string') {
        throw new TypeError('Expected input of salt to be a String')
      }

      if (typeof iterations !== 'number') {
        throw new TypeError('Expected input of iterations to be a Number')
      }

      if (typeof hash !== 'string') {
        throw new TypeError('Expected input of hash to be a String')
      }

      cryptoApi.importKey(
        'raw',
        self.stringToArrayBuffer(passphrase),
        {
          name: 'PBKDF2'
        },
        false,
        ['deriveKey']
      ).then(function (baseKey) {
        cryptoApi.deriveKey(
          {
            name: 'PBKDF2',
            salt: self.stringToArrayBuffer(salt),
            iterations: iterations,
            hash: hash
          },
          baseKey,
          {
            name: 'AES-GCM',
            length: 256
          },
          true,
          ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        ).then(function (derivedKey) {
          cryptoApi.exportKey(
            'raw',
            derivedKey
          ).then(function (exportedKey) {
            resolve(self.arrayBufferToHexString(exportedKey))
          }).catch(function (err) {
            reject(err)
          })
        }).catch(function (err) {
          reject(err)
        })
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Method for getting fingerprint of RSA public or private key
    * - key       {CryptoKey}     default: "undefined"
    * - hash      {String}        default: "SHA-1" can be used SHA-256, SHA-384 or SHA-512
    */
  cryptoKeyToFingerprint (key, hash) {
    hash = (typeof hash !== 'undefined') ? hash : 'SHA-1'
    let self = this

    return new Promise(function (resolve, reject) {
      if (Object.prototype.toString.call(key) !== '[object CryptoKey]') {
        throw new TypeError('Expected input of key to be a CryptoKey Object')
      }

      if (typeof hash !== 'string') {
        throw new TypeError('Expected input of hash to be a String')
      }

      let tmpKeyType = null
      if (key.type === 'public') {
        tmpKeyType = 'spki'
      } else {
        tmpKeyType = 'pkcs8'
      }

      cryptoApi.exportKey(
        tmpKeyType,
        key
      ).then(function (keyAb) {
        cryptoApi.digest(
          {
            name: hash
          },
          keyAb
        ).then(function (fingerprint) {
          resolve(self.arrayBufferToHexString(fingerprint).toUpperCase().replace(/(.{4})/g, '$1 ').trim())
        }).catch(function (err) {
          reject(err)
        })
      }).catch(function (err) {
        reject(err)
      })
    })
  }

  /**
    *
    * Method for getting random salt using cryptographically secure PRNG
    * - size    {number}    default: "16"
    */
  getRandomSalt (size) {
    size = (typeof size !== 'undefined') ? size : 16
    let self = this

    return new Promise(function (resolve, reject) {
      if (typeof size !== 'number') {
        throw new TypeError('Expected input of size to be a Number')
      }

      let salt = cryptoLib.getRandomValues(new Uint8Array(size))
      let hexSalt = self.arrayBufferToHexString(salt)

      resolve(hexSalt)
    })
  }
}
