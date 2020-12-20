/**
 *
 * Copyright (c) 2016 SafeBash
 * Cryptography consultant: Andrew Kozlik, Ph.D.
 *
 */

/**
 * MIT License
 *
 * Copyright (c) 2016 SafeBash
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
    const bytes = new Uint8Array(arrayBuffer)
    const len = bytes.length
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
    const len = base64.length
    let bufferLength = base64.length * 0.75
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

    const arrayBuffer = new ArrayBuffer(bufferLength)
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
   * Method for encoding ArrayBuffer into UTF-8 String
   */
  arrayBufferToString (arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
      throw new TypeError('Expected input of arrayBuffer to be an ArrayBuffer Object')
    }

    const decoder = new TextDecoder('utf-8')
    return decoder.decode(arrayBuffer)
  }

  /**
   * Method for decoding String to ArrayBuffer
   */
  stringToArrayBuffer (str) {
    if (typeof str !== 'string') {
      throw new TypeError('Expected input of str to be a String')
    }

    const encoder = new TextEncoder('utf-8')
    const byteArray = encoder.encode(str)
    return byteArray.buffer
  }

  /**
   * Method for encoding ArrayBuffer to hexadecimal String
   */
  arrayBufferToHexString (arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
      throw new TypeError('Expected input of arrayBuffer to be an ArrayBuffer Object')
    }

    const byteArray = new Uint8Array(arrayBuffer)
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

  /**
   * Method for decoding hexadecimal String to ArrayBuffer
   */
  hexStringToArrayBuffer (hexString) {
    if (typeof hexString !== 'string') {
      throw new TypeError('Expected input of hexString to be a String')
    }

    if ((hexString.length % 2) !== 0) {
      throw new RangeError('Expected string to be an even number of characters')
    }

    const byteArray = new Uint8Array(hexString.length / 2)
    for (let i = 0; i < hexString.length; i += 2) {
      byteArray[i / 2] = parseInt(hexString.substring(i, i + 2), 16)
    }

    return byteArray.buffer
  }

  /**
   * Method for encoding ArrayBuffer to base64 String
   */
  arrayBufferToBase64 (arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
      throw new TypeError('Expected input of arrayBuffer to be an ArrayBuffer Object')
    }

    return this.encodeAb(arrayBuffer)
  }

  /**
   * Method for decoding base64 String to ArrayBuffer
   */
  base64ToArrayBuffer (b64) {
    if (typeof b64 !== 'string') {
      throw new TypeError('Expected input of b64 to be a Base64 String')
    }

    return this.decodeAb(b64)
  }

  /**
   * Method for encoding decimal Number to hexadecimal String
   */
  decimalToHex (d, unsigned) {
    unsigned = (typeof unsigned !== 'undefined') ? unsigned : false

    if (typeof unsigned !== 'boolean') {
      throw new TypeError('Expected input of unsigned to be a Boolean')
    }

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
    } else {
      throw new TypeError('Expected input of d to be a Number or String')
    }
  }

  /**
   * Method for addition of new lines into PEM encoded key
   */
  addNewLines (str) {
    let finalString = ''
    while (str.length > 0) {
      finalString += str.substring(0, 64) + '\r\n'
      str = str.substring(64)
    }

    return finalString
  }

  /**
   * Method that removes lines from PEM encoded key
   */
  removeLines (str) {
    return str.replace(/\r?\n|\r/g, '')
  }

  /**
   * Method that encodes ASN.1 information into PEM encoded key
   */
  toAsn1 (wrappedKey, salt, iv, iterations, hash, cipher, length) {
    wrappedKey = this.arrayBufferToHexString(wrappedKey)
    salt = this.arrayBufferToHexString(salt)
    iv = this.arrayBufferToHexString(iv)
    iterations = this.decimalToHex(iterations, true)

    const opt = {}

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
        if (length === 256) {
          opt.CIPHER_OID = AES256GCM_OID
        } else if (length === 192) {
          opt.CIPHER_OID = AES192GCM_OID
        } else if (length === 128) {
          opt.CIPHER_OID = AES128GCM_OID
        }
        break
      case 'AES-CBC' :
        if (length === 256) {
          opt.CIPHER_OID = AES256CBC_OID
        } else if (length === 192) {
          opt.CIPHER_OID = AES192CBC_OID
        } else if (length === 128) {
          opt.CIPHER_OID = AES128CBC_OID
        }
        break
      case 'AES-CFB' :
        if (length === 256) {
          opt.CIPHER_OID = AES256CFB_OID
        } else if (length === 192) {
          opt.CIPHER_OID = AES192CFB_OID
        } else if (length === 128) {
          opt.CIPHER_OID = AES128CFB_OID
        }
    }

    const ITER_INTEGER = '02' + this.decimalToHex(iterations.length / 2) + iterations
    const SALT_OCTET = '04' + this.decimalToHex(salt) + salt
    const IV_OCTET = '04' + this.decimalToHex(iv) + iv
    const KEY_OCTET_PADDING = this.decimalToHex(wrappedKey).length / 2 === 2 ? '82' : '81'
    const KEY_OCTET = '04' + KEY_OCTET_PADDING + this.decimalToHex(wrappedKey) + wrappedKey

    opt.SEQUENCE_AES_CONTAINER = '30' + this.decimalToHex(opt.CIPHER_OID + IV_OCTET)
    opt.SEQUENCE_HASH_CONTAINER = '30' + this.decimalToHex(opt.HASH_OID)
    opt.SEQUENCE_PBKDF2_INNER_CONTAINER = '30' + this.decimalToHex(SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID)
    opt.SEQUENCE_PBKDF2_CONTAINER = '30' + this.decimalToHex(PBKDF2_OID + opt.SEQUENCE_PBKDF2_INNER_CONTAINER + SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID)
    opt.SEQUENCE_PBES2_INNER_CONTAINER = '30' + this.decimalToHex(opt.SEQUENCE_PBKDF2_CONTAINER + PBKDF2_OID + opt.SEQUENCE_PBKDF2_INNER_CONTAINER + SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID + opt.SEQUENCE_AES_CONTAINER + opt.CIPHER_OID + IV_OCTET)
    opt.SEQUENCE_PBES2_CONTAINER = '30' + this.decimalToHex(PBES2_OID + opt.SEQUENCE_PBES2_INNER_CONTAINER + opt.SEQUENCE_PBKDF2_CONTAINER + PBKDF2_OID + opt.SEQUENCE_PBKDF2_INNER_CONTAINER + SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID + opt.SEQUENCE_AES_CONTAINER + opt.CIPHER_OID + IV_OCTET)

    const SEQUENCE_PARAMETERS = opt.SEQUENCE_PBES2_CONTAINER + PBES2_OID + opt.SEQUENCE_PBES2_INNER_CONTAINER + opt.SEQUENCE_PBKDF2_CONTAINER + PBKDF2_OID + opt.SEQUENCE_PBKDF2_INNER_CONTAINER + SALT_OCTET + ITER_INTEGER + opt.SEQUENCE_HASH_CONTAINER + opt.HASH_OID + opt.SEQUENCE_AES_CONTAINER + opt.CIPHER_OID + IV_OCTET
    const SEQUENCE_LENGTH = this.decimalToHex(SEQUENCE_PARAMETERS + KEY_OCTET)
    const SEQUENCE_PADDING = SEQUENCE_LENGTH.length / 2 === 2 ? '82' : '81'
    const SEQUENCE = '30' + SEQUENCE_PADDING + SEQUENCE_LENGTH + SEQUENCE_PARAMETERS + KEY_OCTET

    const asnKey = this.hexStringToArrayBuffer(SEQUENCE)
    let pemKey = this.arrayBufferToBase64(asnKey)
    pemKey = this.addNewLines(pemKey)
    pemKey = '-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n' + pemKey + '-----END ENCRYPTED PRIVATE KEY-----'

    return pemKey
  }

  /**
   * Method that retrieves ASN.1 encoded information from PEM encoded key
   */
  fromAsn1 (pem) {
    pem = this.removeLines(pem)
    pem = pem.replace('-----BEGIN ENCRYPTED PRIVATE KEY-----', '')
    pem = pem.replace('-----END ENCRYPTED PRIVATE KEY-----', '')
    pem = this.base64ToArrayBuffer(pem)

    const opt = {}
    const hex = this.arrayBufferToHexString(pem)
    opt.data = hex

    if (opt.data.includes(PBES2_OID) && opt.data.includes(PBKDF2_OID)) {
      opt.valid = true
    }

    opt.saltBegin = opt.data.indexOf(PBKDF2_OID) + 28

    if (opt.data.includes(AES256GCM_OID)) {
      opt.cipher = 'AES-GCM'
      opt.length = 256
      opt.ivBegin = opt.data.indexOf(AES256GCM_OID) + 24
    } else if (opt.data.includes(AES192GCM_OID)) {
      opt.cipher = 'AES-GCM'
      opt.length = 192
      opt.ivBegin = opt.data.indexOf(AES192GCM_OID) + 24
    } else if (opt.data.includes(AES128GCM_OID)) {
      opt.cipher = 'AES-GCM'
      opt.length = 128
      opt.ivBegin = opt.data.indexOf(AES128GCM_OID) + 24
    } else if (opt.data.includes(AES256CBC_OID)) {
      opt.cipher = 'AES-CBC'
      opt.length = 256
      opt.ivBegin = opt.data.indexOf(AES256CBC_OID) + 24
    } else if (opt.data.includes(AES192CBC_OID)) {
      opt.cipher = 'AES-CBC'
      opt.length = 192
      opt.ivBegin = opt.data.indexOf(AES192CBC_OID) + 24
    } else if (opt.data.includes(AES128CBC_OID)) {
      opt.cipher = 'AES-CBC'
      opt.length = 128
      opt.ivBegin = opt.data.indexOf(AES128CBC_OID) + 24
    } else if (opt.data.includes(AES256CFB_OID)) {
      opt.cipher = 'AES-CFB'
      opt.length = 256
      opt.ivBegin = opt.data.indexOf(AES256CFB_OID) + 24
    } else if (opt.data.includes(AES192CFB_OID)) {
      opt.cipher = 'AES-CFB'
      opt.length = 192
      opt.ivBegin = opt.data.indexOf(AES192CFB_OID) + 24
    } else if (opt.data.includes(AES128CFB_OID)) {
      opt.cipher = 'AES-CFB'
      opt.length = 128
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
    opt.parametersPadding = opt.data.substr(2, 2) === '81' ? 12 : 16
    opt.sequenceLength = parseInt(opt.data.substr(opt.sequencePadding, 2), 16)
    opt.encryptedDataBegin = opt.parametersPadding + (opt.sequenceLength * 2)
    opt.encryptedDataPadding = opt.data.substr(opt.encryptedDataBegin - 2, 2) === '81' ? 2 : 4
    opt.encryptedDataLength = parseInt(opt.data.substr(opt.encryptedDataBegin, 6), 16)
    opt.encryptedData = opt.data.substr(opt.encryptedDataBegin + opt.encryptedDataPadding, (opt.encryptedDataLength * 2))

    const res = {
      salt: this.hexStringToArrayBuffer(opt.salt),
      iv: this.hexStringToArrayBuffer(opt.iv),
      cipher: opt.cipher,
      length: opt.length,
      hash: opt.hash,
      iter: opt.iter,
      encryptedData: this.hexStringToArrayBuffer(opt.encryptedData)
    }

    return res
  }

  /**
   * Method that converts asymmetric private key from CryptoKey to PEM format
   * @param {CryptoKey} privateKey default: "undefined"
   */
  cryptoPrivateToPem (privateKey) {
    const self = this

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input to be a CryptoKey Object')
      }

      cryptoApi.exportKey(
        'pkcs8',
        privateKey
      ).then(exportedPrivateKey => {
        const b64 = self.arrayBufferToBase64(exportedPrivateKey)
        let pem = self.addNewLines(b64)
        pem = '-----BEGIN PRIVATE KEY-----\r\n' + pem + '-----END PRIVATE KEY-----'

        resolve(pem)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that converts asymmetric private key from PEM to CryptoKey format
   * @param {String} pem default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDH: { name: 'ECDH', usages: ['deriveKey', 'deriveBits'], isExtractable: true }
   * -- ECDSA: { name: 'ECDSA', usages: ['sign'], isExtractable: true }
   * -- RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['decrypt', 'unwrapKey'], isExtractable: true }
   * -- RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['sign'], isExtractable: true }
   */
  pemPrivateToCrypto (pem, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    options.isExtractable = (typeof options.isExtractable !== 'undefined') ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (typeof pem !== 'string') {
        throw new TypeError('Expected input of pem to be a String')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable to be a Boolean')
      }

      pem = pem.replace('-----BEGIN PRIVATE KEY-----', '')
      pem = pem.replace('-----END PRIVATE KEY-----', '')

      const b64 = self.removeLines(pem)
      const arrayBuffer = self.base64ToArrayBuffer(b64)
      const hex = self.arrayBufferToHexString(arrayBuffer)
      const keyOptions = {}

      if (hex.includes(EC_OID)) {
        options.name = (typeof options.name !== 'undefined') ? options.name : 'ECDH'

        if (typeof options.name !== 'string') {
          throw new TypeError('Expected input of options.name to be a String')
        }

        let curve = null
        if (hex.includes(P256_OID)) {
          curve = 'P-256'
        } else if (hex.includes(P384_OID)) {
          curve = 'P-384'
        } else if (hex.includes(P521_OID)) {
          curve = 'P-521'
        }

        if (options.name === 'ECDH') {
          options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['deriveKey', 'deriveBits']
        } else if (options.name === 'ECDSA') {
          options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['sign']
        } else {
          throw new TypeError('Expected input of options.name is not a valid algorithm name')
        }

        if (typeof options.usages !== 'object') {
          throw new TypeError('Expected input of options.usages to be an Array')
        }

        keyOptions.name = options.name
        keyOptions.namedCurve = curve
      } else if (hex.includes(RSA_OID)) {
        options.name = (typeof options.name !== 'undefined') ? options.name : 'RSA-OAEP'
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'

        if (typeof options.name !== 'string') {
          throw new TypeError('Expected input of options.name to be a String')
        }

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        if (options.name === 'RSA-OAEP') {
          options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['decrypt', 'unwrapKey']
        } else if (options.name === 'RSA-PSS') {
          options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['sign']
        } else {
          throw new TypeError('Expected input of options.name is not a valid algorithm name')
        }

        if (typeof options.usages !== 'object') {
          throw new TypeError('Expected input of options.usages to be an Array')
        }

        keyOptions.name = options.name
        keyOptions.hash = {}
        keyOptions.hash.name = options.hash
      } else {
        throw new TypeError('Expected input of pem is not a valid private key')
      }

      cryptoApi.importKey(
        'pkcs8',
        arrayBuffer,
        keyOptions,
        options.isExtractable,
        options.usages
      ).then(importedPrivateKey => {
        resolve(importedPrivateKey)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that converts asymmetric public key from CryptoKey to PEM format
   * @param {CryptoKey} publicKey default: "undefined"
   */
  cryptoPublicToPem (publicKey) {
    const self = this

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
        throw new TypeError('Expected input of publicKey to be a CryptoKey Object of type public')
      }

      cryptoApi.exportKey(
        'spki',
        publicKey
      ).then(exportedPublicKey => {
        const b64 = self.arrayBufferToBase64(exportedPublicKey)
        let pem = self.addNewLines(b64)
        pem = '-----BEGIN PUBLIC KEY-----\r\n' + pem + '-----END PUBLIC KEY-----'

        resolve(pem)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that converts asymmetric public key from PEM to CryptoKey format
   * @param {String} publicKey default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDH: { name: 'ECDH', usages: [], isExtractable: true }
   * -- ECDSA: { name: 'ECDSA', usages: ['verify'], isExtractable: true }
   * -- RSA-OAEP: { name: 'RSA-OAEP', hash: { name: 'SHA-512' }, usages: ['encrypt', 'wrapKey'], isExtractable: true }
   * -- RSA-PSS: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, usages: ['verify'], isExtractable: true }
   */
  pemPublicToCrypto (pem, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    options.isExtractable = (typeof options.isExtractable !== 'undefined') ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (typeof pem !== 'string') {
        throw new TypeError('Expected input of pem to be a String')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable to be a Boolean')
      }

      pem = pem.replace('-----BEGIN PUBLIC KEY-----', '')
      pem = pem.replace('-----END PUBLIC KEY-----', '')

      const b64 = self.removeLines(pem)
      const arrayBuffer = self.base64ToArrayBuffer(b64)
      const hex = self.arrayBufferToHexString(arrayBuffer)
      const keyOptions = {}

      if (hex.includes(EC_OID)) {
        options.name = (typeof options.name !== 'undefined') ? options.name : 'ECDH'

        if (typeof options.name !== 'string') {
          throw new TypeError('Expected input of options.name to be a String')
        }

        let curve = null
        if (hex.includes(P256_OID)) {
          curve = 'P-256'
        } else if (hex.includes(P384_OID)) {
          curve = 'P-384'
        } else if (hex.includes(P521_OID)) {
          curve = 'P-521'
        }

        if (options.name === 'ECDH') {
          options.usages = (typeof options.usages !== 'undefined') ? options.usages : []
        } else if (options.name === 'ECDSA') {
          options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['verify']
        } else {
          throw new TypeError('Expected input of options.name is not a valid algorithm name')
        }

        if (typeof options.usages !== 'object') {
          throw new TypeError('Expected input of options.usages to be an Array')
        }

        keyOptions.name = options.name
        keyOptions.namedCurve = curve
      } else if (hex.includes(RSA_OID)) {
        options.name = (typeof options.name !== 'undefined') ? options.name : 'RSA-OAEP'
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'

        if (typeof options.name !== 'string') {
          throw new TypeError('Expected input of options.name to be a String')
        }

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        if (options.name === 'RSA-OAEP') {
          options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['encrypt', 'wrapKey']
        } else if (options.name === 'RSA-PSS') {
          options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['verify']
        } else {
          throw new TypeError('Expected input of options.name is not a valid algorithm name')
        }

        if (typeof options.usages !== 'object') {
          throw new TypeError('Expected input of options.usages to be an Array')
        }

        keyOptions.name = options.name
        keyOptions.hash = {}
        keyOptions.hash.name = options.hash
      } else {
        throw new TypeError('Expected input of pem is not a valid public key')
      }

      cryptoApi.importKey(
        'spki',
        arrayBuffer,
        keyOptions,
        options.isExtractable,
        options.usages
      ).then(importedPublicKey => {
        resolve(importedPublicKey)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that converts CryptoKey to base64
   * @param {CryptoKey} key default: "undefined"
   * @param {String} type default: "secret: 'raw'; private: 'pkcs8'; public: 'spki'"
   */
  cryptoToBase64 (key, type) {
    const self = this

    let keyType = null
    switch (key.type) {
      case 'secret' :
        keyType = 'raw'
        break
      case 'private' :
        keyType = 'pkcs8'
        break
      case 'public' :
        keyType = 'spki'
    }

    type = (typeof type !== 'undefined') ? type : keyType

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(key) !== '[object CryptoKey]') {
        throw new TypeError('Expected input of key to be a CryptoKey Object')
      }

      if (typeof type !== 'string') {
        throw new TypeError('Expected input of type to be a String')
      }

      cryptoApi.exportKey(
        keyType,
        key
      ).then(exportedKey => {
        const b64Key = self.arrayBufferToBase64(exportedKey)
        resolve(b64Key)
      }).catch(err => {
        reject(err)
      })
    })
  }

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
  base64ToCrypto (key, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    options.name = (typeof options.name !== 'undefined') ? options.name : 'AES-GCM'
    options.isExtractable = (typeof options.isExtractable !== 'undefined' ) ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (typeof key !== 'string') {
        throw new TypeError('Expected input of key to be a Base64 String')
      }

      if (typeof options.name !== 'string') {
        throw new TypeError('Expected input of options.name to be a String')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable to be a Boolean')
      }

      const keyOptions = {}
      keyOptions.name = options.name

      if (options.name === 'AES-GCM' || options.name === 'AES-CBC') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'raw'
        options.length = (typeof options.length !== 'undefined') ? options.length : 256
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']

        if (typeof options.length !== 'number') {
          throw new TypeError('Expected input of options.length to be a Number')
        }
      } else if (options.name === 'ECDH') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'pkcs8'
        options.namedCurve = (typeof options.namedCurve !== 'undefined') ? options.namedCurve : 'P-256'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['deriveKey', 'deriveBits']

        if (typeof options.namedCurve !== 'string') {
          throw new TypeError('Expected input of options.namedCurve to be a String')
        }

        keyOptions.namedCurve = options.namedCurve
      } else if (options.name === 'ECDSA') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'pkcs8'
        options.namedCurve = (typeof options.namedCurve !== 'undefined') ? options.namedCurve : 'P-256'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['sign']

        if (typeof options.namedCurve !== 'string') {
          throw new TypeError('Expected input of options.namedCurve to be a String')
        }

        keyOptions.namedCurve = options.namedCurve
      } else if (options.name === 'RSA-OAEP') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'pkcs8'
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['decrypt', 'unwrapKey']

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        keyOptions.hash = {}
        keyOptions.hash.name = options.hash
      } else if (options.name === 'RSA-PSS') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'pkcs8'
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['sign']

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        keyOptions.hash = {}
        keyOptions.hash.name = options.hash
      } else {
        throw new TypeError('Expected input of options.name is not a valid algorithm name')
      }

      if (typeof options.type !== 'string') {
        throw new TypeError('Expected input of options.type to be a String')
      }

      if (typeof options.usages !== 'object') {
        throw new TypeError('Expected input of options.usages to be an Array')
      }

      const abKey = self.base64ToArrayBuffer(key)

      cryptoApi.importKey(
        options.type,
        abKey,
        keyOptions,
        options.isExtractable,
        options.usages
      ).then(importedKey => {
        resolve(importedKey)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that generates asymmetric RSA-OAEP key pair
   * @param {Integer} modulusLength default: "2048"
   * @param {String} hash default: "SHA-512"
   * @param {String} paddingScheme default: "RSA-OAEP"
   * @param {Array} usages default: "['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']"
   * @param {Boolean} isExtractable default: "true"
   */
  getRSAKeyPair (modulusLength, hash, paddingScheme, usages, isExtractable) {
    modulusLength = (typeof modulusLength !== 'undefined') ? modulusLength : 2048
    hash = (typeof hash !== 'undefined') ? hash : 'SHA-512'
    paddingScheme = (typeof paddingScheme !== 'undefined') ? paddingScheme : 'RSA-OAEP'
    isExtractable = (typeof isExtractable !== 'undefined') ? isExtractable : true

    return new Promise((resolve, reject) => {
      if (typeof modulusLength !== 'number') {
        throw new TypeError('Expected input of modulusLength to be a Number')
      }

      if (typeof hash !== 'string') {
        throw new TypeError('Expected input of hash expected to be a String')
      }

      if (typeof paddingScheme !== 'string') {
        throw new TypeError('Expected input of paddingScheme to be a String')
      }

      if (typeof isExtractable !== 'boolean') {
        throw new TypeError('Expected input of isExtractable to be a Boolean')
      }

      if (paddingScheme === 'RSA-OAEP') {
        usages = (typeof usages !== 'undefined') ? usages : ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
      } else if (paddingScheme === 'RSA-PSS') {
        usages = (typeof usages !== 'undefined') ? usages : ['sign', 'verify']
      } else {
        throw new TypeError('Expected input of paddingScheme is not a valid padding scheme')
      }

      if (typeof usages !== 'object') {
        throw new TypeError('Expected input of usages to be an Array')
      }

      cryptoApi.generateKey(
        {
          name: paddingScheme,
          modulusLength: modulusLength,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: hash }
        },
        isExtractable,
        usages
      ).then(keyPair => {
        resolve(keyPair)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that encrypts data using asymmetric encryption
   * @param {CryptoKey} publicKey default: "undefined"
   * @param {ArrayBuffer} data default: "undefined"
   */
  rsaEncrypt (publicKey, data) {
    const self = this

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
        throw new TypeError('Expected input of publicKey to be a CryptoKey Object of type public')
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
      ).then(encryptedDataAb => {
        const encryptedDataB64 = self.arrayBufferToBase64(encryptedDataAb)
        resolve(encryptedDataB64)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that decrypts data using asymmetric encryption
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {String} encryptedData default: "undefined"
   */
  rsaDecrypt (privateKey, encryptedData) {
    const self = this

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey Object of type private')
      }

      if (typeof encryptedData !== 'string') {
        throw new TypeError('Expected input of encryptedData to be a Base64 String')
      }

      const encryptedDataAb = self.base64ToArrayBuffer(encryptedData)

      cryptoApi.decrypt(
        {
          name: 'RSA-OAEP'
        },
        privateKey,
        encryptedDataAb
      ).then(decryptedDataAb => {
        resolve(decryptedDataAb)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that generates asymmetric Elliptic Curve Diffie-Hellman key pair
   * @param {String} curve default: "P-256"
   * @param {String} type default: "ECDH"
   * @param {Array} usages default: "['deriveKey', 'deriveBits']"
   * @param {Boolean} isExtractable default: "true"
   */
  getECKeyPair (curve, type, usages, isExtractable) {
    curve = (typeof curve !== 'undefined') ? curve : 'P-256'
    type = (typeof type !== 'undefined') ? type : 'ECDH'
    isExtractable = (typeof isExtractable !== 'undefined') ? isExtractable : true

    return new Promise((resolve, reject) => {
      if (typeof curve !== 'string') {
        throw new TypeError('Expected input of curve to be a String')
      }

      if (typeof type !== 'string') {
        throw new TypeError('Expected input of type to be a String')
      }

      if (typeof isExtractable !== 'boolean') {
        throw new TypeError('Expected input of isExtractable to be a Boolean')
      }

      if (type === 'ECDH') {
        usages = (typeof usages !== 'undefined') ? usages : ['deriveKey', 'deriveBits']
      } else if (type === 'ECDSA') {
        usages = (typeof usages !== 'undefined') ? usages : ['sign', 'verify']
      } else {
        throw new TypeError('Expected input of type is not a valid algorithm type')
      }

      if (typeof usages !== 'object') {
        throw new TypeError('Expected input of usages to be an Array')
      }

      cryptoApi.generateKey(
        {
          name: type,
          namedCurve: curve
        },
        isExtractable,
        usages
      ).then(keyPair => {
        resolve(keyPair)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that retrieves public key from private key
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDH: { name: 'ECDH', usages: ['deriveKey', 'deriveBits'], isExtractable: true }
   * -- ECDSA: { name: 'ECDSA', usages: ['sign', 'verify'], isExtractable: true }
   * -- RSA-OAEP: { name: 'RSA-OAEP', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
   * -- RSA-PSS: { name: 'RSA-PSS', usages: ['sign', 'verify'], isExtractable: true }
   */
  getPublicKey (privateKey, options) {
    if (typeof options === 'undefined') {
      options = {}
    }

    options.isExtractable = (typeof options.isExtractable !== 'undefined') ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey must be a CryptoKey Object of type private')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable to be a Boolean')
      }

      cryptoApi.exportKey('jwk', privateKey).then(jwkKey => {
        const keyOptions = {}
        keyOptions.name = privateKey.algorithm.name

        switch (privateKey.algorithm.name) {
          case 'ECDH' :
            delete jwkKey.d
            jwkKey.key_ops = []

            options.usages = (typeof options.usages !== 'undefined') ? options.usages : []

            if (typeof options.usages !== 'object') {
              throw new TypeError('Expected input of options.usages to be an Array')
            }

            keyOptions.namedCurve = privateKey.algorithm.namedCurve
            break
          case 'ECDSA' :
            delete jwkKey.d
            jwkKey.key_ops = ['verify']

            options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['verify']

            if (typeof options.usages !== 'object') {
              throw new TypeError('Expected input of options.usages to be an Array')
            }

            keyOptions.namedCurve = privateKey.algorithm.namedCurve
            break
          case 'RSA-OAEP' :
            delete jwkKey.d
            delete jwkKey.dp
            delete jwkKey.dq
            delete jwkKey.p
            delete jwkKey.q
            delete jwkKey.qi
            jwkKey.key_ops = ['encrypt', 'wrapKey']

            options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['encrypt', 'wrapKey']

            if (typeof options.usages !== 'object') {
              throw new TypeError('Expected input of options.usages to be an Array')
            }

            keyOptions.hash = {}
            keyOptions.hash.name = privateKey.algorithm.hash.name
            break
          case 'RSA-PSS' :
            delete jwkKey.d
            delete jwkKey.dp
            delete jwkKey.dq
            delete jwkKey.p
            delete jwkKey.q
            delete jwkKey.qi
            jwkKey.key_ops = ['verify']

            options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['verify']

            if (typeof options.usages !== 'object') {
              throw new TypeError('Expected input of options.usages to be an Array')
            }

            keyOptions.hash = {}
            keyOptions.hash.name = privateKey.algorithm.hash.name
            break
          default :
            throw new TypeError('Expected input of privateKey is not a valid private key')
        }

        cryptoApi.importKey(
          'jwk',
          jwkKey,
          keyOptions,
          options.isExtractable,
          options.usages
        ).then(publicKey => {
          resolve(publicKey)
        }).catch(err => {
          reject(err)
        })
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that encrypts asymmetric private key using passphrase to enable storage in unsecure environment
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {String} passphrase default: "undefined"
   * @param {Number} iterations default: "64000"
   * @param {String} hash default: "SHA-512"
   * @param {String} cipher default: "AES-GCM"
   * @param {Number} length default: "256"
   */
  encryptPrivateKey (privateKey, passphrase, iterations, hash, cipher, length) {
    const self = this

    iterations = (typeof iterations !== 'undefined') ? iterations : 64000
    hash = (typeof hash !== 'undefined') ? hash : 'SHA-512'
    cipher = (typeof cipher !== 'undefined') ? cipher : 'AES-GCM'
    length = (typeof length !== 'undefined') ? length : 256

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey Object of type private')
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

      if (typeof length !== 'number') {
        throw new TypeError('Expected input of length to be a Number')
      }

      let ivLength = null
      switch (cipher) {
        case 'AES-GCM' :
          ivLength = 12
          break
        case 'AES-CBC' :
          ivLength = 16
          break
        case 'AES-CFB' :
          ivLength = 16
          break
      }

      const salt = cryptoLib.getRandomValues(new Uint8Array(16))
      const iv = cryptoLib.getRandomValues(new Uint8Array(ivLength))
      const passphraseAb = self.stringToArrayBuffer(passphrase)

      cryptoApi.importKey(
        'raw',
        passphraseAb,
        {
          name: 'PBKDF2'
        },
        false,
        ['deriveKey']
      ).then(baseKey => {
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
            length: length
          },
          false,
          ['wrapKey']
        ).then(derivedKey => {
          cryptoApi.wrapKey(
            'pkcs8',
            privateKey,
            derivedKey,
            {
              name: cipher,
              iv: iv,
              tagLength: 128
            }
          ).then(wrappedKey => {
            const pemKey = self.toAsn1(wrappedKey, salt, iv, iterations, hash, cipher, length)
            resolve(pemKey)
          }).catch(err => {
            reject(err)
          })
        }).catch(err => {
          reject(err)
        })
      }).catch(err => {
        reject(err)
      })
    })
  }

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
  decryptPrivateKey (encryptedPrivateKey, passphrase, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    options.name = (typeof options.name !== 'undefined') ? options.name : 'ECDH'
    options.isExtractable = (typeof options.isExtractable !== 'undefined' ) ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (typeof encryptedPrivateKey !== 'string') {
        throw new TypeError('Expected input of encryptedPrivateKey to be a Base64 String')
      }

      if (typeof passphrase !== 'string') {
        throw new TypeError('Expected input of passphrase to be a String')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable to be a Boolean')
      }

      const epki = this.fromAsn1(encryptedPrivateKey)
      const keyOptions = {}
      keyOptions.name = options.name
  
      if (options.name === 'ECDH') {
        options.namedCurve = (typeof options.namedCurve !== 'undefined') ? options.namedCurve : 'P-256'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['deriveKey', 'deriveBits']

        if (typeof options.namedCurve !== 'string') {
          throw new TypeError('Expected input of options.namedCurve to be a String')
        }

        if (typeof options.usages !== 'object') {
          throw new TypeError('Expected input of options.usages to be an Array')
        }

        keyOptions.namedCurve = options.namedCurve
      } else if (options.name === 'ECDSA') {
        options.namedCurve = (typeof options.namedCurve !== 'undefined') ? options.namedCurve : 'P-256'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['sign']

        if (typeof options.namedCurve !== 'string') {
          throw new TypeError('Expected input of options.namedCurve to be a String')
        }

        if (typeof options.usages !== 'object') {
          throw new TypeError('Expected input of options.usages to be an Array')
        }

        keyOptions.namedCurve = options.namedCurve
      } else if (options.name === 'RSA-OAEP') {
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['decrypt', 'unwrapKey']

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        if (typeof options.usages !== 'object') {
          throw new TypeError('Expected input of options.usages to be an Array')
        }

        keyOptions.hash = {}
        keyOptions.hash.name = options.hash
      } else if (options.name === 'RSA-PSS') {
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['sign']

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        if (typeof options.usages !== 'object') {
          throw new TypeError('Expected input of options.usages to be an Array')
        }

        keyOptions.hash = {}
        keyOptions.hash.name = options.hash
      } else {
        throw new TypeError('Expected input of encryptedPrivateKey is not a valid encrypted private key')
      }

      const passphraseAb = self.stringToArrayBuffer(passphrase)

      cryptoApi.importKey(
        'raw',
        passphraseAb,
        {
          name: 'PBKDF2'
        },
        false,
        ['deriveKey']
      ).then(baseKey => {
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
            length: epki.length
          },
          false,
          ['unwrapKey']
        ).then(derivedKey => {
          cryptoApi.unwrapKey(
            'pkcs8',
            epki.encryptedData,
            derivedKey,
            {
              name: epki.cipher,
              iv: epki.iv,
              tagLength: 128
            },
            keyOptions,
            options.isExtractable,
            options.usages
          ).then(unwrappedKey => {
            resolve(unwrappedKey)
          }).catch(err => {
            reject(err)
          })
        }).catch(err => {
          reject(err)
        })
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that performs ECDH key agreement
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {CryptoKey} publicKey default: "undefined"
   * @param {Object} options default: "{ bitLength: 256, hkdfHash: 'SHA-512', hkdfSalt: "new UInt8Array()", hkdfInfo: "new UInt8Array()", cipher: 'AES-GCM', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
   */
  keyAgreement (privateKey, publicKey, options) {
    if (typeof options === 'undefined') {
      options = {}
    }

    options.bitLength = (typeof options.bitLength !== 'undefined') ? options.bitLength : 256
    options.hkdfHash = (typeof options.hkdfHash !== 'undefined') ? options.hkdfHash : 'SHA-512'
    options.hkdfSalt = (typeof options.hkdfSalt !== 'undefined') ? options.hkdfSalt : new Uint8Array()
    options.hkdfInfo = (typeof options.hkdfInfo !== 'undefined') ? options.hkdfInfo : new Uint8Array()
    options.cipher = (typeof options.cipher !== 'undefined') ? options.cipher : 'AES-GCM'
    options.length = (typeof options.length !== 'undefined') ? options.length : 256
    options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['encrypt', 'decrypt', 'unwrapKey', 'wrapKey']
    options.isExtractable = (typeof options.isExtractable !== 'undefined') ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey Object of type private')
      }

      if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
        throw new TypeError('Expected input of publicKey to be a CryptoKey Object of type public')
      }

      if (typeof options.bitLength !== 'number') {
        throw new TypeError('Expected input of options.bitLength to be a Number')
      }

      if (typeof options.hkdfHash !== 'string') {
        throw new TypeError('Expected input of options.hkdfHash to be a String')
      }

      if (typeof options.hkdfSalt !== 'object') {
        throw new TypeError('Expected input of options.hkdfSalt to be an ArrayBuffer')
      }

      if (typeof options.hkdfInfo !== 'object') {
        throw new TypeError('Expected input of options.hkdfInfo to be an ArrayBuffer')
      }

      if (typeof options.cipher !== 'string') {
        throw new TypeError('Expected input of options.cipher to be a String')
      }

      if (typeof options.length !== 'number') {
        throw new TypeError('Expected input of options.length to be a Number')
      }

      if (typeof options.usages !== 'object') {
        throw new TypeError('Expected input of options.usages to be an Array')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable to be a Boolean')
      }

      cryptoApi.deriveBits(
        {
          name: 'ECDH',
          namedCurve: publicKey.algorithm.namedCurve,
          public: publicKey
        },
        privateKey,
        options.bitLength
      ).then(derivedBits => {
        cryptoApi.importKey(
          'raw',
          derivedBits,
          {
            name: 'HKDF'
          },
          false,
          ['deriveKey']
        ).then(derivedKey => {
          cryptoApi.deriveKey(
            {
              name: 'HKDF',
              hash: {
                name: options.hkdfHash
              },
              salt: options.hkdfSalt,
              info: options.hkdfInfo
            },
            derivedKey,
            {
              name: options.cipher,
              length: options.length
            },
            options.isExtractable,
            options.usages
          ).then(sharedKey => {
            resolve(sharedKey)
          }).catch(err => {
            reject(err)
          })
        }).catch(err => {
          reject(err)
        })
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that generates symmetric/shared key for AES encryption
   * @param {Integer} length default: "256"
   * @param {Object} options default: "{ cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
   */
  getSharedKey (length, options) {
    length = (typeof length !== 'undefined') ? length : 256

    if (typeof options === 'undefined') {
      options = {}
    }

    options.cipher = (typeof options.cipher !== 'undefined') ? options.cipher : 'AES-GCM'
    options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    options.isExtractable = (typeof options.isExtractable !== 'undefined') ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (typeof length !== 'number') {
        throw new TypeError('Expected input of length to be a Number')
      }

      if (typeof options.cipher !== 'string') {
        throw new TypeError('Expected input of options.cipher expected to be a String')
      }

      if (typeof options.usages !== 'object') {
        throw new TypeError('Expected input of options.usages to be an Array')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable expected to be a Boolean')
      }

      cryptoApi.generateKey(
        {
          name: options.cipher,
          length: length
        },
        options.isExtractable,
        options.usages
      ).then(sharedKey => {
        resolve(sharedKey)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that encrypts keys
   * @param {CryptoKey} wrappingKey default: "undefined"
   * @param {CryptoKey} key default: "undefined"
   */
  encryptKey (wrappingKey, key) {
    const self = this

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(wrappingKey) !== '[object CryptoKey]') {
        throw new TypeError('Expected input of wrappingKey to be a CryptoKey Object')
      }

      if (Object.prototype.toString.call(key) !== '[object CryptoKey]') {
        throw new TypeError('Expected input of key to be a CryptoKey Object')
      }

      let keyType = null
      switch (key.type) {
        case 'secret' :
          keyType = 'raw'
          break
        case 'private' :
          keyType = 'pkcs8'
          break
        case 'public' :
          keyType = 'spki'
      }

      if (wrappingKey.type === 'secret') {
        let ivAb = null

        if (wrappingKey.algorithm.name === 'AES-GCM') {
          ivAb = cryptoLib.getRandomValues(new Uint8Array(12))
        } else if (wrappingKey.algorithm.name === 'AES-CBC') {
          ivAb = cryptoLib.getRandomValues(new Uint8Array(16))
        } else {
          throw new TypeError('Cipher mode of the wrappingKey is not supported')
        }

        cryptoApi.wrapKey(
          keyType,
          key,
          wrappingKey,
          {
            name: wrappingKey.algorithm.name,
            iv: ivAb,
            tagLength: 128
          }
        ).then(wrappedKey => {
          const encryptedKey = self.arrayBufferToBase64(ivAb) + self.arrayBufferToBase64(wrappedKey)
          resolve(encryptedKey)
        }).catch(err => {
          reject(err)
        })
      } else if (wrappingKey.algorithm.name === 'RSA-OAEP') {
        if (wrappingKey.type !== 'public') {
          throw new TypeError('Expected input of wrappingKey to be a CryptoKey Object of type public')
        }

        cryptoApi.wrapKey(
          keyType,
          key,
          wrappingKey,
          {
            name: 'RSA-OAEP',
            hash: { name: wrappingKey.algorithm.hash.name }
          }
        ).then(wrappedKey => {
          const encryptedKey = self.arrayBufferToBase64(wrappedKey)
          resolve(encryptedKey)
        }).catch(err => {
          reject(err)
        })
      } else {
        throw new TypeError('Expected input of wrappingKey is not a supported key')
      }
    })
  }

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
  decryptKey (unwrappingKey, encryptedKey, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    options.name = (typeof options.name !== 'undefined') ? options.name : 'AES-GCM'
    options.isExtractable = (typeof options.isExtractable !== 'undefined') ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(unwrappingKey) !== '[object CryptoKey]') {
        throw new TypeError('Expected input of unwrappingKey to be a CryptoKey Object')
      }

      if (typeof encryptedKey !== 'string') {
        throw new TypeError('Expected input of encryptedKey to be a Base64 String')
      }

      if (typeof options.name !== 'string') {
        throw new TypeError('Expected input of options.name to be a String')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable to be a Boolean')
      }

      const keyOptions = {}
      keyOptions.name = options.name

      if (options.name === 'AES-GCM' || options.name === 'AES-CBC') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'raw'
        options.length = (typeof options.length !== 'undefined') ? options.length : 256
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']

        if (typeof options.length !== 'number') {
          throw new TypeError('Expected input of options.length to be a Number')
        }
      } else if (options.name === 'ECDH') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'pkcs8'
        options.namedCurve = (typeof options.namedCurve !== 'undefined') ? options.namedCurve : 'P-256'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['deriveKey', 'deriveBits']

        if (typeof options.namedCurve !== 'string') {
          throw new TypeError('Expected input of options.namedCurve to be a String')
        }

        keyOptions.namedCurve = options.namedCurve
      } else if (options.name === 'ECDSA') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'pkcs8'
        options.namedCurve = (typeof options.namedCurve !== 'undefined') ? options.namedCurve : 'P-256'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['sign']

        if (typeof options.namedCurve !== 'string') {
          throw new TypeError('Expected input of options.namedCurve to be a String')
        }

        keyOptions.namedCurve = options.namedCurve
      } else if (options.name === 'RSA-OAEP') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'pkcs8'
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['decrypt', 'unwrapKey']

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        keyOptions.hash = {}
        keyOptions.hash.name = options.hash
      } else if (options.name === 'RSA-PSS') {
        options.type = (typeof options.type !== 'undefined') ? options.type : 'pkcs8'
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
        options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['sign']

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        keyOptions.hash = {}
        keyOptions.hash.name = options.hash
      } else {
        throw new TypeError('Expected input of options.name is not a valid algorithm name')
      }

      if (typeof options.type !== 'string') {
        throw new TypeError('Expected input of options.type to be a String')
      }

      if (typeof options.usages !== 'object') {
        throw new TypeError('Expected input of options.usages to be an Array')
      }

      if (unwrappingKey.type === 'secret') {
        let ivB64 = null
        let encryptedKeyB64 = null

        if (unwrappingKey.algorithm.name === 'AES-GCM') {
          ivB64 = encryptedKey.substring(0, 16)
          encryptedKeyB64 = encryptedKey.substring(16)
        } else if (unwrappingKey.algorithm.name === 'AES-CBC') {
          ivB64 = encryptedKey.substring(0, 24)
          encryptedKeyB64 = encryptedKey.substring(24)
        } else {
          throw new TypeError('Cipher mode of the wrappingKey is not supported')
        }

        const ivAb = self.base64ToArrayBuffer(ivB64)
        const encryptedKeyAb = self.base64ToArrayBuffer(encryptedKeyB64)

        cryptoApi.unwrapKey(
          options.type,
          encryptedKeyAb,
          unwrappingKey,
          {
            name: unwrappingKey.algorithm.name,
            iv: ivAb,
            tagLength: 128
          },
          keyOptions,
          options.isExtractable,
          options.usages
        ).then(decryptedKey => {
          resolve(decryptedKey)
        }).catch(err => {
          reject(err)
        })
      } else if (unwrappingKey.algorithm.name === 'RSA-OAEP') {
        if (unwrappingKey.type !== 'private') {
          throw new TypeError('Expected input of unwrappingKey to be a CryptoKey Object of type private')
        }

        const encryptedKeyAb = self.base64ToArrayBuffer(encryptedKey)

        cryptoApi.unwrapKey(
          options.type,
          encryptedKeyAb,
          unwrappingKey,
          {
            name: 'RSA-OAEP',
            modulusLength: unwrappingKey.algorithm.modulusLength,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: unwrappingKey.algorithm.hash.name }
          },
          keyOptions,
          options.isExtractable,
          options.usages
        ).then(decryptedKey => {
          resolve(decryptedKey)
        }).catch(err => {
          reject(err)
        })
      } else {
        throw new TypeError('Expected input of unwrappingKey is not a supported key')
      }
    })
  }

  /**
   * Method that generates key signature using ECDSA or RSA-PSS
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {CryptoKey} key default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDSA: { hash: 'SHA-512' }
   * -- RSA-PSS: { saltLength: 128 }
   */
  signKey (privateKey, key, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey Object of type private')
      }

      if (Object.prototype.toString.call(key) !== '[object CryptoKey]') {
        throw new TypeError('Expected input of key to be a CryptoKey Object')
      }

      cryptoApi.exportKey(
        'raw',
        key
      ).then(keyAb => {
        if (privateKey.algorithm.name === 'ECDSA') {
          options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
  
          if (typeof options.hash !== 'string') {
            throw new TypeError('Expected input of options.hash to be a String')
          }
  
          cryptoApi.sign(
            {
              name: 'ECDSA',
              hash: { name: options.hash }
            },
            privateKey,
            keyAb
          ).then(signatureAb => {
            const signatureB64 = self.arrayBufferToBase64(signatureAb)
            resolve(signatureB64)
          }).catch(err => {
            reject(err)
          })
        } else if (privateKey.algorithm.name === 'RSA-PSS') {
          options.saltLength = (typeof options.saltLength !== 'undefined') ? options.saltLength : 128
  
          if (typeof options.saltLength !== 'number') {
            throw new TypeError('Expected input of options.saltLength to be a Number')
          }
  
          cryptoApi.sign(
            {
              name: 'RSA-PSS',
              saltLength: options.saltLength
            },
            privateKey,
            keyAb
          ).then(signatureAb => {
            const signatureB64 = self.arrayBufferToBase64(signatureAb)
            resolve(signatureB64)
          }).catch(err => {
            reject(err)
          })
        } else {
          throw new TypeError('Expected input of privateKey is not a valid private key')
        }
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that verifies key signature using ECDSA or RSA-PSS
   * @param {CryptoKey} publicKey default: "undefined"
   * @param {CryptoKey} key default: "undefined"
   * @param {String} signature default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDSA: { hash: 'SHA-512' }
   * -- RSA-PSS: { saltLength: 128 }
   */
  verifyKey (publicKey, key, signature, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
        throw new TypeError('Expected input of publicKey to be a CryptoKey Object of type public')
      }

      if (Object.prototype.toString.call(key) !== '[object CryptoKey]') {
        throw new TypeError('Expected input of key to be a CryptoKey Object')
      }

      if (typeof signature !== 'string') {
        throw new TypeError('Expected input of signature to be a Base64 String')
      }
      
      const signatureAb = self.base64ToArrayBuffer(signature)

      cryptoApi.exportKey(
        'raw',
        key
      ).then(keyAb => {
        if (publicKey.algorithm.name === 'ECDSA') {
          options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
  
          if (typeof options.hash !== 'string') {
            throw new TypeError('Expected input of options.hash to be a String')
          }
  
          cryptoApi.verify(
            {
              name: 'ECDSA',
              hash: { name: options.hash }
            },
            publicKey,
            signatureAb,
            keyAb
          ).then(isValid => {
            resolve(isValid)
          }).catch(err => {
            reject(err)
          })
        } else if (publicKey.algorithm.name === 'RSA-PSS') {
          cryptoApi.verify(
            {
              name: 'RSA-PSS',
              saltLength: 128
            },
            publicKey,
            signatureAb,
            keyAb
          ).then(isValid => {
            resolve(isValid)
          }).catch(err => {
            reject(err)
          })
        } else {
          throw new TypeError('Expected input of publicKey is not a valid public key')
        }
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that generates signature of data using ECDSA or RSA-PSS
   * @param {CryptoKey} privateKey default: "undefined"
   * @param {ArrayBuffer} data default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDSA: { hash: 'SHA-512' }
   * -- RSA-PSS: { saltLength: 128 }
   */
  sign (privateKey, data, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(privateKey) !== '[object CryptoKey]' && privateKey.type !== 'private') {
        throw new TypeError('Expected input of privateKey to be a CryptoKey Object of type private')
      }

      if (typeof data !== 'object') {
        throw new TypeError('Expected input of data to be an ArrayBuffer')
      }

      if (privateKey.algorithm.name === 'ECDSA') {
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        cryptoApi.sign(
          {
            name: 'ECDSA',
            hash: { name: options.hash }
          },
          privateKey,
          data
        ).then(signatureAb => {
          const signatureB64 = self.arrayBufferToBase64(signatureAb)
          resolve(signatureB64)
        }).catch(err => {
          reject(err)
        })
      } else if (privateKey.algorithm.name === 'RSA-PSS') {
        options.saltLength = (typeof options.saltLength !== 'undefined') ? options.saltLength : 128

        if (typeof options.saltLength !== 'number') {
          throw new TypeError('Expected input of options.saltLength to be a Number')
        }

        cryptoApi.sign(
          {
            name: 'RSA-PSS',
            saltLength: options.saltLength
          },
          privateKey,
          data
        ).then(signatureAb => {
          const signatureB64 = self.arrayBufferToBase64(signatureAb)
          resolve(signatureB64)
        }).catch(err => {
          reject(err)
        })
      } else {
        throw new TypeError('Expected input of privateKey is not a valid private key')
      }
    })
  }

  /**
   * Method that verifies data signature using ECDSA or RSA-PSS
   * @param {CryptoKey} publicKey default: "undefined"
   * @param {ArrayBuffer} data default: "undefined"
   * @param {String} signature default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- ECDSA: { hash: 'SHA-512' }
   * -- RSA-PSS: { saltLength: 128 }
   */
  verify (publicKey, data, signature, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(publicKey) !== '[object CryptoKey]' && publicKey.type !== 'public') {
        throw new TypeError('Expected input of publicKey to be a CryptoKey Object of type public')
      }

      if (typeof data !== 'object') {
        throw new TypeError('Expected input of data to be an ArrayBuffer')
      }

      if (typeof signature !== 'string') {
        throw new TypeError('Expected input of signature to be a Base64 String')
      }
      
      const signatureAb = self.base64ToArrayBuffer(signature)

      if (publicKey.algorithm.name === 'ECDSA') {
        options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'

        if (typeof options.hash !== 'string') {
          throw new TypeError('Expected input of options.hash to be a String')
        }

        cryptoApi.verify(
          {
            name: 'ECDSA',
            hash: { name: options.hash }
          },
          publicKey,
          signatureAb,
          data
        ).then(isValid => {
          resolve(isValid)
        }).catch(err => {
          reject(err)
        })
      } else if (publicKey.algorithm.name === 'RSA-PSS') {
        cryptoApi.verify(
          {
            name: 'RSA-PSS',
            saltLength: 128
          },
          publicKey,
          signatureAb,
          data
        ).then(isValid => {
          resolve(isValid)
        }).catch(err => {
          reject(err)
        })
      } else {
        throw new TypeError('Expected input of publicKey is not a valid public key')
      }
    })
  }

  /**
   * Method that encrypts data using symmetric/shared key
   * @param {CryptoKey} sharedKey default: "undefined"
   * @param {ArrayBuffer} data default: "undefined"
   */
  encrypt (sharedKey, data) {
    const self = this

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(sharedKey) !== '[object CryptoKey]' && sharedKey.type !== 'secret') {
        throw new TypeError('Expected input of sharedKey to be a CryptoKey Object')
      }

      if (typeof data !== 'object') {
        throw new TypeError('Expected input of data to be an ArrayBuffer')
      }

      let ivAb = null

      if (sharedKey.algorithm.name === 'AES-GCM') {
        ivAb = cryptoLib.getRandomValues(new Uint8Array(12))
      } else if (sharedKey.algorithm.name === 'AES-CBC') {
        ivAb = cryptoLib.getRandomValues(new Uint8Array(16))
      } else {
        throw new TypeError('Cipher mode of the sharedKey is not supported')
      }

      cryptoApi.encrypt(
        {
          name: sharedKey.algorithm.name,
          iv: ivAb,
          tagLength: 128
        },
        sharedKey,
        data
      ).then(encryptedAb => {
        const ivB64 = self.arrayBufferToBase64(ivAb)
        const encryptedB64 = self.arrayBufferToBase64(encryptedAb)

        resolve(ivB64 + encryptedB64)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that decrypts data using symmetric/shared key
   * @param {CryptoKey} sharedKey default: "undefined"
   * @param {String} encryptedData default: "undefined"
   * @param {Object} options default: depends on algorithm below
   * -- AES-GCM: { cipher: 'AES-GCM' }
   * -- AES-CBC: { cipher: 'AES-CBC' }
   */
  decrypt (sharedKey, encryptedData, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    options.cipher = (typeof options.cipher !== 'undefined') ? options.cipher : 'AES-GCM'

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(sharedKey) !== '[object CryptoKey]' && sharedKey.type !== 'secret') {
        throw new TypeError('Expected input of sharedKey to be a CryptoKey Object')
      }

      if (typeof encryptedData !== 'string') {
        throw new TypeError('Expected input of encryptedData to be a String')
      }

      if (typeof options.cipher !== 'string') {
        throw new TypeError('Expected input of options.cipher to be a String')
      }

      let ivB64 = null
      let encryptedB64 = null

      if (options.cipher === 'AES-GCM') {
        ivB64 = encryptedData.substring(0, 16)
        encryptedB64 = encryptedData.substring(16)
      } else if (options.cipher === 'AES-CBC') {
        ivB64 = encryptedData.substring(0, 24)
        encryptedB64 = encryptedData.substring(24)
      } else {
        throw new TypeError('Cipher mode of the sharedKey is not supported')
      }

      const ivAb = self.base64ToArrayBuffer(ivB64)
      const encryptedAb = self.base64ToArrayBuffer(encryptedB64)

      cryptoApi.decrypt(
        {
          name: options.cipher,
          iv: ivAb,
          tagLength: 128
        },
        sharedKey,
        encryptedAb
      ).then(decryptedDataAb => {
        resolve(decryptedDataAb)
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that derives shared key from passphrase
   * @param {String} passphrase default: "undefined"
   * @param {ArrayBuffer} salt default: "undefined"
   * @param {Number} iterations default: "64000"
   * @param {Object} options default: "{ hash: 'SHA-512', length: 256, cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
   */
  derivePassphraseKey (passphrase, salt, iterations, options) {
    const self = this

    iterations = (typeof iterations !== 'undefined') ? iterations : 64000

    if (typeof options === 'undefined') {
      options = {}
    }

    options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
    options.length = (typeof options.length !== 'undefined') ? options.length : 256
    options.cipher = (typeof options.cipher !== 'undefined') ? options.cipher : 'AES-GCM'
    options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    options.isExtractable = (typeof options.isExtractable !== 'undefined') ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (typeof passphrase !== 'string') {
        throw new TypeError('Expected input of passphrase to be a String')
      }

      if (typeof salt !== 'object') {
        throw new TypeError('Expected input of salt to be an ArrayBuffer')
      }

      if (typeof iterations !== 'number') {
        throw new TypeError('Expected input of iterations to be a Number')
      }

      if (typeof options.hash !== 'string') {
        throw new TypeError('Expected input of options.hash to be a String')
      }

      if (typeof options.length !== 'number') {
        throw new TypeError('Expected input of options.length to be a Number')
      }

      if (typeof options.cipher !== 'string') {
        throw new TypeError('Expected input of options.cipher to be a String')
      }

      if (typeof options.usages !== 'object') {
        throw new TypeError('Expected input of options.usages to be an Array')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable to be a Boolean')
      }

      const passphraseAb = self.stringToArrayBuffer(passphrase)

      cryptoApi.importKey(
        'raw',
        passphraseAb,
        {
          name: 'PBKDF2'
        },
        false,
        ['deriveKey']
      ).then(baseKey => {
        cryptoApi.deriveKey(
          {
            name: 'PBKDF2',
            salt: salt,
            iterations: iterations,
            hash: { name: options.hash }
          },
          baseKey,
          {
            name: options.cipher,
            length: options.length
          },
          options.isExtractable,
          options.usages
        ).then(derivedKey => {
          resolve(derivedKey)
        }).catch(err => {
          reject(err)
        })
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that derives hash from passphrase
   * @param {String} passphrase default: "undefined"
   * @param {ArrayBuffer} salt default: "undefined" salt
   * @param {Number} iterations default: "64000"
   * @param {Object} options default: "{ hash: 'SHA-512', length: 256, cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }"
   */
  hashPassphrase (passphrase, salt, iterations, options) {
    const self = this

    iterations = (typeof iterations !== 'undefined') ? iterations : 64000

    if (typeof options === 'undefined') {
      options = {}
    }

    options.hash = (typeof options.hash !== 'undefined') ? options.hash : 'SHA-512'
    options.length = (typeof options.length !== 'undefined') ? options.length : 256
    options.cipher = (typeof options.cipher !== 'undefined') ? options.cipher : 'AES-GCM'
    options.usages = (typeof options.usages !== 'undefined') ? options.usages : ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    options.isExtractable = (typeof options.isExtractable !== 'undefined') ? options.isExtractable : true

    return new Promise((resolve, reject) => {
      if (typeof passphrase !== 'string') {
        throw new TypeError('Expected input of passphrase to be a String')
      }

      if (typeof salt !== 'object') {
        throw new TypeError('Expected input of salt to be an ArrayBuffer')
      }

      if (typeof iterations !== 'number') {
        throw new TypeError('Expected input of iterations to be a Number')
      }

      if (typeof options.hash !== 'string') {
        throw new TypeError('Expected input of options.hash to be a String')
      }

      if (typeof options.length !== 'number') {
        throw new TypeError('Expected input of options.length to be a Number')
      }

      if (typeof options.cipher !== 'string') {
        throw new TypeError('Expected input of options.cipher to be a String')
      }

      if (typeof options.usages !== 'object') {
        throw new TypeError('Expected input of options.usages to be an Array')
      }

      if (typeof options.isExtractable !== 'boolean') {
        throw new TypeError('Expected input of options.isExtractable to be a Boolean')
      }

      self.derivePassphraseKey(passphrase, salt, iterations, options).then(derivedKey => {
        cryptoApi.exportKey(
          'raw',
          derivedKey
        ).then(exportedKeyAb => {
          const derivedHash = self.arrayBufferToHexString(exportedKeyAb)
          resolve(derivedHash)
        }).catch(err => {
          reject(err)
        })
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that generates fingerprint of EC, RSA and AES keys
   * @param {CryptoKey} key default: "undefined"
   * @param {Object} options default: { hash: 'SHA-512', isBuffer: false }
   */
  getFingerprint (key, options) {
    const self = this

    if (typeof options === 'undefined') {
      options = {}
    }

    options.hash = (typeof hash !== 'undefined') ? hash : 'SHA-512'
    options.isBuffer = (typeof options.isBuffer !== 'undefined') ? options.isBuffer : false

    return new Promise((resolve, reject) => {
      if (Object.prototype.toString.call(key) !== '[object CryptoKey]') {
        throw new TypeError('Expected input of key to be a CryptoKey Object')
      }

      if (typeof options.hash !== 'string') {
        throw new TypeError('Expected input of options.hash to be a String')
      }

      if (typeof options.isBuffer !== 'boolean') {
        throw new TypeError('Expected input of options.isBuffer to be a Boolean')
      }

      let keyType = null
      switch (key.type) {
        case 'secret' :
          keyType = 'raw'
          break
        case 'private' :
          keyType = 'pkcs8'
          break
        case 'public' :
          keyType = 'spki'
      }

      cryptoApi.exportKey(
        keyType,
        key
      ).then(keyAb => {
        cryptoApi.digest(
          {
            name: options.hash
          },
          keyAb
        ).then(fingerprintAb => {
          if (options.isBuffer) {
            resolve(fingerprintAb)
          } else {
            const hexFingerprint = self.arrayBufferToHexString(fingerprintAb)
            resolve(hexFingerprint)
          }
        }).catch(err => {
          reject(err)
        })
      }).catch(err => {
        reject(err)
      })
    })
  }

  /**
   * Method that generates random bytes using cryptographically secure PRNG
   * @param {Number} size default: "16"
   */
  getRandomBytes (size) {
    size = (typeof size !== 'undefined') ? size : 16

    return new Promise((resolve, reject) => {
      if (typeof size !== 'number') {
        throw new TypeError('Expected input of size to be a Number')
      }

      const data = cryptoLib.getRandomValues(new Uint8Array(size))

      resolve(data)
    })
  }
}
