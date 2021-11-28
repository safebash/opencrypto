export default class OpenCrypto {
  /**
   * @source @niklasvh base64-arraybuffer
   * @copyright Copyright (c) 2012 Niklas von Hertzen
   * @license MIT
   */
  encodeAb(arrayBuffer: ArrayBufferLike): Base64;

  /**
   * @source @niklasvh base64-arraybuffer
   * @copyright Copyright (c) 2012 Niklas von Hertzen
   * @license MIT
   */
  decodeAb(base64: Base64): ArrayBufferLike;

  /**
   * Method for encoding ArrayBuffer into UTF-8 String
   */
  arrayBufferToString(arrayBuffer: ArrayBufferLike): string;

  /**
   * Method for decoding String to ArrayBuffer
   */
  stringToArrayBuffer(str: string): ArrayBufferLike;

  /**
   * Method for encoding ArrayBuffer to hexadecimal String
   */
  arrayBufferToHexString(arrayBuffer: ArrayBufferLike): Hexadecimal;

  /**
   * Method for decoding hexadecimal String to ArrayBuffer
   */
  hexStringToArrayBuffer(hexString: Hexadecimal): ArrayBufferLike;

  /**
   * Method for encoding ArrayBuffer to base64 String
   */
  arrayBufferToBase64(arrayBuffer: ArrayBufferLike): Base64;

  /**
   * Method for decoding base64 String to ArrayBuffer
   */
  base64ToArrayBuffer(b64: Base64): ArrayBufferLike;

  /**
   * Method for encoding decimal Number to hexadecimal String
   */
  decimalToHex(d: number, unsigned: boolean): Hexadecimal;

  /**
   * Method for addition of new lines into PEM encoded key
   */
  addNewLines(str: string): string;
  /**
   * Method that removes lines from PEM encoded key
   */
  removeLines(str: string): string;

  /**
   * Method that encodes ASN.1 information into PEM encoded key
   */
  toAsn1(
    wrappedKey: ArrayBufferLike,
    salt: ArrayBufferLike,
    iv: ArrayBufferLike,
    iterations: number,
    hash: Asn1Hash,
    cipher: Asn1Cipher,
    length: number
  ): Base64;

  /**
   * Method that retrieves ASN.1 encoded information from PEM encoded key
   */
  fromAsn1(pem: Base64): {
    salt: ArrayBufferLike;
    iv: ArrayBufferLike;
    cipher: Asn1Cipher;
    length: number;
    hash: Asn1Hash;
    iter: number;
    encryptedData: ArrayBufferLike;
  };

  /**
   * Method that converts asymmetric private key from CryptoKey to PEM format
   */
  cryptoPrivateToPem(privateKey: CryptoKey): Promise<Base64>;

  /**
   * Method that converts asymmetric private key from PEM to CryptoKey format
   */
  pemPrivateToCrypto(
    pem: Base64,
    options?: PrivateKeyCryptoOptions
  ): Promise<CryptoKey>;

  /**
   * Method that converts asymmetric public key from CryptoKey to PEM format
   */
  cryptoPublicToPem(publicKey: CryptoKey): Promise<Base64>;

  /**
   * Method that converts asymmetric public key from PEM to CryptoKey format
   */
  pemPublicToCrypto(
    pem: Base64,
    options?: PublicKeyCryptoOptions
  ): Promise<CryptoKey>;

  /**
   * Method that converts CryptoKey to base64
   */
  cryptoToBase64(
    key: CryptoKey,
    /** @default raw if secret, pkcs8 if private spki if public */
    type?: CryptoKeyType
  ): Promise<Base64>;

  /**
   * Method that converts base64 encoded key to CryptoKey
   */
  base64ToCrypto(
    key: Base64,
    options?: Base64ToCryptoOptions
  ): Promise<CryptoKey>;

  /**
   * Method that generates asymmetric RSA-OAEP key pair
   */
  getRSAKeyPair(
    /** @default 2048 */
    modulusLength?: number,

    /** @default 'SHA-512' */
    hash?: Asn1Hash,

    /** @default 'RSA-OAEP' */
    paddingScheme?: "RSA-OAEP" | "RSA-PSS",

    usages?: RSAOAEPBase64Options["usages"],

    /** @default true */
    isExtractable?: boolean
  ): Promise<CryptoKeyPair>;
  /**
   *
   * Method that encrypts data using asymmetric encryption
   */
  rsaEncrypt(publicKey: CryptoKey, data: ArrayBufferLike): Promise<Base64>;

  /**
   * Method that decrypts data using asymmetric encryption
   */
  rsaDecrypt(
    privateKey: CryptoKey,
    encryptedData: string
  ): Promise<ArrayBufferLike>;

  /**
   * Method that generates asymmetric Elliptic Curve Diffie-Hellman key pair
   */
  getECKeyPair(
    /** @default 'P-256' */
    curve?: ECDNamedCurve,

    /** @default ECDH */
    type?: "ECDH" | "ECDSA",

    usages?: ECDHBase64Options["usages"],

    /** @default true */
    isExtractable?: boolean
  ): Promise<CryptoKeyPair>;

  /**
   * Method that retrieves public key from private key
   */
  getPublicKey(
    privateKey: CryptoKey,
    options?: PublicKeyCryptoOptions
  ): Promise<CryptoKey>;

  /**
   * Method that encrypts asymmetric private key using passphrase to enable storage in unsecure environment
   */
  encryptPrivateKey(
    privateKey: CryptoKey,

    passphrase: string,

    /** @default 64000 */
    iterations?: number,

    /** @default 'SHA-512' */
    hash?: string,

    /** @default 'AES-256' */
    cipher?: Asn1Cipher,

    /** @default 256 */
    length?: number
  ): Promise<Base64>;

  /**
   * Method that decrypts asymmetric private key using passphrase
   */
  decryptPrivateKey(
    encryptedPrivateKey: string,
    passphrase: string,
    options?: PrivateKeyCryptoOptions
  ): Promise<CryptoKey>;

  /**
   * Method that performs ECDH key agreement
   */
  keyAgreement(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    options?: KeyAgreementOptions
  ): Promise<CryptoKey>;

  /**
   * Method that generates symmetric/shared key for AES encryption
   */
  getSharedKey(
    /** @default 256 */
    length: number,

    options?: SharedKeyOptions
  ): Promise<CryptoKeyPair>;

  /**
   * Method that encrypts keys
   */
  encryptKey(wrappingKey: CryptoKey, key: CryptoKey): Promise<Base64>;

  /**
   * Method that decrypts keys
   */
  decryptKey(
    unwrappingKey: CryptoKey,
    encryptedKey: string,
    options?: DecryptKeyOptions
  ): Promise<CryptoKey>;

  /**
   * Method that generates key signature using ECDSA or RSA-PSS
   */
  signKey(
    privateKey: CryptoKey,
    key: CryptoKey,
    options?: SignKeyOptions
  ): Promise<Base64>;

  /**
   * Method that verifies key signature using ECDSA or RSA-PSS
   */
  verifyKey(
    publicKey: CryptoKey,
    key: CryptoKey,
    signature: string,
    options?: SignKeyOptions
  ): Promise<boolean>;

  /**
   * Method that generates signature of data using ECDSA or RSA-PSS
   */
  sign(
    privateKey: CryptoKey,
    data: ArrayBufferLike,
    options?: SignKeyOptions
  ): Promise<Base64>;

  /**
   * Method that verifies data signature using ECDSA or RSA-PSS
   */
  verify(
    publicKey: CryptoKey,
    data: ArrayBufferLike,
    signature: string,
    options?: SignKeyOptions
  ): Promise<boolean>;

  /**
   * Method that encrypts data using symmetric/shared key
   */
  encrypt(sharedKey: CryptoKey, data: ArrayBufferLike): Promise<Base64>;

  /**
   * Method that decrypts data using symmetric/shared key
   */
  decrypt(
    sharedKey: CryptoKey,
    encryptedData: string,
    options?: CipherDecryptOptions
  ): Promise<ArrayBufferLike>;

  /**
   * Method that derives shared key from passphrase
   */
  derivePassphraseKey(
    passphrase: string,
    salt: ArrayBufferLike,
    iterations: number,
    options?: PassphraseOptions
  ): Promise<CryptoKey>;

  /**
   * Method that derives hash from passphrase
   */
  hashPassphrase(
    passphrase: string,
    salt: ArrayBufferLike,
    iterations: number,
    options?: PassphraseOptions
  ): Promise<Hexadecimal>;

  /**
   * Method that generates fingerprint of EC, RSA and AES keys
   */
  getFingerprint(key: CryptoKey, options?: GetFingerprintOptions): Promise<any>;

  /**
   * Method that generates random bytes using cryptographically secure PRNG
   */
  getRandomBytes(
    /** @default 16 */
    size: number
  ): Promise<number>;
}

type Base64 = string;
type Hexadecimal = string;

type Asn1Cipher = "AES-GCM" | "AES-CBC" | "AES-CFB";
type Asn1Hash = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-612";

type PrivateKeyCryptoOptions =
  | ECDHPrivateOptions
  | ECDSAPrivateOptions
  | RSAOAEPPrivateOptions
  | RSAPSSPrivateOptions;

interface ECDHPrivateOptions {
  name: "ECDH";

  /** @default ['deriveKey', 'deriveBits'] */
  usages?: ("deriveKey" | "deriveBits")[];

  /** @default true */
  isExtractable?: boolean;
}

interface ECDSAPrivateOptions {
  name: "ECDSA";

  /** @default ['sign'] */
  usages?: "sign"[];

  /** @default true */
  isExtractable?: boolean;
}

interface RSAOAEPPrivateOptions {
  name: "RSA-OAEP";

  /** @default { name: 'SHA-512' }  */
  hash?: { name: Asn1Hash };

  /** @default ['decrypt', 'unwrapKey'] */
  usages?: ("decypt" | "unwrapKey")[];

  /** @default true */
  isExtractable?: boolean;
}

interface RSAPSSPrivateOptions {
  name: "RSA-PSS";

  /** @default { name: 'SHA-512' }  */
  hash?: { name: Asn1Hash };

  /** @default ['sign'] */
  usages?: "sign"[];

  /** @default true */
  isExtractable?: boolean;
}

type PublicKeyCryptoOptions =
  | ECDHPublicOptions
  | ECDSAPublicOptions
  | RSAOAEPPublicOptions
  | RSAPSSPublicOptions;

type ECDHPublicOptions = Omit<ECDHPrivateOptions, "usages"> & { usages: [] };
type ECDSAPublicOptions = Omit<ECDHPrivateOptions, "usages"> & {
  usages: "verify"[];
};
type RSAOAEPPublicOptions = Omit<RSAOAEPPrivateOptions, "usages"> & {
  usages: ("encrypt" | "wrapKey")[];
};
type RSAPSSPublicOptions = Omit<RSAPSSPrivateOptions, "usages"> & {
  usages: "verify"[];
};

type CryptoKeyType = "raw" | "pkcs8" | "spki";

type Base64ToCryptoOptions =
  | AESGCMBase64Options
  | AESCBCBase64Options
  | ECDHBase64Options
  | ECDSABase64Options
  | RSAOAEPBase64Options
  | RSAPSSBase64Options;

interface AESGCMBase64Options {
  name: "AES-GCM";

  /** @default 256 */
  length?: number;

  /** @default ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'] */
  usages?: ("encrypt" | "decrypt" | "wrapKey" | "unwrapKey")[];

  /** @default true */
  isExtractable?: boolean;
}

interface AESCBCBase64Options {
  name: "AES-GCM";

  /** @default ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'] */
  usages?: ("encrypt" | "decrypt" | "wrapKey" | "unwrapKey")[];

  /** @default true */
  isExtractable?: boolean;
}

interface ECDHBase64Options {
  name: "ECDH";

  /** @default 'P-256' */
  namedCurve?: ECDNamedCurve;

  /** @default ['deriveKey', 'deriveBits'] */
  usages?: ("deriveKey" | "deriveBits")[];

  /** @default true */
  isExtractable?: boolean;
}

type ECDSABase64Options = Omit<ECDHBase64Options, "usages"> & {
  /** @default ['sign', 'verify'] */
  usages?: ("sign" | "verify")[];
};

type ECDNamedCurve = "P-256" | "P-384" | "P-152";

interface RSAOAEPBase64Options {
  name: "RSA-OAEP";

  /** @default { name: 'SHA-512' } */
  hash?: { name: Asn1Hash };

  /** @default ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'] */
  usages: ("encrypt" | "decrypt" | "wrapKey" | "unwrapKey")[];

  /** @default true */
  isExtractable: boolean;
}

type RSAPSSBase64Options = Omit<RSAOAEPBase64Options, "usages"> & {
  /** @default ['sign', 'verify] */
  usages?: ("sign" | "verify")[];
};

interface KeyAgreementOptions {
  /** @default 256 */
  bitLength?: number;

  /** @default 'SHA-512' */
  hkdfHash?: Asn1Hash;

  /** @default new Uint8Array() */
  hkdfSalt?: Uint8Array;

  /** @default new Uint8Array() */
  hkdfInfo?: Uint8Array;

  /** @default 'AES-GCM' */
  cipher?: Asn1Cipher;

  /** @default 256 */
  length?: number;

  /** @default ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'] */
  usages?: ("encrypt" | "decrypt" | "wrapKey" | "unwrapKey")[];

  /** @default true */
  isExtractable?: boolean;
}

type SharedKeyOptions = {
  /** @default 'AES-GCM' */
  cipher: Asn1Cipher;

  /** @default true */
  isExtractable?: boolean;
} & Pick<KeyAgreementOptions, "usages">;

type DecryptKeyOptions =
  | AESGCMDecryptOption
  | AESCBCDecryptOptions
  | ECDHDecryptOptions
  | ECDSADecryptOptions
  | RSAOAEPDecryptOptions
  | RSAPSSDecryptOptions;

type AESGCMDecryptOption = {
  type: "raw";

  /**@default 256 */
  length?: number;
} & Pick<AESCBCBase64Options, "name" | "usages" | "isExtractable">;

type AESCBCDecryptOptions = { type: "raw" } & Pick<
  AESGCMDecryptOption,
  "length"
> &
  Pick<AESCBCBase64Options, "name" | "usages" | "isExtractable">;

type ECDHDecryptOptions = { type: "pkcs8" | "spki" } & ECDHBase64Options;

type ECDSADecryptOptions = Pick<ECDHDecryptOptions, "type"> &
  ECDSABase64Options;

type RSAOAEPDecryptOptions = Pick<ECDHDecryptOptions, "type"> &
  RSAOAEPBase64Options;

type RSAPSSDecryptOptions = Pick<ECDHDecryptOptions, "type"> &
  RSAPSSBase64Options;

type SignKeyOptions = ECDSASignKeyOptions | RSAPSSSignKeyOptions;

interface ECDSASignKeyOptions {
  /** @default 'SHA-512' */
  hash?: Asn1Hash;
}

interface RSAPSSSignKeyOptions {
  /** @default 128 */
  saltLength?: number;
}

type CipherDecryptOptions = {
  /** @default 'AES-GCM' or 'AES-CBC' depending on key */
  cipher?: Asn1Cipher;
};

type PassphraseOptions = {
  /** @default 'SHA-512' */
  hash?: Asn1Hash;

  /** @default 256 */
  length?: number;

  /** @default 'AES-GCM' */
  cipher?: Asn1Cipher;

  /** @default ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'] */
  usages?: ("encrypt" | "decrypt" | "wrapKey" | "unwrapKey")[];

  /** @default true */
  isExtractable?: boolean;
};

interface GetFingerprintOptions {
  /** @default */
  hash?: Asn1Hash;

  /** @default false */
  buffer?: boolean;
}
