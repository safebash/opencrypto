// OpenCrypto PBKDF2 Unit Test

describe('derive keys', function () {
  it('should return derived key', function (done) {
    crypto.keyFromPassphrase('randompassphrase', 'somerandomsalt', 1000, 'SHA-512', 256).then(function (derivedKey) {
      if (derivedKey === '5f721761335585749766376f8879fa9f10282627bf7ecfd1af77d9b64ec730ec') {
        done()
      }
    })
  })
})
