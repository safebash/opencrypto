process.env.CHROME_BIN = require('puppeteer').executablePath()

module.exports = function (config) {
  config.set({
    frameworks: ['mocha', 'chai'],
    files: ['dist/OpenCrypto.min.js', 'test/**/*.js'],
    reporters: ['progress'],
    port: 9876,
    colors: true,
    browsers: ['ChromeHeadless'],
    autoWatch: false,
    concurrency: Infinity
  })
}
