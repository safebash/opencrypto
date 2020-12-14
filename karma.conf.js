module.exports = function (config) {
  config.set({
    frameworks: ['mocha', 'chai'],
    files: ['dist/OpenCrypto.min.js', 'test/**/*.js'],
    reporters: ['progress'],
    port: 9876, // karma web server port
    colors: true,
    logLevel: config.LOG_INFO,
    browsers: ['HeadlessChrome'],
    autoWatch: false,
    concurrency: Infinity
  })
}
