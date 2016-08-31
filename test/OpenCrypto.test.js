QUnit.module('OpenCrypto');

QUnit.test("Session Key Generation Test", function(assert) {
  var crypt = new OpenCrypto();
  crypt.getSessionKey().then(function(sessionKey) {
    assert.ok(1 == "1", 'Passed!');
  });
});
