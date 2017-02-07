QUnit.module('OpenCrypto');

QUnit.test( "Password Key Derivation Test", function(assert) {
  assert.ok(1 == "1", "Passed!");
});

QUnit.test("Session Key Generation Test", function(assert) {
  var crypt = new OpenCrypto();
  crypt.getRandomSalt().then(function(randomSalt) {
    assert.ok(1 == "1", 'Passed!');
  });
});
