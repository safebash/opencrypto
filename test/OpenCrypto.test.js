QUnit.module('General');

QUnit.test('some basic tests', 7, function (assert) {
	var x, y;

	assert.equal('Foo', 'Foo', 'Similar strings are.. equal');
	assert.equal(true, 1, 'Boolean true and 1 are similar');
	assert.notStrictEqual(true, 1, '... but, boolean true and 1 are not *strictly* the same');
	assert.strictEqual(true, true, 'of course one boolean true is *strictly* the same as another boolean true');

	x = { one : 1, two: 2 };
	y = x;
	assert.strictEqual(
		x,
		y,
		'assert.strictEqual compares by reference, same references are equal'
	);
	assert.notStrictEqual(
		{ one : 1, two: 2 },
		{ one: 1, two: 2 },
		'assert.strictEqual compares by reference, different references with the same values are not equal'
	);
	assert.deepEqual(
		{ one : 1, two: 2 },
		{ one: 1, two: 2 },
		'assert.deepEqual compares values, not different references with the same values are equal'
	);
});

QUnit.module('OpenCrypto');
QUnit.test('keyFromPassphrase', 4, function (assert) {
	assert.strictEqual(OpenCrypto.keyFromPassphrase('password', 'uniquesalt', 2048), true, 'Strings are awesome');
});
