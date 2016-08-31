var qunit = require('qunit');

qunit.run({
    code: {

		// Include the source code
		path: './src/MyLib.js',

		// What global var should it introduce for your tests?
		namespace: 'MyLib'

    },
    tests: [

		// Include the test suite(s)
		'./test/MyLib.test.js'

    ]
});
