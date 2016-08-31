module.exports = function (grunt) {
	grunt.loadNpmTasks('grunt-contrib-jshint');
	grunt.loadNpmTasks('grunt-contrib-qunit');
	grunt.loadNpmTasks('grunt-coveralls');

	grunt.initConfig({
		jshint: {
			all: ['test/*.js']
		},
		qunit: {
			all: ['test/index.html']
		},
		coveralls: {
			options: {
				force: false
			},
			your_target: {
				src: 'coverage-results/extra-results-*.info',
			}
		}
	});

	grunt.registerTask('test', ['jshint', 'qunit']);
	grunt.registerTask('default', ['test']);
};
