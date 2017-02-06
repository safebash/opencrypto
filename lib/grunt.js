module.exports = function (grunt) {
    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-contrib-qunit');
    
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        jshint: {
            all: ['../test/*.js']
        },
        qunit: {
            all: ['../test/index.html']
        }
    });
    
    grunt.registerTask('test', ['jshint', 'qunit']);
    grunt.registerTask('default', ['test']);
};
