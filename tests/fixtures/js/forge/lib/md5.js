// forge's own implementation: defining forge.md.md5 is not a use of it
var forge = require('./forge');
var md5 = forge.md5 = forge.md5 || {};
forge.md.md5 = forge.md.algorithms.md5 = md5;
md5.create = function() { return {}; };
