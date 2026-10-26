const { run } = require('node:test');
const { spec } = require('node:test/reporters');
const path = require('node:path');
const fs = require('node:fs');

const testDir = path.resolve(__dirname, '../../export/test');
if (!fs.existsSync(testDir)) {
	console.error(`Test directory not found: ${testDir}. Run npm run compile first.`);
	process.exit(1);
}

const testFiles = fs.readdirSync(testDir)
	.filter((file) => file.endsWith('.test.js'))
	.map((file) => path.join(testDir, file));

if (testFiles.length === 0) {
	console.error(`No *.test.js files found in ${testDir}.`);
	process.exit(1);
}

const stream = run({ files: testFiles });
stream.on('test:fail', () => {
	process.exitCode = 1;
});
stream.compose(new spec()).pipe(process.stdout);
