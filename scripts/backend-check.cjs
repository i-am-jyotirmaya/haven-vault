const { spawnSync } = require('node:child_process');
// Run under the same Node executable as the deployment command, on every OS.
for (const args of [
  ['functions/node_modules/typescript/bin/tsc', '-p', 'functions'],
  ['--test', 'functions/lib/policy.test.js'],
]) {
  const result = spawnSync(process.execPath, args, { stdio: 'inherit' });
  if (result.error || result.status !== 0) process.exit(result.status || 1);
}
