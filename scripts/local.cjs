const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const project = 'demo-haven-vault';
const localEnv = 'OWNER_EMAIL=owner@example.com\nRP_ID=localhost\nEXPECTED_ORIGIN=http://localhost:5173\nENFORCE_APP_CHECK=false\nAUTH_SESSION_MINUTES=60\n';

function run(args) {
  // Keep this wrapper alive while Firebase handles Ctrl+C and exports data.
  const ignoreInterrupt = () => {};
  process.on('SIGINT', ignoreInterrupt);
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit' });
  process.removeListener('SIGINT', ignoreInterrupt);
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Command failed (${result.status ?? result.signal}).`);
}
function setup(directory = root) {
  const file = path.join(directory, `functions/.env.${project}`);
  if (!fs.existsSync(file)) fs.writeFileSync(file, localEnv, { flag: 'wx' });
  console.log('Local configuration ready. Owner: owner@example.com; app: http://localhost:5173');
}
function validateLocalEnv(directory = root, environment = process.env) {
  const { parseEnv: parse } = require('node:util');
  const merged = {};
  for (const name of ['.env', `.env.${project}`, '.env.local']) {
    const file = path.join(directory, 'functions', name);
    if (fs.existsSync(file)) Object.assign(merged, parse(fs.readFileSync(file, 'utf8')));
  }
  for (const [key, value] of Object.entries(parse(localEnv))) {
    if ((environment[key] ?? merged[key]) !== value) {
      throw new Error(`Local ${key} must equal ${value}. Check functions/.env.local and shell overrides.`);
    }
  }
}
function checkRuntime() {
  if (Number(process.versions.node.split('.')[0]) !== 22) throw new Error('Use Node 22 (nvm use).');
  const java = spawnSync('java', ['-version'], { encoding: 'utf8' });
  const version = `${java.stdout || ''}${java.stderr || ''}`.match(/version "(\d+)/);
  if (java.status !== 0 || !version || Number(version[1]) < 21) throw new Error('Install Java 21+ and put java on PATH.');
}
if (require.main === module) {
  try {
    const action = process.argv[2] || 'start';
    if (!['setup', 'start', 'test'].includes(action) || process.argv.length > 3) throw new Error('Usage: node scripts/local.cjs [setup|start|test]');
    setup();
    if (action !== 'setup') {
      checkRuntime();
      validateLocalEnv();
      run(['functions/node_modules/typescript/bin/tsc', '-p', 'functions']);
      const args = ['functions/node_modules/firebase-tools/lib/bin/firebase.js', 'emulators:exec', '--project', project,
        '--only', 'auth,functions,firestore,storage'];
      if (action === 'start') {
        args[1] = 'emulators:start';
        if (fs.existsSync(path.join(root, '.emulator-data/firebase-export-metadata.json'))) args.push('--import', '.emulator-data');
        args.push('--export-on-exit', '.emulator-data');
      } else args.push('node --test --test-concurrency=1 functions/test/local.test.mjs functions/test/rules.test.mjs functions/test/security.local.test.mjs');
      run(action === 'start' ? ['scripts/local-dev.cjs', ...args] : args);
    }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { setup, validateLocalEnv, checkRuntime };
