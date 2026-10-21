const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { loadConfig } = require('./config.cjs');
const root = path.resolve(__dirname, '..');

function validateDeployment(config, browser, backend, environment = process.env) {
  if (config.project.startsWith('demo-')) throw new Error('Demo projects cannot be deployed.');
  for (const key of Object.keys(environment)) {
    if ((key.includes('EMULATOR') || key === 'FIREBASE_CONFIG') && environment[key]) {
      throw new Error(`Unset ${key} before deploying from a local emulator session.`);
    }
  }
  const expected = {
    VITE_FIREBASE_PROJECT_ID: config.project,
    VITE_FIREBASE_STORAGE_BUCKET: config.bucket,
    VITE_FIREBASE_MESSAGING_SENDER_ID: config.projectNumber,
    VITE_FIREBASE_FUNCTIONS_REGION: config.region,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (browser[key] !== value) throw new Error(`${key} must match vault.config.local.json (${value}).`);
  }
  for (const key of ['VITE_FIREBASE_API_KEY', 'VITE_FIREBASE_AUTH_DOMAIN', 'VITE_FIREBASE_APP_ID']) {
    if (!browser[key]?.trim() || /^(your-|fake-)/.test(browser[key])) throw new Error(`Set a real ${key} in .env.local.`);
  }
  if (!browser.VITE_FIREBASE_APP_ID.startsWith(`1:${config.projectNumber}:web:`)) throw new Error('Web app ID must belong to the configured project number.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(backend.OWNER_EMAIL || '')) throw new Error('Set OWNER_EMAIL in the project Functions environment file.');
  if (backend.RP_ID !== config.rpId || backend.EXPECTED_ORIGIN !== config.origin) {
    throw new Error('Functions RP_ID and EXPECTED_ORIGIN must match the deployment origin.');
  }
  if (backend.ENFORCE_APP_CHECK !== 'false') throw new Error('This client has no App Check integration; ENFORCE_APP_CHECK must be false.');
}

function parseArgs(args) {
  let only = 'all';
  let plan = false;
  let configureAccess = false;
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--plan') plan = true;
    else if (args[index] === '--configure-access') configureAccess = true;
    else if (args[index] === '--only') only = args[++index];
    else throw new Error(`Unknown option: ${args[index]}`);
  }
  if (!['all', 'backend', 'hosting'].includes(only)) throw new Error('--only must be all, backend, or hosting.');
  return { only, plan, configureAccess };
}

function deploymentSteps(config, { only, configureAccess }) {
  const cli = 'functions/node_modules/firebase-tools/lib/bin/firebase.js';
  const firebaseDeploy = targets => [cli, 'deploy', '--project', config.project, '--only', targets];
  const steps = [
    ['Frontend tests', ['node_modules/vitest/vitest.mjs', 'run', '--config', 'vitest.config.ts']],
    ['Script tests', ['--test', ...fs.readdirSync(path.join(root, 'scripts')).filter(x => x.endsWith('.test.cjs')).map(x => `scripts/${x}`)]],
    ['Backend tests and build', ['scripts/backend-check.cjs']],
  ];
  if (only !== 'hosting') steps.push(['Deploy backend and rules', firebaseDeploy('functions,firestore,storage')]);
  const access = configureAccess ? '--apply' : '--check';
  steps.push(
    ['Validate cloud permissions and CORS', ['scripts/configure-cloud-access.cjs', access]],
    ['Validate callable invocation access', ['scripts/configure-callable-access.cjs', access]],
    ['Verify backend authorization', ['scripts/verify-deployment.cjs', '--backend']],
  );
  if (only !== 'backend') steps.push(
    ['Typecheck frontend', ['node_modules/typescript/bin/tsc', '-b']],
    ['Build production frontend', ['node_modules/vite/bin/vite.js', 'build', '--mode', 'production']],
    ['Deploy Hosting', firebaseDeploy('hosting')],
    ['Verify published deployment', ['scripts/verify-deployment.cjs']],
  );
  return steps;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const config = loadConfig();
  const { loadEnv } = await import('vite');
  const { parseEnv: parse } = require('node:util');
  const browser = loadEnv('production', root, 'VITE_');
  const backend = {};
  const projectFile = path.join(root, `functions/.env.${config.project}`);
  if (!fs.existsSync(projectFile)) throw new Error(`Missing functions/.env.${config.project}; aliases are not used by this command.`);
  for (const file of [path.join(root, 'functions/.env'), projectFile]) {
    if (fs.existsSync(file)) Object.assign(backend, parse(fs.readFileSync(file, 'utf8')));
  }
  validateDeployment(config, browser, backend);
  const steps = deploymentSteps(config, options);
  console.log(`Target: ${config.project}\nOrigin: ${config.origin}\nScope: ${options.only}`);
  if (options.configureAccess) console.log('Access setup enabled: required IAM grants and exact-origin bucket CORS replacement.');
  if (options.plan) {
    for (const [name] of steps) console.log(`- ${name}`);
    console.log('Plan only: no commands executed and no cloud resources changed.');
    return;
  }
  if (Number(process.versions.node.split('.')[0]) !== 22) throw new Error('Use Node 22 (nvm use).');
  for (const [name, args] of steps) {
    console.log(`\n${name}`);
    const result = spawnSync(process.execPath, args, {
      cwd: root, stdio: 'inherit',
      env: { ...process.env, ...browser, VITE_VAULT_BACKEND_READY: 'true', FUNCTIONS_DISCOVERY_TIMEOUT: '60' },
    });
    if (result.error || result.status !== 0) {
      throw new Error(`${name} failed. Deployment stopped; already completed cloud changes remain applied. For missing access, inspect the helpers or use --configure-access after reviewing the guide.`);
    }
  }
}
if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });
module.exports = { validateDeployment, parseArgs, deploymentSteps };
