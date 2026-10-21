const { spawn } = require('node:child_process');
// emulators:exec starts this only once the services are ready.
const children = [
  spawn(process.execPath, ['functions/node_modules/typescript/bin/tsc', '-p', 'functions', '--watch', '--preserveWatchOutput'], { stdio: 'inherit' }),
  spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--mode', 'emulator', '--host', 'localhost', '--port', '5173', '--strictPort'], {
    stdio: 'inherit', env: { ...process.env, VITE_FIREBASE_FUNCTIONS_REGION: 'us-central1' },
  }),
];
let stopping = false;
function stop(code) {
  if (stopping) return;
  stopping = true;
  process.exitCode = code;
  for (const child of children) child.kill('SIGTERM');
}
for (const child of children) {
  child.on('error', error => { console.error(error.message); stop(1); });
  child.on('exit', code => stop(code ?? 1));
}
process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));
