const { spawn } = require('node:child_process');
// Keep Firebase's own interactive shutdown in charge of export-on-exit.
// emulators:exec would also shut down when the dev command receives Ctrl+C,
// racing that export. emulators:start has only one shutdown owner.
const isolated = process.platform !== 'win32';
const emulators = spawn(process.execPath, process.argv.slice(2), {
  stdio: ['inherit', 'pipe', 'inherit'], detached: isolated,
});
let frontend;
let stopping = false;
let failure = 0;
let output = '';
function stop() {
  if (stopping) return;
  stopping = true;
  frontend?.kill('SIGTERM');
  // POSIX children have their own group. On Windows the terminal delivers
  // Ctrl+C to the CLI as well as this wrapper, so do not deliver it twice.
  if (isolated) emulators.kill('SIGINT');
}
process.on('SIGINT', stop);
process.on('SIGTERM', () => {
  stop();
  if (!isolated) emulators.kill('SIGINT');
});
emulators.stdout.on('data', chunk => {
  process.stdout.write(chunk);
  output = (output + chunk.toString()).slice(-4000);
  if (!frontend && !stopping && /All emulators ready/.test(output)) {
    frontend = spawn(process.execPath, ['scripts/local-vite.cjs'], {
      stdio: 'inherit', detached: isolated,
    });
    frontend.on('error', error => { console.error(error.message); failure = 1; process.exitCode = 1; stop(); });
    frontend.on('exit', code => {
      if (!stopping) { failure = code || 1; stop(); }
    });
  }
});
emulators.on('error', error => { console.error(error.message); failure = 1; process.exitCode = 1; stop(); });
emulators.on('exit', code => {
  frontend?.kill('SIGTERM');
  process.exitCode = failure || code || (stopping ? 0 : 1);
  process.removeListener('SIGINT', stop);
});
