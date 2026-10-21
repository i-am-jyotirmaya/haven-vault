// Deployment helpers require explicit, untracked configuration. No production defaults.
const fs = require('node:fs');
const path = require('node:path');

function loadConfig(file = path.join(__dirname, '../vault.config.local.json')) {
  let config;
  try {
    config = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    throw new Error('Copy vault.config.example.json to vault.config.local.json and configure your own Firebase project.');
  }
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Invalid vault deployment configuration.');
  const { projectId, projectNumber, bucket, origin, region } = config;
  if (typeof projectId !== 'string' || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId) || projectId === 'your-project-id') {
    throw new Error('Set a real Firebase projectId in vault.config.local.json.');
  }
  if (typeof projectNumber !== 'string' || !/^[0-9]{6,20}$/.test(projectNumber)) throw new Error('projectNumber must be a numeric string.');
  if (typeof bucket !== 'string' || !/^[a-z0-9][a-z0-9.-]{1,220}[a-z0-9]$/.test(bucket) || bucket.includes('..')) {
    throw new Error('Set the exact Storage bucket name, without gs:// or a path.');
  }
  let url;
  try { url = new URL(origin); } catch { throw new Error('origin must be an exact HTTPS origin.'); }
  if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) {
    throw new Error('origin must be an exact HTTPS origin without credentials, a path, or a trailing slash.');
  }
  if (region !== 'us-central1') throw new Error('This release deploys Functions in us-central1; change the backend before selecting another region.');
  return { project: projectId, projectNumber, bucket, origin, region, rpId: url.hostname };
}

module.exports = { loadConfig };
