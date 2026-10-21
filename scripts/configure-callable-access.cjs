// Repair invocation access after an initially failed Functions deployment.
// Only these seven services receive the public transport permission. Handlers
// still validate owner identity, passkey signatures, and expiring sessions.
const { getGlobalDefaultAccount } = require('../functions/node_modules/firebase-tools/lib/auth');
const { requireAuth } = require('../functions/node_modules/firebase-tools/lib/requireAuth');
const { getIamPolicy, setIamPolicy } = require('../functions/node_modules/firebase-tools/lib/gcp/run');
const { project, region } = require('./config.cjs').loadConfig();
const apply = process.argv.includes('--apply');
const services = [
  'vaultsessioninfo', 'registrationoptions', 'verifyregistration',
  'authenticationoptions', 'verifyauthentication', 'endvaultsession', 'validatevaultsession',
];
let current = 'authenticate';

(async () => {
  const account = getGlobalDefaultAccount();
  if (!account) throw new Error('Sign into Firebase CLI first.');
  await requireAuth({ project, ...account });
  for (const service of services) {
    current = service;
    const resource = `projects/${project}/locations/${region}/services/${service}`;
    const policy = await getIamPolicy(resource);
    policy.bindings ||= [];
    let binding = policy.bindings.find((item) => item.role === 'roles/run.invoker' && !item.condition);
    let reachable = binding?.members.includes('allUsers') === true;
    if (!reachable && apply) {
      if (binding) binding.members.push('allUsers');
      else policy.bindings.push({ role: 'roles/run.invoker', members: ['allUsers'] });
      policy.version = 3;
      await setIamPolicy(resource, policy);
      reachable = true;
    }
    console.log(JSON.stringify({ service, browserReachable: reachable }));
  }
})().catch((error) => {
  console.error(JSON.stringify({ service: current, failed: true, status: error.status || null }));
  process.exitCode = 1;
});
