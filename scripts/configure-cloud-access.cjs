// Run without arguments to inspect; --apply enables only the vault's required access.
// Uses the Firebase CLI session. Never prints credentials or complete API responses.
const { getGlobalDefaultAccount } = require('../functions/node_modules/firebase-tools/lib/auth');
const { requireAuth } = require('../functions/node_modules/firebase-tools/lib/requireAuth');
const { Client } = require('../functions/node_modules/firebase-tools/lib/apiv2');
const { check, ensure } = require('../functions/node_modules/firebase-tools/lib/ensureApiEnabled');
const { serviceAccountHasRoles, addServiceAccountToRoles, getServiceAccountRoles } = require('../functions/node_modules/firebase-tools/lib/gcp/resourceManager');

const { project, projectNumber, bucket, origin, region } = require('./config.cjs').loadConfig();
const apply = process.argv.includes('--apply');
let step = 'authenticate';
const report = (check, state) => console.log(JSON.stringify({ check, ...state }));
const normalizeCors = (rules) => JSON.stringify(rules.map((rule) => ({
  origin: [...(rule.origin || [])].sort(),
  method: [...(rule.method || [])].sort(),
  responseHeader: [...(rule.responseHeader || [])].sort(),
  maxAgeSeconds: rule.maxAgeSeconds,
})).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))));

(async () => {
  const account = getGlobalDefaultAccount();
  if (!account) throw new Error('Sign into Firebase CLI first.');
  await requireAuth({ project, ...account });

  step = 'project identity';
  const resourceManager = new Client({ urlPrefix: 'https://cloudresourcemanager.googleapis.com', apiVersion: 'v1' });
  const projectInfo = (await resourceManager.get(`/projects/${project}`)).body;
  if (String(projectInfo.projectNumber) !== projectNumber) throw new Error('Project number does not match project ID.');
  report(step, { project, projectNumber });

  step = 'runtime account';
  const functions = new Client({ urlPrefix: 'https://cloudfunctions.googleapis.com', apiVersion: 'v2' });
  const result = await functions.get(`/projects/${project}/locations/${region}/functions/verifyAuthentication`);
  const runtime = result.body.serviceConfig?.serviceAccountEmail;
  if (runtime !== `${projectNumber}-compute@developer.gserviceaccount.com` &&
      !runtime?.endsWith(`@${project}.iam.gserviceaccount.com`)) {
    throw new Error('Unexpected runtime service account; review before changing IAM.');
  }
  report(step, { serviceAccount: runtime, state: result.body.state });

  step = 'IAM Credentials API';
  const api = 'iamcredentials.googleapis.com';
  let enabled = await check(project, api, 'vault', true);
  if (!enabled && apply) {
    await ensure(project, api, 'vault', true);
    enabled = true;
  }
  report(step, { enabled });

  step = 'runtime token signing';
  const iam = new Client({ urlPrefix: 'https://iam.googleapis.com', apiVersion: 'v1' });
  const resource = `/projects/${project}/serviceAccounts/${runtime}`;
  const policyResult = await iam.post(`${resource}:getIamPolicy`, undefined, {
    queryParams: { 'options.requestedPolicyVersion': 3 },
  });
  const policy = policyResult.body;
  const role = 'roles/iam.serviceAccountTokenCreator';
  const member = `serviceAccount:${runtime}`;
  policy.bindings ||= [];
  let binding = policy.bindings.find((item) => item.role === role && !item.condition);
  let granted = binding?.members.includes(member) === true;
  if (!granted && apply) {
    if (binding) binding.members.push(member);
    else policy.bindings.push({ role, members: [member] });
    await iam.post(`${resource}:setIamPolicy`, { policy });
    granted = true;
  }
  report(step, { granted, scope: 'runtime service account only' });

  step = 'runtime Firestore access';
  const runtimeRoles = await getServiceAccountRoles(project, runtime);
  let canUseFirestore = ['roles/datastore.user', 'roles/editor', 'roles/owner'].some((role) => runtimeRoles.includes(role));
  if (!canUseFirestore && apply) {
    await addServiceAccountToRoles(project, runtime, ['roles/datastore.user'], true);
    canUseFirestore = true;
  }
  report(step, { granted: canUseFirestore });

  step = 'storage session lookups';
  const storageAgent = `service-${projectNumber}@gcp-sa-firebasestorage.iam.gserviceaccount.com`;
  const storageRole = 'roles/firebaserules.firestoreServiceAgent';
  let linked = await serviceAccountHasRoles(project, storageAgent, [storageRole], true);
  if (!linked && apply) {
    await addServiceAccountToRoles(project, storageAgent, [storageRole], true);
    linked = true;
  }
  report(step, { granted: linked });

  step = 'storage CORS';
  const storage = new Client({ urlPrefix: 'https://storage.googleapis.com', apiVersion: 'storage/v1' });
  const metadata = (await storage.get(`/b/${bucket}`)).body;
  const desired = [{ origin: [origin], method: ['GET', 'HEAD', 'OPTIONS'], responseHeader: ['Content-Type', 'Authorization'], maxAgeSeconds: 3600 }];
  // This is a dedicated vault bucket. Only its canonical origin is configured.
  let matches = normalizeCors(metadata.cors || []) === normalizeCors(desired);
  if (!matches && apply) {
    await storage.patch(`/b/${bucket}`, { cors: desired }, {
      queryParams: { ifMetagenerationMatch: metadata.metageneration },
    });
    matches = true;
  }
  report(step, { configured: matches });
})().catch((error) => {
  report(step, { failed: true, status: error.status || error.context?.response?.statusCode || null });
  console.error('Cloud access configuration stopped. No credentials have been printed.');
  process.exitCode = 1;
});
