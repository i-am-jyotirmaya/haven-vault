// Use the Firebase CLI's normal signed-in session without printing credentials.
const { getGlobalDefaultAccount } = require('../functions/node_modules/firebase-tools/lib/auth');
const { requireAuth } = require('../functions/node_modules/firebase-tools/lib/requireAuth');
const { Client } = require('../functions/node_modules/firebase-tools/lib/apiv2');

const { project, region } = require('./config.cjs').loadConfig();

(async () => {
  const account = getGlobalDefaultAccount();
  if (!account) throw new Error('Sign into Firebase CLI before checking this project.');
  await requireAuth({ project, ...account });
  const billing = new Client({ urlPrefix: 'https://cloudbilling.googleapis.com', apiVersion: 'v1' });
  const response = await billing.get(`/projects/${project}/billingInfo`);
  console.log(JSON.stringify({ project, billingEnabled: response.body.billingEnabled === true }));
  const checks = [
    {
      name: 'functions',
      origin: 'https://cloudfunctions.googleapis.com',
      path: `/v2/projects/${project}/locations/${region}/functions`,
      select: (body) => ({ functions: (body.functions || []).map(({ name, state, serviceConfig }) => ({
        name: name.split('/').pop(), state, service: serviceConfig?.service, uri: serviceConfig?.uri,
      })) }),
    },
    {
      name: 'storage',
      origin: 'https://firebasestorage.googleapis.com',
      path: `/v1alpha/projects/${project}/defaultBucket`,
      select: (body) => ({ bucket: body.bucket?.name }),
    },
    {
      name: 'firestore',
      origin: 'https://firestore.googleapis.com',
      path: `/v1/projects/${project}/databases`,
      select: (body) => ({ databases: (body.databases || []).map(({ name, locationId, type }) => ({ name, locationId, type })) }),
    },
    {
      name: 'authentication',
      origin: 'https://identitytoolkit.googleapis.com',
      path: `/admin/v2/projects/${project}/config`,
      select: (body) => ({ authorizedDomains: body.authorizedDomains || [] }),
    },
    {
      name: 'googleSignIn',
      origin: 'https://identitytoolkit.googleapis.com',
      path: `/admin/v2/projects/${project}/defaultSupportedIdpConfigs/google.com`,
      select: (body) => ({ enabled: body.enabled === true }),
    },
  ];
  await Promise.all(checks.map(async ({ name, origin, path, select }) => {
    try {
      const client = new Client({ urlPrefix: origin });
      const result = await client.get(path, { headers: { 'x-goog-user-project': project } });
      console.log(JSON.stringify({ check: name, ...select(result.body) }));
    } catch (error) {
      // Never dump request objects, account objects, or provider configuration.
      console.log(JSON.stringify({ check: name, unavailable: true, status: error.status || error.context?.response?.statusCode || null }));
    }
  }));
})().catch(() => {
  console.error('Project billing status could not be checked. Check Firebase Console; no credentials have been printed.');
  process.exitCode = 1;
});
