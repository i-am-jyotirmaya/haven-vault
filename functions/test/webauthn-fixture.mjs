import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { encodeCBOR } from '@levischuck/tiny-cbor';
const hash = bytes => createHash('sha256').update(bytes).digest();
const b64 = bytes => Buffer.from(bytes).toString('base64url');
export function authenticator() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const rawId = randomBytes(32), id = b64(rawId);
  const cose = encodeCBOR(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
  let count = 0;
  const client = (type, challenge) => Buffer.from(JSON.stringify({ type, challenge, origin: 'http://localhost:5173', crossOrigin: false }));
  const authData = (flags, n) => { const counter = Buffer.alloc(4); counter.writeUInt32BE(n); return Buffer.concat([hash('localhost'), Buffer.from([flags]), counter]); };
  return { id,
    registration(challenge) {
      const length = Buffer.alloc(2); length.writeUInt16BE(rawId.length);
      const data = Buffer.concat([authData(0x45, 0), Buffer.alloc(16), length, rawId, cose]);
      return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'cross-platform', response: { clientDataJSON: b64(client('webauthn.create', challenge)), attestationObject: b64(encodeCBOR(new Map([['fmt', 'none'], ['authData', data], ['attStmt', new Map()]]))), transports: ['usb'] } };
    },
    authentication(challenge, userHandle) {
      const c = client('webauthn.get', challenge), data = authData(0x05, ++count);
      return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64(c), authenticatorData: b64(data), userHandle, signature: b64(sign('sha256', Buffer.concat([data, hash(c)]), privateKey)) } };
    },
  };
}
