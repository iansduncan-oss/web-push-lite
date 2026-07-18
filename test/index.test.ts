import { describe, it, expect, vi, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { generateVapidKeys, encryptPayload, sendWebPush } from '../src/index.js';

// ---- helpers ---------------------------------------------------------------

/** Re-implement the library's single-block HKDF so the decrypt test is independent. */
function hkdf(salt: Buffer, ikm: Buffer, info: Buffer, length: number): Buffer {
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  const okm = crypto
    .createHmac('sha256', prk)
    .update(Buffer.concat([info, Buffer.from([1])]))
    .digest();
  return okm.subarray(0, length);
}

/** A stand-in browser subscription: a real P-256 keypair + random auth secret. */
function makeClientSubscription() {
  const client = crypto.createECDH('prime256v1');
  client.generateKeys();
  const auth = crypto.randomBytes(16);
  return {
    clientPrivate: client, // kept out of the real PushSubscription; used to decrypt in tests
    subscription: {
      endpoint: 'https://push.example.com/send/abc123',
      keys: {
        p256dh: client.getPublicKey().toString('base64url'),
        auth: auth.toString('base64url'),
      },
    },
  };
}

/** Decrypt an aes128gcm (RFC 8291) block the way a browser's push service would. */
function decryptPayload(block: Buffer, client: crypto.ECDH, authB64: string): string {
  const salt = block.subarray(0, 16);
  const idlen = block[20];
  const serverPublicKey = block.subarray(21, 21 + idlen);
  const ciphertext = block.subarray(21 + idlen);

  const clientPublicKey = client.getPublicKey();
  const sharedSecret = client.computeSecret(serverPublicKey);
  const authSecret = Buffer.from(authB64, 'base64url');

  const ikmInfo = Buffer.concat([Buffer.from('WebPush: info\0'), clientPublicKey, serverPublicKey]);
  const ikm = hkdf(authSecret, sharedSecret, ikmInfo, 32);
  const cek = hkdf(salt, ikm, Buffer.from('Content-Encoding: aes128gcm\0'), 16);
  const nonce = hkdf(salt, ikm, Buffer.from('Content-Encoding: nonce\0'), 12);

  const tag = ciphertext.subarray(ciphertext.length - 16);
  const data = ciphertext.subarray(0, ciphertext.length - 16);
  const decipher = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
  decipher.setAuthTag(tag);
  const padded = Buffer.concat([decipher.update(data), decipher.final()]);
  // Strip the trailing 0x02 last-record delimiter.
  return padded.subarray(0, padded.length - 1).toString();
}

/** Verify a VAPID Authorization header's JWT signature against its public key. */
function vapidJwtIsValid(authHeader: string): boolean {
  const t = /t=([^,]+)/.exec(authHeader)![1];
  const k = /k=([^,\s]+)/.exec(authHeader)![1];
  const [headerB64, claimsB64, sigB64] = t.split('.');

  // Reconstruct the public key (uncompressed point 0x04||X||Y) as a JWK.
  const pub = Buffer.from(k, 'base64url');
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: pub.subarray(1, 33).toString('base64url'),
    y: pub.subarray(33, 65).toString('base64url'),
  };
  const keyObj = crypto.createPublicKey({ key: jwk, format: 'jwk' });

  return crypto.verify(
    'sha256',
    Buffer.from(`${headerB64}.${claimsB64}`),
    { key: keyObj, dsaEncoding: 'ieee-p1363' }, // raw r||s, as we produce
    Buffer.from(sigB64, 'base64url'),
  );
}

// ---- tests -----------------------------------------------------------------

describe('generateVapidKeys', () => {
  it('produces a 65-byte uncompressed public key and 32-byte private key', () => {
    const { publicKey, privateKey } = generateVapidKeys();
    const pub = Buffer.from(publicKey, 'base64url');
    const priv = Buffer.from(privateKey, 'base64url');
    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(0x04); // uncompressed point marker
    expect(priv.length).toBe(32);
  });

  it('produces a fresh pair each call', () => {
    expect(generateVapidKeys().privateKey).not.toBe(generateVapidKeys().privateKey);
  });
});

describe('encryptPayload', () => {
  it('round-trips: what we encrypt is what the subscriber decrypts', () => {
    const { clientPrivate, subscription } = makeClientSubscription();
    const message = JSON.stringify({ title: 'Job assigned', body: 'Tap to view', url: '/jobs/42' });

    const block = encryptPayload(message, subscription.keys.p256dh, subscription.keys.auth);
    const recovered = decryptPayload(block, clientPrivate, subscription.keys.auth);

    expect(recovered).toBe(message);
  });

  it('emits a well-formed aes128gcm header (salt + rs=4096 + 65-byte key id)', () => {
    const { subscription } = makeClientSubscription();
    const block = encryptPayload('hi', subscription.keys.p256dh, subscription.keys.auth);
    expect(block.subarray(0, 16).length).toBe(16); // salt
    expect(block.readUInt32BE(16)).toBe(4096); // record size
    expect(block[20]).toBe(65); // key id length (uncompressed point)
  });

  it('accepts a Buffer payload as well as a string', () => {
    const { clientPrivate, subscription } = makeClientSubscription();
    const block = encryptPayload(
      Buffer.from('raw-bytes'),
      subscription.keys.p256dh,
      subscription.keys.auth,
    );
    expect(decryptPayload(block, clientPrivate, subscription.keys.auth)).toBe('raw-bytes');
  });
});

describe('sendWebPush', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('signs a valid ES256 VAPID JWT and sets the RFC 8291 headers', async () => {
    const keys = generateVapidKeys();
    const { subscription } = makeClientSubscription();
    let captured: { url: string; init: RequestInit } | null = null;

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: unknown, init: RequestInit) => {
        captured = { url: String(url), init };
        return new Response(null, { status: 201 });
      }),
    );

    const res = await sendWebPush(subscription, JSON.stringify({ title: 'Hi' }), {
      vapidPublicKey: keys.publicKey,
      vapidPrivateKey: keys.privateKey,
      subject: 'mailto:ops@example.com',
      ttl: 3600,
      urgency: 'high',
      topic: 'job-42',
    });

    expect(res).toEqual({ statusCode: 201, success: true, expired: false });
    expect(captured!.url).toBe(subscription.endpoint);

    const headers = captured!.init.headers as Record<string, string>;
    expect(headers['Content-Encoding']).toBe('aes128gcm');
    expect(headers.TTL).toBe('3600');
    expect(headers.Urgency).toBe('high');
    expect(headers.Topic).toBe('job-42');
    // The signature must verify against the VAPID public key as real ES256.
    expect(vapidJwtIsValid(headers.Authorization)).toBe(true);
  });

  it('reports success for any 2xx', async () => {
    const keys = generateVapidKeys();
    const { subscription } = makeClientSubscription();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 200 })));
    const res = await sendWebPush(subscription, 'x', {
      vapidPublicKey: keys.publicKey,
      vapidPrivateKey: keys.privateKey,
      subject: 'mailto:ops@example.com',
    });
    expect(res.success).toBe(true);
    expect(res.expired).toBe(false);
  });

  it('flags expired subscriptions on 404 and 410', async () => {
    const keys = generateVapidKeys();
    const { subscription } = makeClientSubscription();
    for (const status of [404, 410]) {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status })));
      const res = await sendWebPush(subscription, 'x', {
        vapidPublicKey: keys.publicKey,
        vapidPrivateKey: keys.privateKey,
        subject: 'mailto:ops@example.com',
      });
      expect(res.expired, `status ${status}`).toBe(true);
      expect(res.success).toBe(false);
    }
  });

  it('does not set a Topic header when no topic is given', async () => {
    const keys = generateVapidKeys();
    const { subscription } = makeClientSubscription();
    let headers: Record<string, string> = {};
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: unknown, init: RequestInit) => {
        headers = init.headers as Record<string, string>;
        return new Response(null, { status: 201 });
      }),
    );
    await sendWebPush(subscription, 'x', {
      vapidPublicKey: keys.publicKey,
      vapidPrivateKey: keys.privateKey,
      subject: 'mailto:ops@example.com',
    });
    expect('Topic' in headers).toBe(false);
  });
});
