/**
 * web-push-lite — a zero-dependency Web Push sender for Node.js.
 *
 * Sends VAPID-authenticated Web Push notifications using only the built-in
 * `node:crypto` module — no native addons, no `web-push` dependency tree. It
 * mints the VAPID JWT (ES256), encrypts the payload per RFC 8291 (aes128gcm),
 * and POSTs it to the push service with Node's global `fetch`.
 */

import crypto from 'node:crypto';

/** The subscription object a browser produces via `PushManager.subscribe()`. */
export interface PushSubscription {
  endpoint: string;
  keys: {
    /** The client's P-256 public key (base64url). */
    p256dh: string;
    /** The client's auth secret (base64url). */
    auth: string;
  };
}

/** A VAPID application-server key pair (both base64url-encoded). */
export interface VapidKeys {
  /** Uncompressed P-256 public key, 65 bytes → 87 base64url chars. */
  publicKey: string;
  /** P-256 private scalar, 32 bytes → 43 base64url chars. */
  privateKey: string;
}

export interface WebPushOptions {
  /** VAPID public key (base64url). Get one from `generateVapidKeys()`. */
  vapidPublicKey: string;
  /** VAPID private key (base64url). Keep this secret. */
  vapidPrivateKey: string;
  /**
   * VAPID `sub` claim — a `mailto:` or `https:` URL identifying you, the
   * application-server operator, so a push service can contact you. Required
   * by the VAPID spec.
   */
  subject: string;
  /** Seconds the push service should retain an undelivered message. Default 86400 (24h). */
  ttl?: number;
  /** Delivery urgency hint. Default `'normal'`. */
  urgency?: 'very-low' | 'low' | 'normal' | 'high';
  /** Optional `Topic` header — a later push with the same topic replaces this one. */
  topic?: string;
  /** Abort signal. Defaults to a 10-second timeout when omitted. */
  signal?: AbortSignal;
}

export interface WebPushResult {
  /** HTTP status returned by the push service. */
  statusCode: number;
  /** True when the push service accepted the message (2xx). */
  success: boolean;
  /**
   * True when the push service reports the subscription is gone (404/410).
   * The caller should stop sending to — and typically delete — this
   * subscription.
   */
  expired: boolean;
}

/**
 * Generate a fresh VAPID key pair. Store the pair once and reuse it: the public
 * key is handed to the browser at `subscribe()` time and must stay stable, and
 * the private key signs every push.
 */
export function generateVapidKeys(): VapidKeys {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return {
    publicKey: ecdh.getPublicKey().toString('base64url'),
    privateKey: ecdh.getPrivateKey().toString('base64url'),
  };
}

/**
 * Send a single Web Push notification.
 *
 * @param subscription The browser's push subscription.
 * @param payload      The message body delivered to the service worker. A
 *                     string or Buffer is sent as-is; pass `JSON.stringify(obj)`
 *                     for structured data.
 * @param options      VAPID keys, contact `subject`, and delivery hints.
 * @returns            The push service's status, plus `expired` when the
 *                     subscription should be pruned.
 */
export async function sendWebPush(
  subscription: PushSubscription,
  payload: string | Buffer,
  options: WebPushOptions,
): Promise<WebPushResult> {
  const endpoint = new URL(subscription.endpoint);

  const jwt = signVapidJwt(endpoint, options.subject, options.vapidPrivateKey);
  const body = encryptPayload(payload, subscription.keys.p256dh, subscription.keys.auth);

  const headers: Record<string, string> = {
    Authorization: `vapid t=${jwt}, k=${options.vapidPublicKey}`,
    'Content-Type': 'application/octet-stream',
    'Content-Encoding': 'aes128gcm',
    'Content-Length': String(body.length),
    TTL: String(options.ttl ?? 86400),
    Urgency: options.urgency ?? 'normal',
  };
  if (options.topic) headers.Topic = options.topic;

  const res = await fetch(subscription.endpoint, {
    method: 'POST',
    headers,
    body,
    signal: options.signal ?? AbortSignal.timeout(10000),
  });

  return {
    statusCode: res.status,
    success: res.status >= 200 && res.status < 300,
    expired: res.status === 404 || res.status === 410,
  };
}

/**
 * Encrypt a push payload with the `aes128gcm` content encoding (RFC 8291).
 * Exported for advanced callers; `sendWebPush()` uses it internally.
 */
export function encryptPayload(
  payload: string | Buffer,
  p256dhB64: string,
  authB64: string,
): Buffer {
  const clientPublicKey = Buffer.from(p256dhB64, 'base64url');
  const authSecret = Buffer.from(authB64, 'base64url');
  const plaintext = typeof payload === 'string' ? Buffer.from(payload) : payload;

  // Ephemeral server ECDH key pair + shared secret.
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const serverPublicKey = ecdh.getPublicKey();
  const sharedSecret = ecdh.computeSecret(clientPublicKey);

  // HKDF to the input keying material, then to the content-encryption key + nonce.
  const ikmInfo = Buffer.concat([Buffer.from('WebPush: info\0'), clientPublicKey, serverPublicKey]);
  const ikm = hkdf(authSecret, sharedSecret, ikmInfo, 32);

  const salt = crypto.randomBytes(16);
  const cek = hkdf(salt, ikm, Buffer.from('Content-Encoding: aes128gcm\0'), 16);
  const nonce = hkdf(salt, ikm, Buffer.from('Content-Encoding: nonce\0'), 12);

  // Records carry a single 0x02 delimiter (last-record marker) before encryption.
  const padded = Buffer.concat([plaintext, Buffer.from([2])]);
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const encrypted = Buffer.concat([cipher.update(padded), cipher.final(), cipher.getAuthTag()]);

  // aes128gcm header: salt(16) + rs(4) + idlen(1) + keyid(65) + ciphertext.
  const rs = Buffer.alloc(4);
  rs.writeUInt32BE(4096);
  const idlen = Buffer.from([serverPublicKey.length]);

  return Buffer.concat([salt, rs, idlen, serverPublicKey, encrypted]);
}

/** Build and sign the VAPID JWT (ES256) for a push endpoint. */
function signVapidJwt(endpoint: URL, subject: string, vapidPrivateKey: string): string {
  const header = { typ: 'JWT', alg: 'ES256' };
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    aud: `${endpoint.protocol}//${endpoint.host}`,
    exp: now + 43200, // 12 hours; push services reject > 24h.
    sub: subject,
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const claimsB64 = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const unsigned = `${headerB64}.${claimsB64}`;

  // Wrap the raw 32-byte private scalar in the fixed PKCS#8 prefix for a
  // P-256 key so node:crypto can load it without the public half.
  const privKeyBuffer = Buffer.from(vapidPrivateKey, 'base64url');
  const keyObj = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from(
        '308141020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420',
        'hex',
      ),
      privKeyBuffer,
    ]),
    format: 'der',
    type: 'pkcs8',
  });

  // ES256 = ECDSA P-256 with SHA-256, signature as raw r||s (64 bytes).
  const sig = crypto.sign('sha256', Buffer.from(unsigned), keyObj);
  const sigB64 = Buffer.from(derToRaw(sig)).toString('base64url');
  return `${unsigned}.${sigB64}`;
}

/** HMAC-based HKDF (single-block; sufficient for the ≤32-byte outputs here). */
function hkdf(salt: Buffer, ikm: Buffer, info: Buffer, length: number): Buffer {
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  const okm = crypto
    .createHmac('sha256', prk)
    .update(Buffer.concat([info, Buffer.from([1])]))
    .digest();
  return okm.subarray(0, length);
}

/** Convert an ASN.1/DER ECDSA signature to the fixed-width r||s (64-byte) form. */
function derToRaw(derSig: Buffer): Buffer {
  // DER: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
  let offset = 2;
  const rLen = derSig[offset + 1];
  const r = derSig.subarray(offset + 2, offset + 2 + rLen);
  offset = offset + 2 + rLen;
  const sLen = derSig[offset + 1];
  const s = derSig.subarray(offset + 2, offset + 2 + sLen);

  const rPad = Buffer.alloc(32);
  r.copy(rPad, Math.max(0, 32 - r.length), Math.max(0, r.length - 32));
  const sPad = Buffer.alloc(32);
  s.copy(sPad, Math.max(0, 32 - s.length), Math.max(0, s.length - 32));

  return Buffer.concat([rPad, sPad]);
}
