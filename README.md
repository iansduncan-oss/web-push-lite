# web-push-lite

Send [Web Push](https://developer.mozilla.org/en-US/docs/Web/API/Push_API) notifications from Node.js with **zero runtime dependencies**. It mints the VAPID JWT (ES256) and encrypts the payload per [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291) (`aes128gcm`) using only the built-in `node:crypto` module — no native addons, no transitive dependency tree to audit.

```ts
import { generateVapidKeys, sendWebPush } from 'web-push-lite';

// One-time: generate a key pair and store it.
const keys = generateVapidKeys();

// Per notification:
const result = await sendWebPush(
  subscription, // the PushSubscription JSON from the browser
  JSON.stringify({ title: 'Job assigned', body: 'Tap to view', url: '/jobs/42' }),
  {
    vapidPublicKey: keys.publicKey,
    vapidPrivateKey: keys.privateKey,
    subject: 'mailto:you@example.com',
  },
);

if (result.expired) {
  // 404/410 — the subscription is gone; delete it from your store.
}
```

## Why

The de-facto library, [`web-push`](https://www.npmjs.com/package/web-push), pulls in a chain of dependencies (`https-proxy-agent`, `jws`, `asn1.js`, …) for what is, at core, a JWT signature and an ECDH+AES-GCM encryption — both of which Node's standard library already does. `web-push-lite` is that core, and nothing else:

- **Zero runtime dependencies.** Nothing to audit, nothing to get a CVE.
- **Just `node:crypto`.** No `node-gyp`, no prebuilt binaries.
- **One small surface** you can read in a single sitting.

If you send a handful of notification types from your own server, this is likely all you need.

## Install

```sh
npm install web-push-lite
```

Requires Node.js **20+** (uses the global `fetch` and `AbortSignal.timeout`).

## API

### `generateVapidKeys(): { publicKey, privateKey }`

Generate a VAPID application-server key pair, both base64url-encoded. Generate it **once**, store both halves, and reuse them: the public key is handed to the browser when it calls `pushManager.subscribe({ applicationServerKey })` and must stay stable, while the private key signs every push.

```ts
const { publicKey, privateKey } = generateVapidKeys();
```

### `sendWebPush(subscription, payload, options): Promise<WebPushResult>`

Send one notification.

- **`subscription`** — the `PushSubscription` object serialized by the browser: `{ endpoint, keys: { p256dh, auth } }`.
- **`payload`** — a `string` or `Buffer` delivered to your service worker's `push` event. Pass `JSON.stringify(obj)` for structured data.
- **`options`**:

  | Field | Required | Default | Notes |
  |---|---|---|---|
  | `vapidPublicKey` | ✓ | — | base64url, from `generateVapidKeys()` |
  | `vapidPrivateKey` | ✓ | — | base64url; keep secret |
  | `subject` | ✓ | — | `mailto:` or `https:` URL identifying you (VAPID `sub` claim) |
  | `ttl` | | `86400` | seconds the push service retains an undelivered message |
  | `urgency` | | `'normal'` | `'very-low' \| 'low' \| 'normal' \| 'high'` |
  | `topic` | | — | later push with the same topic replaces this one |
  | `signal` | | 10s timeout | your own `AbortSignal` |

Returns:

```ts
interface WebPushResult {
  statusCode: number; // the push service's HTTP status
  success: boolean;   // 2xx
  expired: boolean;   // 404/410 — subscription gone, delete it
}
```

`sendWebPush` only throws on a network/transport error (or your `signal` aborting). A push service rejecting the message is reported via `statusCode`/`success`, not thrown — so a single dead subscription never crashes a fan-out loop.

#### Fanning out to many subscribers

The library sends one message; you own the loop and your subscription store:

```ts
for (const sub of subscriptions) {
  const { expired } = await sendWebPush(sub, payload, opts).catch(() => ({ expired: false }));
  if (expired) await db.deleteSubscription(sub.endpoint);
}
```

### `encryptPayload(payload, p256dh, auth): Buffer`

The RFC 8291 `aes128gcm` encryption `sendWebPush` uses internally, exported for advanced callers who build the HTTP request themselves.

## How it works

1. **VAPID JWT** — an ES256 (ECDSA P-256 + SHA-256) JWT is signed with your private key, asserting the push endpoint's origin as the audience and your `subject` as contact. Sent in the `Authorization: vapid t=…, k=…` header.
2. **Payload encryption** — an ephemeral ECDH key agreement with the subscriber's `p256dh` key derives, via HKDF, a content-encryption key and nonce; the payload is sealed with AES-128-GCM and framed with the `aes128gcm` content-coding header (salt, record size, and the ephemeral public key).
3. **Delivery** — a single `POST` to `subscription.endpoint` with the encrypted body and the standard `TTL` / `Urgency` / `Content-Encoding` headers.

Every step is covered by tests that verify against the standard: the JWT is checked with an independent ES256 verification, and the encrypted payload is decrypted back to the original plaintext exactly as a browser's push service would.

## Limitations & scope

- **Sends; doesn't store.** Managing subscriptions (persisting them, pruning `expired` ones) is your application's job — see the fan-out example.
- **`aes128gcm` only.** This is the modern encoding every current browser supports. The legacy `aesgcm`/`aesgcm128` encodings are intentionally not implemented.
- **No VAPID key persistence.** `generateVapidKeys()` returns a pair; storing it is up to you.
- **One dependency-free HTTP send.** It uses Node's global `fetch`; there's no built-in retry or proxy support — wrap the call if you need those.

## License

MIT © Ian Duncan
