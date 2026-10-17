// Ops alert: send a push notification to the OWNER's device (never regular
// users — scoped to ALERT_USER_ID) when the pipeline degrades or halts.
// Deliberately zero-dependency (node:crypto JWT + fetch) so it works even
// when the Cluster codebase or its node_modules are the thing that's broken.
//
// Usage: node scripts/ops-alert.mjs "<title>" "<body>"
// Env:   FIREBASE_SERVICE_ACCOUNT (service-account JSON),
//        NEXT_PUBLIC_SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
//        ALERT_USER_ID (owner's user uuid in device_push_tokens)
import crypto from "node:crypto";

const [title, body] = process.argv.slice(2);
if (!title || !body) {
  console.error("usage: ops-alert.mjs <title> <body>");
  process.exit(1);
}
const { FIREBASE_SERVICE_ACCOUNT, NEXT_PUBLIC_SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, ALERT_USER_ID } = process.env;
if (!FIREBASE_SERVICE_ACCOUNT || !NEXT_PUBLIC_SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !ALERT_USER_ID) {
  console.error("ops-alert: missing env (FIREBASE_SERVICE_ACCOUNT / SUPABASE / ALERT_USER_ID) — not sending");
  process.exit(1);
}
const sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT);

// OAuth2 access token via signed JWT grant (what firebase-admin does, minus the dependency).
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const iat = Math.floor(Date.now() / 1000);
const unsigned = `${b64({ alg: "RS256", typ: "JWT" })}.${b64({
  iss: sa.client_email,
  scope: "https://www.googleapis.com/auth/firebase.messaging",
  aud: "https://oauth2.googleapis.com/token",
  iat,
  exp: iat + 3600,
})}`;
const sig = crypto.createSign("RSA-SHA256").update(unsigned).sign(sa.private_key).toString("base64url");
const tokRes = await fetch("https://oauth2.googleapis.com/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: `${unsigned}.${sig}` }),
});
const { access_token } = await tokRes.json();
if (!access_token) {
  console.error("ops-alert: oauth token exchange failed");
  process.exit(1);
}

// Owner's device tokens only.
const devRes = await fetch(
  `${NEXT_PUBLIC_SUPABASE_URL}/rest/v1/device_push_tokens?select=fcm_token&user_id=eq.${ALERT_USER_ID}`,
  { headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` } }
);
const devices = await devRes.json();
if (!Array.isArray(devices) || devices.length === 0) {
  console.error("ops-alert: no owner devices registered");
  process.exit(1);
}

let sent = 0;
for (const { fcm_token } of devices) {
  const r = await fetch(`https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`, {
    method: "POST",
    headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      message: {
        token: fcm_token,
        notification: { title, body },
        apns: {
          headers: { "apns-collapse-id": "ops-alert" },
          payload: { aps: { "interruption-level": "time-sensitive" } },
        },
      },
    }),
  });
  if (r.ok) sent += 1;
  else console.error(`ops-alert: FCM ${r.status} for one device`);
}
console.log(`ops-alert: "${title}" sent to ${sent}/${devices.length} owner device(s)`);
process.exit(sent > 0 ? 0 : 1);
