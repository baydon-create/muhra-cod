// cod-api — authenticated backend for the Muhra COD dashboard.
//
// Every request must carry the dashboard PIN in the `x-cod-pin` header. The PIN
// is checked here against edge-function secrets (never shipped to the browser),
// failed attempts are rate-limited, and only the Shopify / cod_pipeline
// operations the dashboard actually uses are allowed. Viewers are read-only.
//
// Required secrets:
//   SHOPIFY_CLIENT_ID +   Dev Dashboard app credentials. cod-api requests its own
//   SHOPIFY_CLIENT_SECRET Admin API token (client credentials grant, valid 24h)
//                         and renews it automatically.
//   SHOPIFY_ADMIN_TOKEN   Optional fallback static token, used only if the client
//                         credentials are not set or the token request fails.
//   COD_OPERATOR_PIN      PIN for the operator role (full access)
//   COD_VIEWER_PIN        PIN for the viewer role (read-only)
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

const SHOPIFY_STORE = "muhrastore-2.myshopify.com";
const SHOPIFY_API_VERSION = "2024-01";

const STATIC_TOKEN = (Deno.env.get("SHOPIFY_ADMIN_TOKEN") ?? "").trim();
const CLIENT_ID = (Deno.env.get("SHOPIFY_CLIENT_ID") ?? "").trim();
const CLIENT_SECRET = (Deno.env.get("SHOPIFY_CLIENT_SECRET") ?? "").trim();
const OPERATOR_PIN = Deno.env.get("COD_OPERATOR_PIN") ?? "";
const VIEWER_PIN = Deno.env.get("COD_VIEWER_PIN") ?? "";
const SB_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const MAX_FAILS_PER_IP = 5;      // per window
const MAX_FAILS_GLOBAL = 30;     // per window, guards against IP rotation
const FAIL_WINDOW_MIN = 15;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-cod-pin",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Expose-Headers": "X-Shopify-Link",
};

const PIPELINE_COLUMNS = new Set([
  "shopify_order_id", "order_number", "customer_name", "total_price", "created_at_shopify",
  "stage", "deposit_confirmed_at", "deposit_confirmed_by", "shipped_at", "collected_at",
  "cancelled_at", "notes", "updated_at", "delivery_attempts", "edit_flagged", "edit_note",
  "return_reason", "returned_at", "return_confirmed_at", "payment_source",
]);

type Role = "operator" | "viewer";

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

function safeEqual(a: string, b: string) {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  let diff = ea.length ^ eb.length;
  for (let i = 0; i < Math.max(ea.length, eb.length); i++) diff |= (ea[i] ?? 0) ^ (eb[i] ?? 0);
  return diff === 0;
}

function roleForPin(pin: string): Role | null {
  if (!pin) return null;
  if (OPERATOR_PIN && safeEqual(pin, OPERATOR_PIN)) return "operator";
  if (VIEWER_PIN && safeEqual(pin, VIEWER_PIN)) return "viewer";
  return null;
}

// ── Service-role PostgREST helper ────────────────────────────────────────────
async function db(path: string, init: RequestInit = {}) {
  return fetch(`${SB_URL}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: SERVICE_KEY,
      Authorization: `Bearer ${SERVICE_KEY}`,
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
}

async function countFailures(filter: string) {
  const since = new Date(Date.now() - FAIL_WINDOW_MIN * 60_000).toISOString();
  const res = await db(`cod_auth_failures?select=id&at=gte.${encodeURIComponent(since)}${filter}`, {
    method: "HEAD",
    headers: { Prefer: "count=exact" },
  });
  const range = res.headers.get("content-range") ?? "*/0";
  return Number(range.split("/")[1]) || 0;
}

async function isLockedOut(ip: string) {
  const [perIp, global] = await Promise.all([
    countFailures(`&ip=eq.${encodeURIComponent(ip)}`),
    countFailures(""),
  ]);
  return perIp >= MAX_FAILS_PER_IP || global >= MAX_FAILS_GLOBAL;
}

async function recordFailure(ip: string) {
  await db("cod_auth_failures", { method: "POST", body: JSON.stringify({ ip }) });
}

// ── Shopify access token ─────────────────────────────────────────────────────
// Client-credentials tokens expire after 24h; cache per instance and renew
// 10 minutes before expiry.
let cachedToken = "";
let cachedTokenExpiresAt = 0;
let tokenRetryAfter = 0;   // after a failed token request, wait before trying again

async function fetchClientCredentialsToken(): Promise<string> {
  const res = await fetch(`https://${SHOPIFY_STORE}/admin/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  });
  const text = await res.text();
  if (!res.ok) {
    const reason = text.match(/<title>([^<]*)<\/title>/)?.[1] ?? text.slice(0, 200);
    throw new Error(`Shopify token request failed (${res.status}): ${reason} ` +
      `[client_id ${CLIENT_ID.slice(0, 6)}… length ${CLIENT_ID.length}, secret length ${CLIENT_SECRET.length}]`);
  }
  const data = JSON.parse(text);
  if (!data.access_token) throw new Error("Shopify token response had no access_token");
  cachedToken = data.access_token;
  cachedTokenExpiresAt = Date.now() + (Number(data.expires_in) || 86_399) * 1000 - 10 * 60_000;
  return cachedToken;
}

async function getShopifyToken(forceRefresh = false): Promise<string> {
  if (CLIENT_ID && CLIENT_SECRET) {
    if (!forceRefresh && cachedToken && Date.now() < cachedTokenExpiresAt) return cachedToken;
    if (Date.now() >= tokenRetryAfter || !STATIC_TOKEN) {
      try {
        return await fetchClientCredentialsToken();
      } catch (e) {
        console.error("[cod-api]", (e as Error).message);
        tokenRetryAfter = Date.now() + 5 * 60_000;
        if (!STATIC_TOKEN) throw e;
      }
    }
  }
  return STATIC_TOKEN;
}

async function shopifyRequest(path: string, method: string, body: unknown) {
  const send = (token: string) =>
    fetch(`https://${SHOPIFY_STORE}/admin/api/${SHOPIFY_API_VERSION}/${path}`, {
      method,
      headers: { "X-Shopify-Access-Token": token, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : null,
    });
  let res = await send(await getShopifyToken());
  // A cached token may have been revoked; get a fresh one and retry once.
  if (res.status === 401 && CLIENT_ID && CLIENT_SECRET) res = await send(await getShopifyToken(true));
  return res;
}

// ── Shopify allow-list ───────────────────────────────────────────────────────
// Returns the (possibly sanitised) body to send, or null if the call is not allowed.
function checkShopifyCall(role: Role, path: string, method: string, body: any): { ok: true; body: any } | { ok: false } {
  const [rawPath] = path.split("?");
  if (rawPath.includes("..") || rawPath.includes("//")) return { ok: false };

  if (method === "GET") {
    if (rawPath === "orders.json" || rawPath === "products.json") return { ok: true, body: null };
    return { ok: false };
  }
  if (role !== "operator") return { ok: false };
  if (path.includes("?")) return { ok: false };

  const m = rawPath.match(/^orders\/(\d+)(?:\/(transactions|cancel|close|refunds|refunds\/calculate))?\.json$/);
  if (!m) return { ok: false };
  const [, orderId, sub] = m;

  if (method === "PUT" && !sub) {
    // Only the order note may be changed.
    const note = body?.order?.note;
    if (typeof note !== "string") return { ok: false };
    return { ok: true, body: { order: { id: Number(orderId), note } } };
  }
  if (method === "POST" && sub === "refunds") {
    // Dashboard only issues zero-cash "void" refunds; never move money.
    const refund = body?.refund ?? {};
    return { ok: true, body: { refund: { ...refund, transactions: [] } } };
  }
  if (method === "POST" && (sub === "transactions" || sub === "cancel" || sub === "close" || sub === "refunds/calculate")) {
    return { ok: true, body };
  }
  return { ok: false };
}

async function handleShopify(role: Role, payload: any) {
  const path = String(payload.path ?? "");
  const method = String(payload.method ?? "GET").toUpperCase();
  const check = checkShopifyCall(role, path, method, payload.body);
  if (!check.ok) return json({ error: "Operation not allowed" }, 403);

  let res: Response;
  try {
    res = await shopifyRequest(path, method, check.body);
  } catch (e) {
    return json({ error: `Could not get a Shopify access token: ${(e as Error).message}` }, 502);
  }
  // Don't pass Shopify's 401 through: the dashboard reads 401 as "wrong PIN".
  if (res.status === 401) {
    return json({ error: "Shopify rejected the access token — check the SHOPIFY_CLIENT_ID / SHOPIFY_CLIENT_SECRET secrets" }, 502);
  }
  // Shopify paginates with a Link header (page_info cursors); pass it on.
  const link = res.headers.get("link");
  return new Response(await res.text(), {
    status: res.status,
    headers: { ...CORS, "Content-Type": "application/json", ...(link ? { "X-Shopify-Link": link } : {}) },
  });
}

// Mark a pending (COD) order as paid with the GraphQL orderMarkAsPaid mutation.
async function handleMarkPaid(role: Role, payload: any) {
  if (role !== "operator") return json({ error: "View-only access" }, 403);
  const orderId = String(payload.order_id ?? "");
  if (!/^\d+$/.test(orderId)) return json({ error: "Bad order id" }, 400);
  let res: Response;
  try {
    res = await shopifyRequest(`graphql.json`, "POST", {
      query: `mutation markPaid($input: OrderMarkAsPaidInput!) {
        orderMarkAsPaid(input: $input) {
          order { id displayFinancialStatus }
          userErrors { field message }
        }
      }`,
      variables: { input: { id: `gid://shopify/Order/${orderId}` } },
    });
  } catch (e) {
    return json({ error: `Could not get a Shopify access token: ${(e as Error).message}` }, 502);
  }
  if (res.status === 401) return json({ error: "Shopify rejected the access token" }, 502);
  return new Response(await res.text(), { status: res.status, headers: { ...CORS, "Content-Type": "application/json" } });
}

// ── cod_pipeline ─────────────────────────────────────────────────────────────
function pickColumns(data: any) {
  const out: Record<string, unknown> = {};
  if (data && typeof data === "object") {
    for (const [k, v] of Object.entries(data)) if (PIPELINE_COLUMNS.has(k)) out[k] = v;
  }
  return out;
}

async function handleDb(role: Role, payload: any) {
  const op = String(payload.op ?? "");

  if (op === "select") {
    // Page through everything (PostgREST caps a single response at 1000 rows).
    const rows: unknown[] = [];
    const pageSize = 1000;
    for (let from = 0; ; from += pageSize) {
      const res = await db(`cod_pipeline?select=*&order=created_at_shopify.asc.nullsfirst,id.asc`, {
        headers: { Range: `${from}-${from + pageSize - 1}`, "Range-Unit": "items" },
      });
      if (!res.ok) return json({ error: await res.text() }, res.status);
      const batch = await res.json();
      rows.push(...batch);
      if (batch.length < pageSize) break;
    }
    return json(rows);
  }

  if (role !== "operator") return json({ error: "View-only access" }, 403);

  if (op === "insert") {
    // Accepts one record or an array of records.
    const many = Array.isArray(payload.data);
    const rows = (many ? payload.data : [payload.data]).map(pickColumns);
    if (!rows.length || rows.some((r: any) => !/^\d+$/.test(String(r.shopify_order_id ?? "")))) {
      return json({ error: "Bad order id" }, 400);
    }
    const data = many ? rows : rows[0];
    const res = await db("cod_pipeline?on_conflict=shopify_order_id", {
      method: "POST",
      headers: { Prefer: "return=representation,resolution=ignore-duplicates" },
      body: JSON.stringify(data),
    });
    return new Response(await res.text(), { status: res.status, headers: { ...CORS, "Content-Type": "application/json" } });
  }

  if (op === "update") {
    const sid = String(payload.shopify_order_id ?? "");
    if (!/^\d+$/.test(sid)) return json({ error: "Bad order id" }, 400);
    const data = pickColumns(payload.data);
    delete data.shopify_order_id;
    const res = await db(`cod_pipeline?shopify_order_id=eq.${sid}`, {
      method: "PATCH",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify(data),
    });
    return new Response(await res.text(), { status: res.status, headers: { ...CORS, "Content-Type": "application/json" } });
  }

  return json({ error: "Unknown op" }, 400);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  if (!(STATIC_TOKEN || (CLIENT_ID && CLIENT_SECRET)) || !OPERATOR_PIN || !VIEWER_PIN || !SERVICE_KEY) {
    return json({ error: "Server not configured" }, 500);
  }

  try {
    const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || "unknown";
    if (await isLockedOut(ip)) {
      return json({ error: `Too many wrong PINs. Try again in ${FAIL_WINDOW_MIN} minutes.` }, 429);
    }

    const role = roleForPin(req.headers.get("x-cod-pin") ?? "");
    if (!role) {
      await recordFailure(ip);
      return json({ error: "Incorrect PIN" }, 401);
    }

    const payload = await req.json().catch(() => ({}));
    switch (payload.action) {
      case "login":   return json({ role });
      case "shopify": return await handleShopify(role, payload);
      case "db":      return await handleDb(role, payload);
      case "markPaid": return await handleMarkPaid(role, payload);
      default:        return json({ error: "Unknown action" }, 400);
    }
  } catch (e) {
    return json({ error: (e as Error).message }, 500);
  }
});
