// cod-api — authenticated backend for the Muhra COD dashboard.
//
// Every request must carry the dashboard PIN in the `x-cod-pin` header. The PIN
// is checked here against edge-function secrets (never shipped to the browser),
// failed attempts are rate-limited, and only the Shopify / cod_pipeline
// operations the dashboard actually uses are allowed. Viewers are read-only.
//
// Required secrets:
//   SHOPIFY_ADMIN_TOKEN   Shopify Admin API access token
//   COD_OPERATOR_PIN      PIN for the operator role (full access)
//   COD_VIEWER_PIN        PIN for the viewer role (read-only)
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

const SHOPIFY_STORE = "muhrastore-2.myshopify.com";
const SHOPIFY_API_VERSION = "2024-01";

const SHOPIFY_TOKEN = Deno.env.get("SHOPIFY_ADMIN_TOKEN") ?? "";
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

  const m = rawPath.match(/^orders\/(\d+)(?:\/(transactions|cancel|refunds|refunds\/calculate))?\.json$/);
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
  if (method === "POST" && (sub === "transactions" || sub === "cancel" || sub === "refunds/calculate")) {
    return { ok: true, body };
  }
  return { ok: false };
}

async function handleShopify(role: Role, payload: any) {
  const path = String(payload.path ?? "");
  const method = String(payload.method ?? "GET").toUpperCase();
  const check = checkShopifyCall(role, path, method, payload.body);
  if (!check.ok) return json({ error: "Operation not allowed" }, 403);

  const res = await fetch(`https://${SHOPIFY_STORE}/admin/api/${SHOPIFY_API_VERSION}/${path}`, {
    method,
    headers: { "X-Shopify-Access-Token": SHOPIFY_TOKEN, "Content-Type": "application/json" },
    body: check.body ? JSON.stringify(check.body) : null,
  });
  return new Response(await res.text(), {
    status: res.status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
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
    const data = pickColumns(payload.data);
    if (!/^\d+$/.test(String(data.shopify_order_id ?? ""))) return json({ error: "Bad order id" }, 400);
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
  if (!SHOPIFY_TOKEN || !OPERATOR_PIN || !VIEWER_PIN || !SERVICE_KEY) {
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
      default:        return json({ error: "Unknown action" }, 400);
    }
  } catch (e) {
    return json({ error: (e as Error).message }, 500);
  }
});
