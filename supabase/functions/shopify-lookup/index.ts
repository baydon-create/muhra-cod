// ============================================================
// Muhra CRM — Shopify Lookup Edge Function
// Uses the GraphQL Admin API. The access token is requested with the client
// credentials grant (SHOPIFY_CLIENT_ID / SHOPIFY_CLIENT_SECRET), cached, and
// renewed before its 24h expiry. SHOPIFY_ADMIN_TOKEN is a fallback.
// Secrets: SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET, SHOPIFY_DOMAIN,
//          SHOPIFY_ADMIN_TOKEN (optional fallback)
// ============================================================
const STATIC_TOKEN  = Deno.env.get("SHOPIFY_ADMIN_TOKEN") ?? "";
const CLIENT_ID     = Deno.env.get("SHOPIFY_CLIENT_ID") ?? "";
const CLIENT_SECRET = Deno.env.get("SHOPIFY_CLIENT_SECRET") ?? "";
const DOMAIN = Deno.env.get("SHOPIFY_DOMAIN") ?? "muhrastore-2.myshopify.com";
const GQL    = `https://${DOMAIN}/admin/api/2024-10/graphql.json`;

const cors = () => ({
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
});

function json(o: unknown, status = 200) {
  return new Response(JSON.stringify(o), {
    status, headers: { "Content-Type": "application/json", ...cors() },
  });
}

// ---- Access token (client credentials, renewed 10 min before expiry) ----
let cachedToken = "";
let cachedTokenExpiresAt = 0;

async function fetchClientCredentialsToken(): Promise<string> {
  const r = await fetch(`https://${DOMAIN}/admin/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  });
  const t = await r.text();
  if (!r.ok) throw new Error(`Shopify token request failed (${r.status}): ${t.slice(0, 300)}`);
  const d = JSON.parse(t);
  if (!d.access_token) throw new Error("Shopify token response had no access_token");
  cachedToken = d.access_token;
  cachedTokenExpiresAt = Date.now() + (Number(d.expires_in) || 86_399) * 1000 - 10 * 60_000;
  return cachedToken;
}

async function getToken(forceRefresh = false): Promise<string> {
  if (CLIENT_ID && CLIENT_SECRET) {
    if (!forceRefresh && cachedToken && Date.now() < cachedTokenExpiresAt) return cachedToken;
    try {
      return await fetchClientCredentialsToken();
    } catch (e) {
      console.error("shopify-lookup token error:", String(e));
      if (!STATIC_TOKEN) throw e;
    }
  }
  return STATIC_TOKEN;
}

async function gql(query: string, variables = {}) {
  const send = (token: string) => fetch(GQL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": token,
    },
    body: JSON.stringify({ query, variables }),
  });
  let r = await send(await getToken());
  // A cached token may have been revoked; get a fresh one and retry once.
  if (r.status === 401 && CLIENT_ID && CLIENT_SECRET) r = await send(await getToken(true));
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`Shopify ${r.status}: ${t}`);
  }
  return await r.json();
}

const SEARCH_GQL = `
query searchCustomers($q: String!) {
  customers(first: 6, query: $q) {
    edges {
      node {
        id
        firstName
        lastName
        email
        phone
        numberOfOrders
        amountSpent { amount }
        createdAt
      }
    }
  }
}`;

const PROFILE_GQL = `
query getCustomer($id: ID!) {
  customer(id: $id) {
    id
    firstName
    lastName
    email
    phone
    numberOfOrders
    amountSpent { amount }
    createdAt
    orders(first: 10, sortKey: CREATED_AT, reverse: true) {
      edges {
        node {
          id
          name
          createdAt
          displayFinancialStatus
          displayFulfillmentStatus
          totalPriceSet { shopMoney { amount } }
          lineItems(first: 10) {
            edges {
              node {
                title
                variantTitle
                quantity
                originalUnitPriceSet { shopMoney { amount } }
              }
            }
          }
        }
      }
    }
  }
}`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors() });

  const url    = new URL(req.url);
  const action = url.searchParams.get("action");
  const q      = url.searchParams.get("q") ?? "";
  const id     = url.searchParams.get("id") ?? "";

  try {
    // ---- SEARCH ----
    if (action === "search") {
      if (!q) return json({ customers: [] });
      const data = await gql(SEARCH_GQL, { q });
      const customers = (data?.data?.customers?.edges ?? []).map(({ node: c }: any) => ({
        id: c.id.replace("gid://shopify/Customer/", ""),
        firstName: c.firstName ?? "",
        lastName:  c.lastName  ?? "",
        email:     c.email     ?? "",
        phone:     c.phone     ?? "",
        ordersCount: Number(c.numberOfOrders ?? 0),
        totalSpent:  c.amountSpent?.amount ?? "0",
        createdAt:   c.createdAt,
      }));
      return json({ customers });
    }

    // ---- PROFILE ----
    if (action === "profile") {
      if (!id) return json({ customer: null, orders: [] });
      const gid = id.startsWith("gid://") ? id : `gid://shopify/Customer/${id}`;
      const data = await gql(PROFILE_GQL, { id: gid });
      const c = data?.data?.customer;
      if (!c) return json({ cust: null, orders: [] });
      return json({
        cust: {
          id:          c.id.replace("gid://shopify/Customer/", ""),
          firstName:   c.firstName ?? "",
          lastName:    c.lastName  ?? "",
          email:       c.email     ?? "",
          phone:       c.phone     ?? "",
          ordersCount: Number(c.numberOfOrders ?? 0),
          totalSpent:  c.amountSpent?.amount ?? "0",
          createdAt:   c.createdAt,
        },
        orders: (c.orders?.edges ?? []).map(({ node: o }: any) => ({
          id:                o.id,
          name:              o.name,
          createdAt:         o.createdAt,
          financialStatus:   o.displayFinancialStatus,
          fulfillmentStatus: o.displayFulfillmentStatus,
          totalPrice:        o.totalPriceSet?.shopMoney?.amount ?? "0",
          lineItems: (o.lineItems?.edges ?? []).map(({ node: li }: any) => ({
            title:        li.title,
            variantTitle: li.variantTitle,
            quantity:     li.quantity,
            price:        li.originalUnitPriceSet?.shopMoney?.amount ?? "0",
          })),
        })),
      });
    }

    return json({ error: "action must be search or profile" }, 400);

  } catch (e) {
    console.error("shopify-lookup error:", String(e));
    return json({ error: String(e) }, 500);
  }
});
