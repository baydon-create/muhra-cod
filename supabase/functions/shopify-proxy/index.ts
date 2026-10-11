// Retired: this proxy forwarded any request to the Shopify Admin API without
// authentication. The COD dashboard now uses the authenticated cod-api function.
Deno.serve(() =>
  new Response(JSON.stringify({ error: "shopify-proxy has been retired; use cod-api" }), {
    status: 410,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  })
);
