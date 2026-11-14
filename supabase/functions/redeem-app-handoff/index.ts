import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders });
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "Method not allowed" });

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceRoleKey) return json(500, { error: "Server configuration is incomplete" });

  try {
    const body = await req.json();
    const code = typeof body?.code === "string" ? body.code : "";
    if (!/^[A-Za-z0-9_-]{40,60}$/.test(code)) {
      return json(400, { error: "Invalid or expired handoff code" });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const codeHash = await sha256(code);
    const now = new Date().toISOString();

    // One atomic UPDATE: only the first request can consume an unused, unexpired code.
    const { data, error } = await admin.from("app_auth_handoffs")
      .update({ consumed_at: now })
      .eq("code_hash", codeHash)
      .is("consumed_at", null)
      .gt("expires_at", now)
      .select("email, token_hash")
      .maybeSingle();

    if (error) {
      console.error("Could not redeem app handoff", error.message);
      return json(500, { error: "Could not redeem app handoff" });
    }
    if (!data) return json(410, { error: "Handoff code is expired or already used" });

    return json(200, { email: data.email, token_hash: data.token_hash });
  } catch (error) {
    console.error("redeem-app-handoff failed", error);
    return json(400, { error: "Invalid request" });
  }
});
