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

function base64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "Method not allowed" });

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const authorization = req.headers.get("Authorization");

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    return json(500, { error: "Server configuration is incomplete" });
  }
  if (!authorization) return json(401, { error: "Authentication required" });

  try {
    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authorization } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: userData, error: userError } = await userClient.auth.getUser();
    const user = userData?.user;
    if (userError || !user || !user.email) return json(401, { error: "Valid user session required" });

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: linkData, error: linkError } = await admin.auth.admin.generateLink({
      type: "magiclink",
      email: user.email,
    });
    const tokenHash = linkData?.properties?.hashed_token;
    if (linkError || !tokenHash) {
      console.error("Could not create app handoff magic link", linkError?.message);
      return json(500, { error: "Could not create a one-time sign-in credential" });
    }

    const random = new Uint8Array(32);
    crypto.getRandomValues(random);
    const code = base64Url(random);
    const codeHash = await sha256(code);
    const expiresAt = new Date(Date.now() + 90 * 1000).toISOString();

    const { error: insertError } = await admin.from("app_auth_handoffs").insert({
      code_hash: codeHash,
      user_id: user.id,
      email: user.email,
      token_hash: tokenHash,
      expires_at: expiresAt,
    });
    if (insertError) {
      console.error("Could not store app handoff", insertError.message);
      return json(500, { error: "Could not create app handoff" });
    }

    return json(200, { code, expires_in: 90 });
  } catch (error) {
    console.error("create-app-handoff failed", error);
    return json(500, { error: "Could not create app handoff" });
  }
});
