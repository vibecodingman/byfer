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

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "Method not allowed" });

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anonKey || !serviceRoleKey) return json(500, { error: "Server configuration is incomplete" });

  try {
    const body = await req.json();
    const username = typeof body?.username === "string" ? body.username.trim().toLowerCase() : "";
    const password = typeof body?.password === "string" ? body.password : "";
    if (!/^[a-z0-9_.]{3,24}$/.test(username) || password.length < 8 || password.length > 128) {
      return json(400, { error: "Неверный username или пароль" });
    }

    const admin = createClient(url, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: profile, error: profileError } = await admin
      .from("profiles").select("id,password_login_enabled")
      .eq("username", username).maybeSingle();

    if (profileError || !profile || !profile.password_login_enabled) {
      return json(401, { error: "Неверный username или пароль" });
    }

    const { data: userData, error: userError } = await admin.auth.admin.getUserById(profile.id);
    const email = userData?.user?.email;
    if (userError || !email) return json(401, { error: "Неверный username или пароль" });

    const authClient = createClient(url, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data, error } = await authClient.auth.signInWithPassword({ email, password });
    if (error || !data.session) return json(401, { error: "Неверный username или пароль" });

    return json(200, {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
    });
  } catch (error) {
    console.error("username-login failed", error);
    return json(400, { error: "Не удалось выполнить вход" });
  }
});
