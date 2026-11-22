// Supabase Edge Function: cinetrack-access
// Actions:
//   bootstrap-owner: first device claims Umb using BOOTSTRAP_SECRET
//   create-invite: Umb creates one-time Lu invite
//   redeem-invite: Lu redeems invite and becomes a member
//
// Required Edge Function secrets:
//   SUPABASE_URL
//   SUPABASE_ANON_KEY
//   SUPABASE_SERVICE_ROLE_KEY   (server-side only; NEVER put in the PWA)
//   CINETRACK_BOOTSTRAP_SECRET  (long random one-time setup secret)
//
// Deploy with Supabase CLI. The function validates the caller's Supabase JWT.
// CORS is open for the GitHub Pages origin; tighten ALLOWED_ORIGIN before deploy.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const BOOTSTRAP_SECRET = Deno.env.get("CINETRACK_BOOTSTRAP_SECRET")!;
const ALLOWED_ORIGIN = Deno.env.get("CINETRACK_ALLOWED_ORIGIN") ?? "https://huberio.github.io";

const corsHeaders = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return json({ error: "Missing session" }, 401);

  const userClient = createClient(SUPABASE_URL, ANON_KEY, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: userData, error: userError } = await userClient.auth.getUser();
  if (userError || !userData.user) return json({ error: "Invalid session" }, 401);
  const userId = userData.user.id;

  let body: { action?: string; bootstrapSecret?: string; code?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  if (body.action === "bootstrap-owner") {
    if (!BOOTSTRAP_SECRET || body.bootstrapSecret !== BOOTSTRAP_SECRET) {
      return json({ error: "Invalid bootstrap secret" }, 403);
    }
    const { count, error: countError } = await admin
      .from("cinetrack_members").select("*", { count: "exact", head: true });
    if (countError) return json({ error: "Could not check initial owner" }, 500);
    if ((count ?? 0) !== 0) return json({ error: "Owner already initialized" }, 409);

    const { error } = await admin.from("cinetrack_members").insert({
      user_id: userId, display_name: "Umb", role: "owner",
    });
    if (error) return json({ error: "Could not create owner" }, 500);
    return json({ ok: true, member: "Umb" });
  }

  if (body.action === "create-invite") {
    const { data: member } = await admin.from("cinetrack_members")
      .select("display_name,role").eq("user_id", userId).maybeSingle();
    if (!member || member.role !== "owner" || member.display_name !== "Umb") {
      return json({ error: "Only Umb can create invitations" }, 403);
    }
    const { count, error: countError } = await admin
      .from("cinetrack_members").select("*", { count: "exact", head: true });
    if (countError) return json({ error: "Could not check members" }, 500);
    if ((count ?? 0) >= 2) return json({ error: "Both member slots are occupied" }, 409);

    const codeBytes = crypto.getRandomValues(new Uint8Array(18));
    const code = [...codeBytes].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    const codeHash = await sha256(code);
    const { error } = await admin.from("cinetrack_invites").insert({
      code_hash: codeHash,
      created_by: userId,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    });
    if (error) return json({ error: "Could not create invitation" }, 500);
    return json({ ok: true, code, expiresInHours: 24 });
  }

  if (body.action === "redeem-invite") {
    const code = (body.code ?? "").replace(/[^0-9A-F]/gi, "").toUpperCase();
    if (code.length !== 36) return json({ error: "Invalid invitation code" }, 400);

    const { count, error: countError } = await admin
      .from("cinetrack_members").select("*", { count: "exact", head: true });
    if (countError) return json({ error: "Could not check members" }, 500);
    if ((count ?? 0) >= 2) return json({ error: "CineTrack already has two members" }, 409);

    const codeHash = await sha256(code);
    const { data: invite, error: inviteError } = await admin.from("cinetrack_invites")
      .select("code_hash,expires_at,redeemed_at")
      .eq("code_hash", codeHash).maybeSingle();
    if (inviteError || !invite || invite.redeemed_at ||
        new Date(invite.expires_at).getTime() < Date.now()) {
      return json({ error: "Invitation invalid, expired or already used" }, 403);
    }

    // Claim atomically: update only if still unused and unexpired.
    const { data: claimed, error: claimError } = await admin.from("cinetrack_invites")
      .update({ redeemed_by: userId, redeemed_at: new Date().toISOString() })
      .eq("code_hash", codeHash).is("redeemed_at", null)
      .gt("expires_at", new Date().toISOString())
      .select("code_hash").maybeSingle();
    if (claimError || !claimed) return json({ error: "Invitation was already used" }, 409);

    const { error: memberError } = await admin.from("cinetrack_members").insert({
      user_id: userId, display_name: "Lu", role: "member",
    });
    if (memberError) {
      // Revert the claim if membership insert failed.
      await admin.from("cinetrack_invites").update({ redeemed_by: null, redeemed_at: null })
        .eq("code_hash", codeHash).eq("redeemed_by", userId);
      return json({ error: "Could not create Lu member" }, 500);
    }
    return json({ ok: true, member: "Lu" });
  }

  return json({ error: "Unknown action" }, 400);
});
