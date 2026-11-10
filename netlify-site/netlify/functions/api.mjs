// API de « Mes films » (Netlify Functions v2 + Netlify Blobs)
//   GET  /api/catalog            catalogue public de l'admin
//   PUT  /api/catalog            (en-tête x-admin-code = variable ADMIN_CODE)
//   POST /api/signup | /api/login   {pseudo, password} -> {token, pseudo, name}
//   GET  /api/profiles           profils publics (pseudo, nombre de films, titres vus)
//   GET  /api/profile/:pseudo    films d'un profil public (ou le sien, avec son jeton)
//   PUT  /api/password           change son mot de passe (jeton requis)
//   POST /api/admin              gestion des profils (en-tête x-admin-code) : list, approve, delete, newcode, settings
//   PUT|POST /api/me             enregistre les films de son propre profil (jeton requis)
import { getStore } from "@netlify/blobs";
import { randomBytes, randomInt, scryptSync, timingSafeEqual, createHmac, createHash, createCipheriv, createDecipheriv } from "node:crypto";

const HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: HEADERS });
const PSEUDO = /^[\p{L}\p{N}_-]{3,20}$/u;   // lettres (accents compris), chiffres, - et _
const MAX_BYTES = 4_500_000;

/* Jeton de session : « pseudo.expiration.signature », signé avec un secret généré une fois et gardé dans Blobs. */
async function secret() {
  const st = getStore("config");
  let s = await st.get("secret");
  if (!s) { s = randomBytes(32).toString("hex"); await st.set("secret", s); }
  return s;
}
const sign = (sec, payload) => createHmac("sha256", sec).update(payload).digest("base64url");
async function makeToken(pseudo) {
  const payload = `${pseudo}.${Date.now() + 30 * 864e5}`;
  return `${payload}.${sign(await secret(), payload)}`;
}
async function readToken(token) {
  const [pseudo, exp, sig] = String(token || "").split(".");
  if (!pseudo || !exp || !sig) return null;
  const good = Buffer.from(sign(await secret(), `${pseudo}.${exp}`)), got = Buffer.from(sig);
  return good.length === got.length && timingSafeEqual(good, got) && Number(exp) > Date.now() ? pseudo : null;
}
/* Code de secours à 10 chiffres : chiffré en AES-256-GCM (clé dérivée du secret serveur) pour que l'admin puisse le relire. */
const newCode = () => String(randomInt(0, 1e10)).padStart(10, "0");
async function codeKey() { return createHash("sha256").update((await secret()) + "|code").digest(); }
async function encCode(code) {
  const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", await codeKey(), iv);
  const ct = Buffer.concat([c.update(code, "utf8"), c.final()]);
  return [iv, c.getAuthTag(), ct].map((b) => b.toString("hex")).join(".");
}
async function decCode(str) {
  try {
    const [iv, tag, ct] = String(str || "").split(".").map((h) => Buffer.from(h, "hex"));
    const d = createDecipheriv("aes-256-gcm", await codeKey(), iv); d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
  } catch { return null; }
}
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
async function getSettings() {
  return { signups: "open", max: 20, ...((await getStore("config").get("settings", { type: "json" })) || {}) };
}
const hashPw = (pw, salt) => scryptSync(pw, salt, 64).toString("hex");
const bearer = (req, body) => (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "") || body?.token;

export default async (req) => {
  const url = new URL(req.url), path = url.pathname.replace(/\/+$/, ""), method = req.method;
  const users = getStore("users"), profiles = getStore("profiles");

  /* ----- catalogue de l'admin ----- */
  if (path === "/api/catalog") {
    const store = getStore("catalog");
    if (method === "GET") return json((await store.get("catalog", { type: "json" })) ?? null);
    if (method === "PUT") {
      const code = process.env.ADMIN_CODE;
      if (!code) return json({ error: "ADMIN_CODE non défini sur Netlify" }, 500);
      if (req.headers.get("x-admin-code") !== code) return json({ error: "code invalide" }, 401);
      let body; try { body = await req.json(); } catch { return json({ error: "JSON invalide" }, 400); }
      if (!body || !Array.isArray(body.films)) return json({ error: "catalogue invalide" }, 400);
      await store.setJSON("catalog", body);
      return json({ ok: true });
    }
    return json({ error: "méthode non autorisée" }, 405);
  }

  /* ----- inscription / connexion ----- */
  if ((path === "/api/signup" || path === "/api/login") && method === "POST") {
    let b; try { b = await req.json(); } catch { return json({ error: "JSON invalide" }, 400); }
    const name = String(b?.pseudo || "").trim().normalize("NFC"), pseudo = name.toLowerCase(), password = String(b?.password || "");
    if (!PSEUDO.test(pseudo)) return json({ error: "Pseudo invalide : 3 à 20 caractères (lettres, chiffres, - _)." }, 400);
    const user = await users.get(pseudo, { type: "json" });

    if (path === "/api/signup") {
      if (password.length < 6 || password.length > 200) return json({ error: "Mot de passe : 6 caractères minimum." }, 400);
      if (user) return json({ error: "Ce pseudo est déjà pris." }, 409);
      const st = await getSettings();
      if (st.signups === "closed") return json({ error: "Les inscriptions sont fermées." }, 403);
      if ((await users.list()).blobs.length >= st.max) return json({ error: "Le nombre maximal de profils est atteint." }, 403);
      const salt = randomBytes(16).toString("hex"), code = newCode(), pending = st.signups === "approval";
      await users.setJSON(pseudo, { name, salt, hash: hashPw(password, salt), codeEnc: await encCode(code), status: pending ? "pending" : "active", fails: 0, lockUntil: 0, created: Date.now() });
      if (pending) return json({ pending: true, code, message: "Compte créé : en attente de validation par l'admin." }, 202);
      await profiles.setJSON(pseudo, { pseudo, name, films: [], public: true, updated: Date.now() });
      return json({ token: await makeToken(pseudo), pseudo, name, code });
    }

    /* connexion : mot de passe OU code de secours à 10 chiffres ; verrou de 15 min après 5 échecs */
    if (user && user.lockUntil > Date.now()) return json({ error: "Trop d'essais : réessayez dans quelques minutes." }, 429);
    let ok = false;
    if (user) {
      ok = safeEq(hashPw(password, user.salt), user.hash);
      if (!ok && /^\d{10}$/.test(password)) ok = safeEq((await decCode(user.codeEnc)) ?? "", password);
    }
    if (!ok) {
      if (user) {
        user.fails = (user.fails || 0) + 1;
        if (user.fails >= 5) { user.fails = 0; user.lockUntil = Date.now() + 15 * 60_000; }
        await users.setJSON(pseudo, user);
      }
      return json({ error: "Pseudo ou mot de passe incorrect." }, 401);
    }
    if (user.status === "pending") return json({ error: "Compte en attente de validation par l'admin." }, 403);
    if (user.fails || user.lockUntil) { user.fails = 0; user.lockUntil = 0; await users.setJSON(pseudo, user); }
    return json({ token: await makeToken(pseudo), pseudo, name: user.name });
  }

  /* ----- changer son mot de passe (après connexion, y compris avec le code de secours) ----- */
  if (path === "/api/password" && (method === "PUT" || method === "POST")) {
    let b; try { b = await req.json(); } catch { return json({ error: "JSON invalide" }, 400); }
    const pseudo = await readToken(bearer(req, b));
    if (!pseudo) return json({ error: "non connecté" }, 401);
    const pw = String(b?.password || "");
    if (pw.length < 6 || pw.length > 200) return json({ error: "Mot de passe : 6 caractères minimum." }, 400);
    const user = await users.get(pseudo, { type: "json" });
    if (!user) return json({ error: "compte introuvable" }, 401);
    user.salt = randomBytes(16).toString("hex"); user.hash = hashPw(pw, user.salt);
    await users.setJSON(pseudo, user);
    return json({ ok: true });
  }

  /* ----- administration des profils ----- */
  if (path === "/api/admin" && method === "POST") {
    const code = process.env.ADMIN_CODE;
    if (!code) return json({ error: "ADMIN_CODE non défini sur Netlify" }, 500);
    if (!safeEq(req.headers.get("x-admin-code") || "", code)) return json({ error: "code invalide" }, 401);
    let b; try { b = await req.json(); } catch { return json({ error: "JSON invalide" }, 400); }
    const pseudo = String(b?.pseudo || "").trim().normalize("NFC").toLowerCase();

    if (b.action === "list") {
      const out = [];
      for (const { key } of (await users.list()).blobs) {
        const u = await users.get(key, { type: "json" }); if (!u) continue;
        const p = await profiles.get(key, { type: "json" }), films = p?.films || [];
        out.push({ pseudo: key, name: u.name, status: u.status || "active", created: u.created, public: p ? p.public !== false : null,
          seen: films.filter((f) => (f.list || "seen") === "seen").length, watch: films.filter((f) => f.list === "watch").length,
          code: u.codeEnc ? await decCode(u.codeEnc) : null });
      }
      return json({ settings: await getSettings(), users: out });
    }
    if (b.action === "settings") {
      if (!["open", "approval", "closed"].includes(b.signups)) return json({ error: "réglage invalide" }, 400);
      const max = Math.min(500, Math.max(1, parseInt(b.max, 10) || 20));
      await getStore("config").setJSON("settings", { signups: b.signups, max });
      return json({ ok: true });
    }
    const u = pseudo && (await users.get(pseudo, { type: "json" }));
    if (!u) return json({ error: "profil introuvable" }, 404);
    if (b.action === "approve") {
      u.status = "active"; await users.setJSON(pseudo, u);
      if (!(await profiles.get(pseudo, { type: "json" }))) await profiles.setJSON(pseudo, { pseudo, name: u.name, films: [], public: true, updated: Date.now() });
      return json({ ok: true });
    }
    if (b.action === "newcode") {
      const c = newCode(); u.codeEnc = await encCode(c); u.fails = 0; u.lockUntil = 0;
      await users.setJSON(pseudo, u); return json({ ok: true, code: c });
    }
    if (b.action === "delete") { await users.delete(pseudo); await profiles.delete(pseudo); return json({ ok: true }); }
    return json({ error: "action inconnue" }, 400);
  }

  /* ----- liste des profils publics ----- */
  if (path === "/api/profiles" && method === "GET") {
    const { blobs } = await profiles.list();
    const out = [];
    for (const { key } of blobs) {
      const p = await profiles.get(key, { type: "json" });
      if (!p || p.public === false) continue;
      const films = p.films || [];
      out.push({
        pseudo: p.pseudo, name: p.name,
        seen: films.filter((f) => (f.list || "seen") === "seen").length,
        watch: films.filter((f) => f.list === "watch").length,
        keys: films.filter((f) => (f.list || "seen") === "seen").map((f) => [f.title, f.year || 0, f.tmdb || 0]),
        updated: p.updated,
      });
    }
    return json(out);
  }

  /* ----- un profil ----- */
  const m = path.match(/^\/api\/profile\/([^/]+)$/);
  if (m && method === "GET") {
    const pseudo = decodeURIComponent(m[1]).normalize("NFC").toLowerCase();
    const p = await profiles.get(pseudo, { type: "json" });
    if (!p) return json({ error: "profil introuvable" }, 404);
    if (p.public === false && (await readToken(bearer(req))) !== pseudo) return json({ error: "profil privé" }, 403);
    return json({ pseudo: p.pseudo, name: p.name, films: p.films || [], public: p.public !== false });
  }

  /* ----- enregistrer son propre profil ----- */
  if (path === "/api/me" && (method === "PUT" || method === "POST")) {
    const raw = await req.text();
    if (raw.length > MAX_BYTES) return json({ error: "profil trop volumineux" }, 413);
    let b; try { b = JSON.parse(raw); } catch { return json({ error: "JSON invalide" }, 400); }
    const pseudo = await readToken(bearer(req, b));
    if (!pseudo) return json({ error: "non connecté" }, 401);
    if (!Array.isArray(b.films)) return json({ error: "films invalides" }, 400);
    const user = await users.get(pseudo, { type: "json" });
    if (!user) return json({ error: "compte introuvable" }, 401);
    await profiles.setJSON(pseudo, { pseudo, name: user.name, films: b.films, public: b.public !== false, updated: Date.now() });
    return json({ ok: true });
  }

  return json({ error: "introuvable" }, 404);
};

export const config = { path: "/api/*" };
