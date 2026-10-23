// demo1 — the "regular web app" (confidential OAuth client) pattern, as
// opposed to the SPA+PKCE pattern used elsewhere in this workspace
// (quant0-client/examples/react-demo, demo-app/quant0-todo). The defining
// difference: this server does the authorization_code -> token exchange
// itself, with a client_secret that never leaves the backend. The browser
// never sees an access_token at all — only an opaque, httpOnly session
// cookie. Everything in here is deliberately minimal (in-memory session/todo
// state, no refresh-token handling) — a real app would move sessions/todos
// into a real store and handle token refresh.
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import cookieParser from "cookie-parser";
import express from "express";

import {
  InvalidTokenError,
  Quant0Client,
  StrategyUnavailableError,
} from "@quant0/sdk-core";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT ?? 3200);
const GATEWAY_URL = process.env.QUANT0_GATEWAY_URL ?? "http://localhost:8082";
const CLIENT_ID = process.env.QUANT0_CLIENT_ID;
const CLIENT_SECRET = process.env.QUANT0_CLIENT_SECRET;
const REDIRECT_URI =
  process.env.QUANT0_REDIRECT_URI ?? `http://localhost:${PORT}/callback`;
// Option B (plain deep link) from docs/playbooks/aivagam-integration.md's
// "How to open the portal" — simplest of the two documented ways to send a
// signed-in user to their account portal, at the cost of a second login
// screen there (Option A mints a PKCE-bound portal_ticket server-side to
// skip that, not needed for this demo).
const ACCOUNT_PORTAL_URL = process.env.QUANT0_ACCOUNT_PORTAL_URL;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error(
    "Set QUANT0_CLIENT_ID and QUANT0_CLIENT_SECRET (copy .env.example to .env — see ../README.md to register the app first).",
  );
  process.exit(1);
}

// Quant0Client() with no args negotiates the local q0-agent, defaulting to
// http://127.0.0.1:9595. This server verifies tokens against the agent's
// cached JWKS — it never calls the gateway to check a token, only to
// exchange the authorization code for one in /callback below. Override via
// QUANT0_AGENT_URL if another agent already owns the default port (e.g. a
// second agent enrolled for a different app/org on this same machine).
const q0 = new Quant0Client(
  process.env.QUANT0_AGENT_URL ? { agentUrl: process.env.QUANT0_AGENT_URL } : undefined,
);

// ---- In-memory state. Demo only — restart loses everything. -------------
const sessions = new Map(); // sid -> { accessToken, refreshToken, expiresAt }
const pendingStates = new Map(); // oauth `state` -> { issuedAt, codeVerifier } (CSRF + PKCE)
const todosByUser = new Map(); // subject -> Todo[]

const STATE_TTL_MS = 10 * 60 * 1000;

function newId() {
  return crypto.randomBytes(16).toString("hex");
}

// RFC 7636 S256: code_verifier is a random string; code_challenge is its
// base64url(SHA-256), no padding.
function newPkcePair() {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  return { codeVerifier, codeChallenge };
}

function sweepExpiredStates() {
  const cutoff = Date.now() - STATE_TTL_MS;
  for (const [state, entry] of pendingStates) {
    if (entry.issuedAt < cutoff) pendingStates.delete(state);
  }
}

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "client")));

// ---- Step 1: kick off login — redirect to quant0's hosted authorize
// endpoint. `state` is a CSRF nonce we check back in /callback.
//
// PKCE here despite this being a confidential (client_secret-bearing) app:
// this app IS registered with require_pkce:false, which skips the presence
// check on /v1/oauth/authorize itself — but the hosted login portal's
// signup/login-ticket flow unconditionally attaches a code_challenge to
// whatever code it mints (see api-gateway's validatePKCEForTicket), so the
// token endpoint ends up requiring a matching code_verifier regardless of
// that setting. The code_verifier stays server-side the whole time (never
// sent to the browser) — if anything this is more defensible than the
// SPA+PKCE pattern, where the verifier has to live in the browser. --------
app.get("/login", (req, res) => {
  sweepExpiredStates();
  const state = newId();
  const { codeVerifier, codeChallenge } = newPkcePair();
  pendingStates.set(state, { issuedAt: Date.now(), codeVerifier });

  const url = new URL("/v1/oauth/authorize", GATEWAY_URL);
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  res.redirect(url.toString());
});

// ---- Step 2: the gateway/login-portal redirects the browser back here
// with ?code=...&state=.... This handler does the actual token exchange —
// server-to-server, client_secret never reaches the browser. That's the
// entire reason this pattern exists instead of the SPA+PKCE one. ---------
app.get("/callback", async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  if (error) {
    res.status(400).send(`Login failed: ${error} — ${errorDescription ?? ""}`);
    return;
  }
  if (typeof state !== "string" || !pendingStates.has(state)) {
    res.status(400).send("Invalid or expired state — try logging in again.");
    return;
  }
  const { codeVerifier } = pendingStates.get(state);
  pendingStates.delete(state);

  let tokenRes;
  try {
    tokenRes = await fetch(new URL("/v1/oauth/token", GATEWAY_URL), {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: codeVerifier,
      }),
    });
  } catch (err) {
    res.status(502).send(`Could not reach ${GATEWAY_URL}: ${err.message}`);
    return;
  }

  if (!tokenRes.ok) {
    const body = await tokenRes.text();
    res.status(502).send(`Token exchange failed: ${tokenRes.status} ${body}`);
    return;
  }

  const tokens = await tokenRes.json(); // { access_token, refresh_token?, expires_in, ... }

  const sid = newId();
  sessions.set(sid, {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token ?? null,
    expiresAt: Date.now() + tokens.expires_in * 1000,
  });

  res.cookie("sid", sid, {
    httpOnly: true,
    sameSite: "lax",
    secure: req.protocol === "https",
    maxAge: tokens.expires_in * 1000,
  });
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  const sid = req.cookies.sid;
  if (sid) sessions.delete(sid);
  res.clearCookie("sid");
  res.redirect("/");
});

// ---- Auth middleware: session cookie -> stored access_token -> verified
// via the local q0-agent (never the gateway) -> req.quant0 claims. This is
// the cookie-session equivalent of the SDK's own requireAuth() express
// adapter, which expects an Authorization header instead — not applicable
// here since the browser never holds the token. -------------------------
async function requireSession(req, res, next) {
  const sid = req.cookies.sid;
  const session = sid ? sessions.get(sid) : undefined;
  if (!session) {
    res.status(401).json({ error: "not_authenticated" });
    return;
  }

  try {
    req.quant0 = await q0.verify(session.accessToken);
    next();
  } catch (err) {
    if (err instanceof InvalidTokenError) {
      sessions.delete(sid);
      res.clearCookie("sid");
      res.status(401).json({ error: "invalid_token" });
      return;
    }
    if (err instanceof StrategyUnavailableError) {
      res.status(503).json({
        error: "agent_unavailable",
        message: "q0-agent is not reachable on 127.0.0.1:9595 — see ../README.md",
      });
      return;
    }
    next(err);
  }
}

app.get("/api/me", requireSession, (req, res) => {
  res.json({ subject: req.quant0.subject, orgId: req.quant0.orgId });
});

// Unauthenticated on purpose — just hands the client the public values it
// needs to build the "Manage account" link (client_id is not a secret).
app.get("/api/config", (_req, res) => {
  res.json({ accountPortalUrl: ACCOUNT_PORTAL_URL ?? null, clientId: CLIENT_ID });
});

app.get("/api/todos", requireSession, (req, res) => {
  res.json(todosByUser.get(req.quant0.subject) ?? []);
});

app.post("/api/todos", requireSession, (req, res) => {
  const text = (req.body?.text ?? "").trim();
  if (!text) {
    res.status(400).json({ error: "text_required" });
    return;
  }

  const list = todosByUser.get(req.quant0.subject) ?? [];
  const todo = { id: newId(), text, done: false };
  list.push(todo);
  todosByUser.set(req.quant0.subject, list);
  res.status(201).json(todo);
});

app.patch("/api/todos/:id", requireSession, (req, res) => {
  const list = todosByUser.get(req.quant0.subject) ?? [];
  const todo = list.find((t) => t.id === req.params.id);
  if (!todo) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  if (typeof req.body?.done === "boolean") todo.done = req.body.done;
  res.json(todo);
});

app.delete("/api/todos/:id", requireSession, (req, res) => {
  const list = todosByUser.get(req.quant0.subject) ?? [];
  todosByUser.set(
    req.quant0.subject,
    list.filter((t) => t.id !== req.params.id),
  );
  res.status(204).end();
});

// Generic error handler so an unexpected throw doesn't crash the demo.
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "internal_error" });
});

app.listen(PORT, () => {
  console.log(`demo1 server listening on http://localhost:${PORT}`);
});
