import crypto from "node:crypto";
import express, { Router, Request, Response, NextFunction } from "express";

const authCodes = new Map<string, { challenge: string; expiresAt: number }>();

function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function createAuthRouter(apiToken: string, baseUrl: string): Router {
  const router = Router();

  router.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
    });
  });

  router.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.json({
      resource: baseUrl,
      authorization_servers: [baseUrl],
    });
  });

  router.get("/authorize", (req, res) => {
    const {
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
      response_type,
    } = req.query as Record<string, string>;

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Paperless MCP &#8212; Authorize</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: sans-serif; max-width: 400px; margin: 4rem auto; padding: 1rem; }
    input[type=password] { width: 100%; padding: .5rem; margin: .5rem 0 1rem; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; }
    button { width: 100%; padding: .75rem; background: #1a73e8; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
    button:hover { background: #1557b0; }
  </style>
</head>
<body>
  <h2>Paperless MCP</h2>
  <p>Enter the API token to authorize Claude's access to your Paperless-NGX instance.</p>
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id" value="${escapeHtml(client_id || "")}">
    <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri || "")}">
    <input type="hidden" name="state" value="${escapeHtml(state || "")}">
    <input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge || "")}">
    <input type="hidden" name="code_challenge_method" value="${escapeHtml(code_challenge_method || "")}">
    <input type="hidden" name="response_type" value="${escapeHtml(response_type || "")}">
    <input type="password" name="password" placeholder="API Token" autofocus>
    <button type="submit">Authorize</button>
  </form>
</body>
</html>`);
  });

  router.post(
    "/authorize",
    express.urlencoded({ extended: false }),
    (req, res) => {
      const {
        password,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
      } = req.body as Record<string, string>;

      if (password !== apiToken) {
        res.status(401).send("Invalid token");
        return;
      }

      if (code_challenge_method !== "S256") {
        res.status(400).send("Only S256 code_challenge_method is supported");
        return;
      }

      const code = base64url(crypto.randomBytes(32));
      authCodes.set(code, {
        challenge: code_challenge,
        expiresAt: Date.now() + 5 * 60 * 1000,
      });

      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.set("code", code);
      if (state) redirectUrl.searchParams.set("state", state);
      res.redirect(redirectUrl.toString());
    }
  );

  router.post(
    "/oauth/token",
    express.urlencoded({ extended: false }),
    (req, res) => {
      const { grant_type, code, code_verifier } = req.body as Record<
        string,
        string
      >;

      if (grant_type !== "authorization_code") {
        res.status(400).json({ error: "unsupported_grant_type" });
        return;
      }

      if (!code || !code_verifier) {
        res.status(400).json({ error: "invalid_request" });
        return;
      }

      const stored = authCodes.get(code);
      if (!stored || stored.expiresAt < Date.now()) {
        authCodes.delete(code);
        res.status(400).json({ error: "invalid_grant" });
        return;
      }

      const verifierHash = base64url(
        crypto.createHash("sha256").update(code_verifier).digest()
      );

      if (verifierHash !== stored.challenge) {
        authCodes.delete(code);
        res.status(400).json({ error: "invalid_grant" });
        return;
      }

      authCodes.delete(code);
      res.json({
        access_token: apiToken,
        token_type: "bearer",
      });
    }
  );

  return router;
}

export function bearerAuthMiddleware(apiToken: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer ")) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    if (auth.slice(7) !== apiToken) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    next();
  };
}
