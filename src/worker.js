const MAX_BODY_PREVIEW = 400;
const MAX_BODY_STORED = 50000;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const PASSWORD_ITERATIONS = 150000;

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (url.pathname === "/") {
        return new Response(renderAppHtml(), {
          headers: { "content-type": "text/html; charset=utf-8" },
        });
      }

      if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }

      if (url.pathname === "/api/health") {
        return json({ ok: true, ts: Date.now() });
      }

      if (request.method === "POST" && url.pathname === "/api/auth/register") {
        const authStore = requireAuthKv(env);
        if (authStore.error) return authStore.error;
        return handleRegister(request, authStore.value);
      }

      if (request.method === "POST" && url.pathname === "/api/auth/login") {
        const authStore = requireAuthKv(env);
        if (authStore.error) return authStore.error;
        return handleLogin(request, authStore.value);
      }

      if (request.method === "POST" && url.pathname === "/api/auth/logout") {
        const authStore = requireAuthKv(env);
        if (authStore.error) return authStore.error;
        return handleLogout(request, authStore.value);
      }

      if (request.method === "GET" && url.pathname === "/api/auth/me") {
        const authStore = requireAuthKv(env);
        if (authStore.error) return authStore.error;
        const auth = await resolveSessionAuth(request, authStore.value);
        if (!auth) return json({ error: "Unauthorized" }, 401);
        return json({
          user: auth.user,
          tenant: auth.tenant,
          role: auth.membership.role,
        });
      }

      if (request.method === "GET" && url.pathname === "/api/auth/tenants") {
        const authStore = requireAuthKv(env);
        if (authStore.error) return authStore.error;
        const auth = await resolveSessionAuth(request, authStore.value);
        if (!auth) return json({ error: "Unauthorized" }, 401);
        const memberships = await listUserMemberships(authStore.value, auth.user.id);
        return json({ tenants: memberships.map((item) => item.tenant) });
      }

      if (request.method === "POST" && url.pathname === "/api/auth/switch-tenant") {
        const authStore = requireAuthKv(env);
        if (authStore.error) return authStore.error;
        return handleSwitchTenant(request, authStore.value);
      }

      if (url.pathname.startsWith("/api/")) {
        const auth = await requireApiAuth(request, env);
        if (auth.error) {
          return auth.error;
        }

        if (request.method === "GET" && url.pathname === "/api/mailboxes/exists") {
          const kv = requireKv(env);
          if (kv.error) return kv.error;

          const address = normalizeEmail(url.searchParams.get("address") || "");
          if (!address) {
            return json({ error: "address is required" }, 400);
          }

          const exists = await mailboxExistsForAuth(auth.value, kv.value, address);
          return json({ exists, address });
        }

        if (request.method === "GET" && url.pathname === "/api/mailboxes") {
          if (!hasRole(auth.value.role, ["owner", "admin"])) {
            return json({ error: "Forbidden" }, 403);
          }
          if (!auth.value.authStore || !auth.value.tenantId) {
            return json({ error: "AUTH_KV session mode is required for mailbox routes" }, 400);
          }
          const mailboxes = await listTenantMailboxes(auth.value.authStore, auth.value.tenantId);
          return json({ mailboxes });
        }

        if (request.method === "POST" && url.pathname === "/api/mailboxes") {
          if (!hasRole(auth.value.role, ["owner", "admin"])) {
            return json({ error: "Forbidden" }, 403);
          }
          if (!auth.value.authStore || !auth.value.tenantId) {
            return json({ error: "AUTH_KV session mode is required for mailbox routes" }, 400);
          }
          const body = await parseJson(request);
          const address = normalizeEmail(body?.address || "");
          if (!address) return json({ error: "address is required" }, 400);

          await auth.value.authStore.put(
            `mailbox:${address}`,
            JSON.stringify({ tenantId: auth.value.tenantId, createdAt: new Date().toISOString() })
          );
          await auth.value.authStore.put(
            `tenant_mailbox:${auth.value.tenantId}:${address}`,
            JSON.stringify({ address, createdAt: new Date().toISOString() })
          );
          return json({ ok: true, address });
        }

        if (request.method === "DELETE" && url.pathname.startsWith("/api/mailboxes/")) {
          if (!hasRole(auth.value.role, ["owner", "admin"])) {
            return json({ error: "Forbidden" }, 403);
          }
          if (!auth.value.authStore || !auth.value.tenantId) {
            return json({ error: "AUTH_KV session mode is required for mailbox routes" }, 400);
          }
          const address = normalizeEmail(decodeURIComponent(url.pathname.replace("/api/mailboxes/", "")));
          if (!address) return json({ error: "Invalid address" }, 400);

          await auth.value.authStore.delete(`mailbox:${address}`);
          await auth.value.authStore.delete(`tenant_mailbox:${auth.value.tenantId}:${address}`);
          return json({ ok: true, address });
        }
      }

      if (request.method === "GET" && url.pathname === "/api/messages") {
        const kv = requireKv(env);
        if (kv.error) return kv.error;

        const auth = await requireApiAuth(request, env);
        if (auth.error) return auth.error;

        const limit = Math.min(Number(url.searchParams.get("limit") || 30), 100);
        const prefixes = auth.value.mode === "legacy-token" ? ["mail:legacy:", "mail:"] : [auth.value.mailPrefix];
        const keyMap = new Map();

        for (const prefix of prefixes) {
          const list = await kv.value.list({ prefix });
          for (const entry of list.keys) {
            if (!keyMap.has(entry.name)) {
              keyMap.set(entry.name, entry.name);
            }
          }
        }

        const items = Array.from(keyMap.values())
          .map((name) => ({ key: name, sortKey: name }))
          .sort((a, b) => (a.sortKey < b.sortKey ? 1 : -1))
          .slice(0, limit);

        const messages = [];
        for (const item of items) {
          const raw = await kv.value.get(item.key, "json");
          if (raw) {
            messages.push({
              id: raw.id,
              from: raw.from,
              to: raw.to,
              subject: raw.subject,
              receivedAt: raw.receivedAt,
              size: raw.size,
              preview: raw.preview,
            });
          }
        }

        return json({ messages });
      }

      if (request.method === "GET" && url.pathname.startsWith("/api/messages/")) {
        const kv = requireKv(env);
        if (kv.error) return kv.error;

        const auth = await requireApiAuth(request, env);
        if (auth.error) return auth.error;

        const id = decodeURIComponent(url.pathname.replace("/api/messages/", ""));
        const key = await resolveMessageKey(kv.value, auth.value, id);
        if (!key) {
          return json({ error: "Not found" }, 404);
        }
        const doc = await kv.value.get(key, "json");
        if (!doc) {
          return json({ error: "Not found" }, 404);
        }
        return json(doc);
      }

      if (request.method === "DELETE" && url.pathname.startsWith("/api/messages/")) {
        const kv = requireKv(env);
        if (kv.error) return kv.error;

        const auth = await requireApiAuth(request, env);
        if (auth.error) return auth.error;
        if (!hasRole(auth.value.role, ["owner", "admin", "operator"])) {
          return json({ error: "Forbidden" }, 403);
        }

        const id = decodeURIComponent(url.pathname.replace("/api/messages/", ""));
        const key = await resolveMessageKey(kv.value, auth.value, id);
        if (!key) {
          return json({ error: "Not found" }, 404);
        }
        await kv.value.delete(key);
        return json({ ok: true, id });
      }

      if (request.method === "POST" && url.pathname === "/api/clear") {
        const kv = requireKv(env);
        if (kv.error) return kv.error;

        const auth = await requireApiAuth(request, env);
        if (auth.error) return auth.error;
        if (!hasRole(auth.value.role, ["owner", "admin"])) {
          return json({ error: "Forbidden" }, 403);
        }

        const prefixes = auth.value.mode === "legacy-token" ? ["mail:legacy:", "mail:"] : [auth.value.mailPrefix];
        let deleted = 0;
        for (const prefix of prefixes) {
          const list = await kv.value.list({ prefix });
          deleted += list.keys.length;
          await Promise.all(list.keys.map((entry) => kv.value.delete(entry.name)));
        }
        return json({ ok: true, deleted });
      }

      return new Response("Not found", { status: 404 });
    } catch (error) {
      return json(
        {
          error: "Worker runtime error",
          message: error?.message || "unknown",
        },
        500
      );
    }
  },

  async email(message, env) {
    try {
      const parsed = await parseIncomingEmail(message);
      const tenantId = await resolveTenantForInbound(env, parsed.to);
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const doc = {
        id,
        tenantId,
        from: parsed.from,
        to: parsed.to,
        subject: parsed.subject,
        receivedAt: new Date().toISOString(),
        size: parsed.size,
        preview: parsed.preview,
        textBody: parsed.textBody,
        htmlBody: parsed.htmlBody,
        headers: parsed.headers,
      };

      const prefix = tenantId ? `mail:${tenantId}:` : "mail:legacy:";
      await env.MAIL_KV.put(`${prefix}${id}`, JSON.stringify(doc));
    } catch (error) {
      message.setReject(`Worker parsing error: ${error?.message || "unknown"}`);
    }
  },
};

function requireKv(env) {
  if (!env?.MAIL_KV) {
    return {
      error: json(
        {
          error: "KV binding missing",
          message: "MAIL_KV is not bound. Check wrangler.toml and deployment environment.",
        },
        500
      ),
    };
  }
  return { value: env.MAIL_KV };
}

function requireAuthKv(env) {
  if (!env?.AUTH_KV) {
    return {
      error: json(
        {
          error: "AUTH_KV missing",
          message: "AUTH_KV is not bound. Create and bind AUTH_KV namespace.",
        },
        500
      ),
    };
  }
  return { value: env.AUTH_KV };
}

async function requireApiAuth(request, env) {
  const authStore = env?.AUTH_KV ? { value: env.AUTH_KV } : null;

  if (authStore?.value) {
    const session = await resolveSessionAuth(request, authStore.value);
    if (session) {
      return {
        value: {
          mode: "session",
          role: session.membership.role,
          tenantId: session.tenant.id,
          mailPrefix: `mail:${session.tenant.id}:`,
          authStore: authStore.value,
        },
      };
    }
  }

  // Backward compatibility for existing token-based frontend.
  if (env.DASHBOARD_TOKEN) {
    const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "").trim();
    if (token && token === env.DASHBOARD_TOKEN) {
      return {
        value: {
          mode: "legacy-token",
          role: "owner",
          tenantId: null,
          mailPrefix: "mail:legacy:",
          authStore: authStore?.value || null,
        },
      };
    }
  }

  return { error: json({ error: "Unauthorized" }, 401) };
}

async function resolveSessionAuth(request, authKv) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const sid = cookies["cf_mv_sid"];
  if (!sid) return null;

  const session = await authKv.get(`session:${sid}`, "json");
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    await authKv.delete(`session:${sid}`);
    return null;
  }

  const user = await authKv.get(`user:${session.userId}`, "json");
  const tenant = await authKv.get(`tenant:${session.tenantId}`, "json");
  const membership = await authKv.get(`membership:${session.tenantId}:${session.userId}`, "json");
  if (!user || !tenant || !membership) return null;

  return { sid, user: safeUser(user), tenant, membership };
}

async function handleRegister(request, authKv) {
  const body = await parseJson(request);
  const email = normalizeEmail(body?.email || "");
  const password = String(body?.password || "");
  const tenantName = String(body?.tenantName || "").trim();

  if (!email || !password || !tenantName) {
    return json({ error: "email, password, tenantName are required" }, 400);
  }

  if (password.length < 8) {
    return json({ error: "Password must be at least 8 characters" }, 400);
  }

  const existing = await authKv.get(`user_email:${email}`, "text");
  if (existing) {
    return json({ error: "Email already registered" }, 409);
  }

  const userId = createId("usr");
  const tenantId = createId("ten");
  const createdAt = new Date().toISOString();
  const pwd = await hashPassword(password);

  const user = {
    id: userId,
    email,
    passwordHash: pwd.hash,
    passwordSalt: pwd.salt,
    createdAt,
  };
  const tenant = {
    id: tenantId,
    name: tenantName,
    createdAt,
  };
  const membership = {
    tenantId,
    userId,
    role: "owner",
    createdAt,
  };

  await Promise.all([
    authKv.put(`user_email:${email}`, userId),
    authKv.put(`user:${userId}`, JSON.stringify(user)),
    authKv.put(`tenant:${tenantId}`, JSON.stringify(tenant)),
    authKv.put(`membership:${tenantId}:${userId}`, JSON.stringify(membership)),
    authKv.put(`user_tenant:${userId}:${tenantId}`, JSON.stringify({ tenantId, role: "owner", createdAt })),
  ]);

  const sid = createId("sid");
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  await authKv.put(
    `session:${sid}`,
    JSON.stringify({ id: sid, userId, tenantId, role: "owner", expiresAt, createdAt })
  );

  return json(
    { ok: true, user: safeUser(user), tenant, role: "owner" },
    200,
    { "set-cookie": buildSessionCookie(request, sid, SESSION_TTL_SECONDS) }
  );
}

async function handleLogin(request, authKv) {
  const body = await parseJson(request);
  const email = normalizeEmail(body?.email || "");
  const password = String(body?.password || "");
  const requestedTenantId = String(body?.tenantId || "").trim();

  if (!email || !password) {
    return json({ error: "email and password are required" }, 400);
  }

  const userId = await authKv.get(`user_email:${email}`, "text");
  if (!userId) return json({ error: "Invalid credentials" }, 401);

  const user = await authKv.get(`user:${userId}`, "json");
  if (!user) return json({ error: "Invalid credentials" }, 401);

  const valid = await verifyPassword(password, user.passwordHash, user.passwordSalt);
  if (!valid) return json({ error: "Invalid credentials" }, 401);

  const memberships = await listUserMemberships(authKv, userId);
  if (!memberships.length) return json({ error: "No tenant membership" }, 403);

  const chosen = requestedTenantId
    ? memberships.find((m) => m.tenant.id === requestedTenantId)
    : memberships[0];
  if (!chosen) {
    return json({ error: "Tenant access denied" }, 403);
  }

  const sid = createId("sid");
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  await authKv.put(
    `session:${sid}`,
    JSON.stringify({
      id: sid,
      userId: user.id,
      tenantId: chosen.tenant.id,
      role: chosen.role,
      expiresAt,
      createdAt: new Date().toISOString(),
    })
  );

  return json(
    { ok: true, user: safeUser(user), tenant: chosen.tenant, role: chosen.role },
    200,
    { "set-cookie": buildSessionCookie(request, sid, SESSION_TTL_SECONDS) }
  );
}

async function handleLogout(request, authKv) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const sid = cookies["cf_mv_sid"];
  if (sid) {
    await authKv.delete(`session:${sid}`);
  }
  return json({ ok: true }, 200, { "set-cookie": buildSessionCookie(request, "", 0) });
}

async function handleSwitchTenant(request, authKv) {
  const auth = await resolveSessionAuth(request, authKv);
  if (!auth) return json({ error: "Unauthorized" }, 401);

  const body = await parseJson(request);
  const tenantId = String(body?.tenantId || "").trim();
  if (!tenantId) return json({ error: "tenantId is required" }, 400);

  const membership = await authKv.get(`membership:${tenantId}:${auth.user.id}`, "json");
  const tenant = await authKv.get(`tenant:${tenantId}`, "json");
  if (!membership || !tenant) return json({ error: "Tenant access denied" }, 403);

  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  await authKv.put(
    `session:${auth.sid}`,
    JSON.stringify({
      id: auth.sid,
      userId: auth.user.id,
      tenantId,
      role: membership.role,
      expiresAt,
      createdAt: new Date().toISOString(),
    })
  );

  return json({ ok: true, tenant, role: membership.role });
}

async function listUserMemberships(authKv, userId) {
  const list = await authKv.list({ prefix: `user_tenant:${userId}:` });
  const rows = [];
  for (const key of list.keys) {
    const item = await authKv.get(key.name, "json");
    if (!item?.tenantId) continue;

    const tenant = await authKv.get(`tenant:${item.tenantId}`, "json");
    if (!tenant) continue;
    rows.push({ tenant, role: item.role || "viewer" });
  }
  return rows;
}

async function listTenantMailboxes(authKv, tenantId) {
  const list = await authKv.list({ prefix: `tenant_mailbox:${tenantId}:` });
  return list.keys
    .map((key) => key.name.replace(`tenant_mailbox:${tenantId}:`, ""))
    .filter(Boolean)
    .sort();
}

async function resolveTenantForInbound(env, toAddress) {
  if (!env?.AUTH_KV) return null;
  const normalized = normalizeEmail(toAddress || "");
  if (!normalized) return null;
  const route = await env.AUTH_KV.get(`mailbox:${normalized}`, "json");
  return route?.tenantId || null;
}

async function mailboxExistsForAuth(auth, mailKv, address) {
  const normalized = normalizeEmail(address || "");
  if (!normalized) return false;

  if (auth.authStore) {
    const route = await auth.authStore.get(`mailbox:${normalized}`, "json");
    if (route?.tenantId) {
      if (auth.mode === "session") {
        if (route.tenantId === auth.tenantId) return true;
      } else {
        return true;
      }
    }
  }

  const prefixes = auth.mode === "legacy-token"
    ? ["mail:legacy:", "mail:"]
    : [`mail:${auth.tenantId}:`];

  for (const prefix of prefixes) {
    let cursor = undefined;
    let rounds = 0;

    do {
      const list = await mailKv.list({ prefix, cursor, limit: 200 });
      for (const entry of list.keys) {
        const doc = await mailKv.get(entry.name, "json");
        if (!doc) continue;
        if (normalizeEmail(doc.to || "").includes(normalized)) {
          return true;
        }
      }
      cursor = list.cursor;
      rounds += 1;
    } while (cursor && rounds < 5);
  }

  return false;
}

async function resolveMessageKey(mailKv, auth, id) {
  const candidates = auth.mode === "legacy-token"
    ? [`mail:legacy:${id}`, `mail:${id}`]
    : [`${auth.mailPrefix}${id}`];

  for (const key of candidates) {
    const value = await mailKv.get(key, "text");
    if (value !== null) return key;
  }
  return null;
}

function hasRole(role, allowed) {
  return allowed.includes(String(role || "").toLowerCase());
}

function parseCookies(cookieHeader) {
  return String(cookieHeader || "")
    .split(";")
    .map((chunk) => chunk.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const idx = part.indexOf("=");
      if (idx <= 0) return acc;
      const key = decodeURIComponent(part.slice(0, idx).trim());
      const value = decodeURIComponent(part.slice(idx + 1).trim());
      acc[key] = value;
      return acc;
    }, {});
}

function buildSessionCookie(request, sid, maxAgeSeconds) {
  const isHttps = (() => {
    try {
      return new URL(request.url).protocol === "https:";
    } catch {
      return false;
    }
  })();

  const attrs = [
    `cf_mv_sid=${encodeURIComponent(sid)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.max(0, Number(maxAgeSeconds) || 0)}`,
  ];
  if (isHttps) {
    attrs.push("Secure");
  }
  return attrs.join("; ");
}

function createId(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;
}

function normalizeEmail(input) {
  return String(input || "").trim().toLowerCase();
}

function safeUser(user) {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
  };
}

async function parseJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function hashPassword(password) {
  const salt = crypto.randomUUID().replace(/-/g, "");
  const hash = await pbkdf2(password, salt);
  return { hash, salt };
}

async function verifyPassword(password, storedHash, storedSalt) {
  if (!storedHash || !storedSalt) return false;
  const computed = await pbkdf2(password, storedSalt);
  return timingSafeEqual(computed, storedHash);
}

async function pbkdf2(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: PASSWORD_ITERATIONS,
      salt: enc.encode(salt),
    },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqual(a, b) {
  const left = String(a || "");
  const right = String(b || "");
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) {
    diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return diff === 0;
}

async function parseIncomingEmail(message) {
  const arrayBuffer = await new Response(message.raw).arrayBuffer();
  const rawText = new TextDecoder("utf-8", { fatal: false }).decode(arrayBuffer);

  const headers = extractHeaders(rawText);
  const subject = safeHeader(decodeMimeHeaderValue(headers["subject"])) || "(No Subject)";
  const from = safeHeader(decodeMimeHeaderValue(headers["from"])) || message.from || "unknown";
  const to = safeHeader(decodeMimeHeaderValue(headers["to"])) || message.to || "unknown";

  const { textBody, htmlBody } = parseMimeBody(rawText, headers);
  const preview = textBody.slice(0, MAX_BODY_PREVIEW);

  return {
    from,
    to,
    subject,
    size: arrayBuffer.byteLength,
    preview,
    textBody,
    htmlBody,
    headers,
  };
}

function parseMimeBody(rawText, headers) {
  const contentType = headers["content-type"] || "";
  const transferEncoding = headers["content-transfer-encoding"] || "";
  const headerEnd = findHeaderEnd(rawText);
  const bodyRaw = headerEnd >= 0 ? rawText.slice(headerEnd) : "";

  if (/multipart\//i.test(contentType)) {
    const boundary = getBoundary(contentType);
    if (!boundary) {
      return { textBody: "", htmlBody: "" };
    }

    const parts = splitMultipartBody(bodyRaw, boundary);
    let textBody = "";
    let htmlBody = "";

    for (const part of parts) {
      const partType = part.headers["content-type"] || "text/plain; charset=utf-8";
      const partEncoding = part.headers["content-transfer-encoding"] || "";
      const decoded = decodePartContent(part.body, partEncoding, partType);

      if (!textBody && /text\/plain/i.test(partType)) {
        textBody = sanitizeBody(decoded).slice(0, MAX_BODY_STORED);
      }

      if (!htmlBody && /text\/html/i.test(partType)) {
        htmlBody = decoded.slice(0, MAX_BODY_STORED);
      }
    }

    if (!textBody && htmlBody) {
      textBody = sanitizeBody(stripHtml(htmlBody)).slice(0, MAX_BODY_STORED);
    }

    return { textBody, htmlBody };
  }

  const singleBody = decodePartContent(bodyRaw, transferEncoding, contentType);
  const isHtml = /text\/html/i.test(contentType);
  return {
    textBody: sanitizeBody(isHtml ? stripHtml(singleBody) : singleBody).slice(0, MAX_BODY_STORED),
    htmlBody: isHtml ? singleBody.slice(0, MAX_BODY_STORED) : "",
  };
}

function findHeaderEnd(rawText) {
  const idx = rawText.search(/\r?\n\r?\n/);
  if (idx < 0) return -1;
  const matched = rawText.slice(idx).match(/^\r?\n\r?\n/);
  return idx + (matched ? matched[0].length : 2);
}

function getBoundary(contentType) {
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  return (match?.[1] || match?.[2] || "").trim();
}

function splitMultipartBody(bodyRaw, boundary) {
  const marker = `--${boundary}`;
  const segments = bodyRaw.split(marker);
  const parts = [];

  for (const segment of segments) {
    const trimmed = segment.trim();
    if (!trimmed || trimmed === "--") continue;
    if (trimmed.startsWith("--")) continue;

    const cleaned = segment.replace(/^\r?\n/, "").replace(/\r?\n$/, "");
    const splitIdx = cleaned.search(/\r?\n\r?\n/);
    if (splitIdx < 0) continue;

    const headerBlock = cleaned.slice(0, splitIdx);
    const body = cleaned.slice(splitIdx).replace(/^\r?\n\r?\n/, "");
    parts.push({
      headers: parseHeaderBlock(headerBlock),
      body,
    });
  }

  return parts;
}

function parseHeaderBlock(headerBlock) {
  const lines = headerBlock.split(/\r?\n/);
  const merged = [];

  for (const line of lines) {
    if (/^[\t ]/.test(line) && merged.length) {
      merged[merged.length - 1] += ` ${line.trim()}`;
    } else {
      merged.push(line);
    }
  }

  const map = {};
  for (const line of merged) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    map[key] = value;
  }
  return map;
}

function decodePartContent(bodyRaw, transferEncoding, contentType) {
  const charset = getCharset(contentType);
  let bytes;

  if (/base64/i.test(transferEncoding)) {
    bytes = decodeBase64ToBytes(bodyRaw);
  } else if (/quoted-printable/i.test(transferEncoding)) {
    bytes = decodeQuotedPrintableToBytes(bodyRaw);
  } else {
    bytes = new TextEncoder().encode(bodyRaw || "");
  }

  return decodeBytesWithCharset(bytes, charset);
}

function getCharset(contentType) {
  const match = (contentType || "").match(/charset=(?:"([^"]+)"|([^;]+))/i);
  const charset = (match?.[1] || match?.[2] || "utf-8").trim().toLowerCase();
  if (charset === "gb2312" || charset === "gbk") return "gb18030";
  return charset;
}

function decodeBase64ToBytes(input) {
  try {
    const normalized = (input || "").replace(/\s+/g, "");
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return new TextEncoder().encode(input || "");
  }
}

function decodeQuotedPrintableToBytes(input) {
  const text = (input || "")
    .replace(/=\r\n/g, "")
    .replace(/=\n/g, "");

  const out = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "=" && i + 2 < text.length) {
      const hex = text.slice(i + 1, i + 3);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        out.push(parseInt(hex, 16));
        i += 2;
        continue;
      }
    }
    out.push(text.charCodeAt(i) & 0xff);
  }
  return new Uint8Array(out);
}

function decodeBytesWithCharset(bytes, charset) {
  try {
    return new TextDecoder(charset || "utf-8", { fatal: false }).decode(bytes);
  } catch {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }
}

function decodeMimeHeaderValue(value) {
  if (!value) return "";

  return value.replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (_, charset, encoding, payload) => {
    const normalizedCharset = getCharset(`text/plain; charset=${charset}`);
    let bytes;

    if (/^[bB]$/.test(encoding)) {
      bytes = decodeBase64ToBytes(payload);
    } else {
      bytes = decodeQuotedPrintableToBytes(payload.replace(/_/g, " "));
    }

    return decodeBytesWithCharset(bytes, normalizedCharset);
  });
}

function stripHtml(html) {
  return (html || "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/\s{2,}/g, " ");
}

function extractHeaders(rawText) {
  const headerBlock = rawText.split(/\r?\n\r?\n/)[0] || "";
  const lines = headerBlock.split(/\r?\n/);
  const merged = [];

  for (const line of lines) {
    if (/^[\t ]/.test(line) && merged.length) {
      merged[merged.length - 1] += ` ${line.trim()}`;
    } else {
      merged.push(line);
    }
  }

  const map = {};
  for (const line of merged) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    map[key] = value;
  }
  return map;
}

function safeHeader(value) {
  if (!value) return "";
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").trim();
}

function sanitizeBody(text) {
  return (text || "")
    .replace(/\u0000/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}
