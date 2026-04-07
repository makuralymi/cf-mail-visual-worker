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

function renderAppHtml() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cloudflare Mail Visual Worker</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=Noto+Serif+SC:wght@400;500;600;700&display=swap');

    :root {
      --paper: #ece7db;
      --wash: #dde4dd;
      --pond: #9eb4b0;
      --reed: #7f938d;
      --iris: #b7a3b5;
      --rose-dust: #c9a89c;
      --ink: #2d3a37;
      --muted: #5d6f6a;
      --card: rgba(245, 241, 232, 0.82);
      --card-border: rgba(121, 143, 136, 0.4);
      --accent: #6d8880;
      --accent-soft: #94aba5;
      --danger: #b46f66;
      --ok: #5f8574;
      --shadow: 0 20px 48px rgba(67, 84, 78, 0.18);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Noto Serif SC", "PingFang SC", "Microsoft YaHei", serif;
      color: var(--ink);
      background-color: var(--paper);
      overflow-x: hidden;
    }

    body::before,
    body::after {
      content: "";
      position: fixed;
      border-radius: 999px;
      filter: blur(54px);
      pointer-events: none;
      z-index: -2;
      opacity: 0.34;
      animation: drift 14s ease-in-out infinite;
    }

    body::before {
      width: 42vw;
      height: 42vw;
      left: -12vw;
      top: -10vw;
      background-color: var(--pond);
    }

    body::after {
      width: 36vw;
      height: 36vw;
      right: -8vw;
      bottom: -10vw;
      background-color: var(--iris);
      animation-delay: -5s;
    }

    #particles {
      position: fixed;
      inset: 0;
      z-index: -1;
      opacity: 0.45;
      pointer-events: none;
    }

    .wrap {
      max-width: 1220px;
      margin: 0 auto;
      padding: 24px 16px 32px;
    }

    .top {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
      animation: fadeUp .7s ease;
    }

    .title {
      font-size: clamp(1.25rem, 2.5vw, 2.1rem);
      font-family: "Cormorant Garamond", "Noto Serif SC", serif;
      font-weight: 700;
      letter-spacing: 0.04em;
      margin: 0;
      color: #344642;
      text-shadow: 0 3px 14px rgba(115, 136, 130, 0.22);
    }

    .account-tools {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }

    .account-select {
      min-width: 220px;
      max-width: 300px;
      border-radius: 10px;
      border: 1px solid rgba(117, 139, 132, 0.45);
      background: rgba(244, 240, 230, 0.9);
      color: var(--ink);
      padding: 9px 10px;
    }

    input {
      width: 100%;
      border: 1px solid rgba(117, 139, 132, 0.45);
      background: rgba(244, 240, 230, 0.88);
      color: var(--ink);
      border-radius: 10px;
      padding: 10px 12px;
      outline: none;
    }

    input::placeholder {
      color: #7a8d86;
    }

    input:focus {
      border-color: rgba(111, 137, 129, 0.85);
      box-shadow: 0 0 0 3px rgba(159, 182, 174, 0.28);
    }

    button {
      border: 1px solid rgba(89, 117, 109, 0.65);
      border-radius: 10px;
      color: #f5f4ee;
      background: var(--accent);
      font-weight: 700;
      padding: 10px 14px;
      cursor: pointer;
      transition: transform .2s ease, box-shadow .2s ease, background-color .2s ease;
      box-shadow: 0 8px 16px rgba(94, 120, 112, 0.24);
      white-space: nowrap;
    }

    button:hover {
      transform: translateY(-1px);
      background: #5c786f;
    }

    .btn-secondary {
      background: rgba(214, 201, 188, 0.68);
      color: #445650;
      box-shadow: none;
      border: 1px solid rgba(126, 108, 99, 0.4);
    }

    .grid {
      display: grid;
      grid-template-columns: 370px 1fr;
      gap: 14px;
    }

    .panel {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: var(--shadow);
      backdrop-filter: blur(8px);
      animation: fadeUp .8s ease;
    }

    .panel-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px;
      border-bottom: 1px solid rgba(116, 140, 132, 0.24);
      background: rgba(222, 230, 223, 0.66);
    }

    .list {
      max-height: 68vh;
      overflow: auto;
      padding: 8px;
    }

    .item {
      border: 1px solid rgba(135, 153, 147, 0.24);
      border-radius: 12px;
      padding: 10px;
      margin: 8px 2px;
      background: rgba(241, 237, 228, 0.82);
      cursor: pointer;
      transition: .2s ease;
    }

    .item:hover, .item.active {
      border-color: rgba(103, 130, 123, 0.72);
      transform: translateY(-1px);
      box-shadow: 0 10px 22px rgba(126, 148, 141, 0.22);
    }

    .subject {
      font-weight: 700;
      margin-bottom: 6px;
    }

    .meta, .preview {
      color: var(--muted);
      font-size: 0.88rem;
      line-height: 1.35;
      word-break: break-word;
    }

    .mail-body {
      padding: 14px;
      min-height: 360px;
      max-height: 72vh;
      overflow: auto;
    }

    .mail-top {
      padding-bottom: 12px;
      border-bottom: 1px dashed rgba(116, 138, 132, 0.44);
      margin-bottom: 12px;
    }

    .content {
      white-space: pre-wrap;
      line-height: 1.5;
      color: #32443f;
      font-size: 0.95rem;
    }

    .empty {
      padding: 28px;
      color: var(--muted);
      text-align: center;
      font-size: 0.95rem;
    }

    .status {
      margin-top: 8px;
      font-size: 0.84rem;
      color: var(--muted);
      min-height: 1.2em;
    }

    .status.ok {
      color: var(--ok);
    }

    .status.err {
      color: var(--danger);
    }

    .token-modal {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 20;
      padding: 16px;
      background: rgba(74, 87, 82, 0.38);
      backdrop-filter: blur(3px);
    }

    .token-modal.show {
      display: flex;
      animation: fadeUp .25s ease;
    }

    .token-modal-card {
      width: min(92vw, 440px);
      background: rgba(245, 241, 232, 0.95);
      border: 1px solid rgba(121, 143, 136, 0.5);
      border-radius: 16px;
      box-shadow: var(--shadow);
      padding: 16px;
    }

    .token-modal-title {
      margin: 0;
      font-size: 1.1rem;
      color: #2f443e;
    }

    .token-modal-desc {
      margin: 8px 0 12px;
      font-size: 0.9rem;
      color: #5b6e68;
      line-height: 1.45;
    }

    .token-modal-actions {
      display: flex;
      justify-content: flex-end;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }

    .account-list {
      max-height: 180px;
      overflow: auto;
      margin: 10px 0;
      padding-right: 2px;
    }

    .account-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 8px 10px;
      border: 1px solid rgba(129, 150, 143, 0.34);
      border-radius: 10px;
      background: rgba(243, 239, 231, 0.75);
      margin-bottom: 8px;
    }

    .account-row-main {
      min-width: 0;
    }

    .account-name {
      color: #314641;
      font-size: 0.92rem;
      font-weight: 700;
      margin-bottom: 2px;
    }

    .account-email {
      color: #60736d;
      font-size: 0.82rem;
      word-break: break-all;
    }

    .account-form {
      border-top: 1px dashed rgba(116, 138, 132, 0.44);
      padding-top: 12px;
      margin-top: 12px;
    }

    .account-form-title {
      color: #395149;
      font-size: 0.9rem;
      margin-bottom: 8px;
    }

    .account-form-grid {
      display: grid;
      gap: 8px;
    }

    @media (max-width: 960px) {
      .grid {
        grid-template-columns: 1fr;
      }
      .list {
        max-height: 42vh;
      }
      .mail-body {
        max-height: none;
      }
    }

    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(16px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes drift {
      0%, 100% { transform: translate3d(0, 0, 0); }
      50% { transform: translate3d(10px, -14px, 0); }
    }
  </style>
</head>
<body>
  <canvas id="particles"></canvas>
  <main class="wrap">
    <section class="top">
      <h1 class="title">Cloudflare 邮件可视化收件箱</h1>
      <div class="account-tools">
        <select id="accountSelect" class="account-select"></select>
        <button id="manageAccountsBtn">账户设置</button>
      </div>
    </section>

    <section class="panel" style="margin-bottom:14px;">
      <div class="panel-head">
        <div>控制台</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button id="refreshBtn">刷新</button>
          <button id="clearBtn" class="btn-secondary">清空全部</button>
        </div>
      </div>
      <div style="padding: 10px 12px;" class="meta">
        邮件由 Cloudflare Email Worker 接收并写入 KV。页面通过 API 实时读取。
        <div id="status" class="status"></div>
      </div>
    </section>

    <section class="grid">
      <article class="panel">
        <div class="panel-head">
          <strong>邮件列表</strong>
          <span id="count" class="meta">0 封</span>
        </div>
        <div id="list" class="list"></div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <strong>邮件详情</strong>
          <button id="deleteBtn" class="btn-secondary">删除当前</button>
        </div>
        <div id="detail" class="mail-body empty">请选择左侧邮件查看内容</div>
      </article>
    </section>
  </main>

  <div id="tokenModal" class="token-modal" aria-hidden="true">
    <div class="token-modal-card">
      <h2 class="token-modal-title">多账户设置</h2>
      <p class="token-modal-desc">可添加多个邮箱账户并切换查看。若填写“收件地址”，列表会按 To 字段过滤。</p>
      <div id="accountList" class="account-list"></div>

      <div class="account-form">
        <div id="accountFormTitle" class="account-form-title">新增账户</div>
        <div class="account-form-grid">
          <input id="accountNameInput" autocomplete="off" placeholder="账户名称（如：主邮箱）" />
          <input id="accountEmailInput" autocomplete="off" placeholder="收件地址（可选，用于过滤）" />
          <input id="tokenModalInput" type="password" autocomplete="off" placeholder="Dashboard Token（Bearer Token）" />
        </div>
      </div>

      <div class="token-modal-actions">
        <button id="accountResetBtn" class="btn-secondary" style="display:none;">取消编辑</button>
        <button id="tokenCancelBtn" class="btn-secondary">关闭</button>
        <button id="tokenSaveBtn">新增账户</button>
      </div>
    </div>
  </div>

  <script>
    const listEl = document.getElementById('list');
    const detailEl = document.getElementById('detail');
    const countEl = document.getElementById('count');
    const statusEl = document.getElementById('status');
    const tokenModal = document.getElementById('tokenModal');
    const accountListEl = document.getElementById('accountList');
    const tokenModalInput = document.getElementById('tokenModalInput');
    const accountFormTitle = document.getElementById('accountFormTitle');
    const accountNameInput = document.getElementById('accountNameInput');
    const accountEmailInput = document.getElementById('accountEmailInput');
    const accountSelect = document.getElementById('accountSelect');
    const manageAccountsBtn = document.getElementById('manageAccountsBtn');
    const accountResetBtn = document.getElementById('accountResetBtn');
    const tokenSaveBtn = document.getElementById('tokenSaveBtn');
    const tokenCancelBtn = document.getElementById('tokenCancelBtn');
    const STORAGE_ACCOUNTS = 'cf_mail_accounts';
    const STORAGE_ACTIVE_ACCOUNT = 'cf_mail_active_account';

    function loadAccounts() {
      try {
        const raw = localStorage.getItem(STORAGE_ACCOUNTS);
        const parsed = raw ? JSON.parse(raw) : [];
        if (Array.isArray(parsed)) return parsed;
      } catch (_) {}
      return [];
    }

    function sanitizeAccount(account) {
      return {
        id: String(account.id || '').trim(),
        name: String(account.name || '').trim(),
        email: String(account.email || '').trim(),
        token: String(account.token || '').trim(),
      };
    }

    const legacyToken = localStorage.getItem('cf_mail_token') || '';
    let accounts = loadAccounts().map(sanitizeAccount).filter((a) => a.id && a.name);
    if (!accounts.length && legacyToken) {
      accounts = [{
        id: 'acc-' + Date.now(),
        name: '默认账户',
        email: '',
        token: legacyToken,
      }];
    }

    let activeAccountId = localStorage.getItem(STORAGE_ACTIVE_ACCOUNT) || accounts[0]?.id || null;
    if (accounts.length && !accounts.some((a) => a.id === activeAccountId)) {
      activeAccountId = accounts[0].id;
    }

    let state = {
      messages: [],
      currentId: null,
      accounts,
      activeAccountId,
      editingAccountId: null,
    };

    function resetAccountForm() {
      state.editingAccountId = null;
      accountNameInput.value = '';
      accountEmailInput.value = '';
      tokenModalInput.value = '';
      accountFormTitle.textContent = '新增账户';
      tokenSaveBtn.textContent = '新增账户';
      accountResetBtn.style.display = 'none';
    }

    function startEditAccount(accountId) {
      const account = state.accounts.find((item) => item.id === accountId);
      if (!account) return;

      state.editingAccountId = account.id;
      accountNameInput.value = account.name || '';
      accountEmailInput.value = account.email || '';
      tokenModalInput.value = account.token || '';
      accountFormTitle.textContent = '编辑账户';
      tokenSaveBtn.textContent = '保存修改';
      accountResetBtn.style.display = 'inline-flex';
      setTimeout(() => accountNameInput.focus(), 0);
    }

    function persistAccounts() {
      localStorage.setItem(STORAGE_ACCOUNTS, JSON.stringify(state.accounts));
      if (state.activeAccountId) {
        localStorage.setItem(STORAGE_ACTIVE_ACCOUNT, state.activeAccountId);
      }
    }

    function getActiveAccount() {
      return state.accounts.find((a) => a.id === state.activeAccountId) || null;
    }

    function normalizeEmail(value) {
      return String(value || '').trim().toLowerCase();
    }

    function renderAccountSelect() {
      if (!state.accounts.length) {
        accountSelect.innerHTML = '<option value="">未配置账户</option>';
        return;
      }

      accountSelect.innerHTML = state.accounts.map((account) => {
        const selected = account.id === state.activeAccountId ? ' selected' : '';
        const label = account.email ? (account.name + ' (' + account.email + ')') : (account.name + ' (不过滤)');
        return '<option value="' + escapeHtml(account.id) + '"' + selected + '>' + escapeHtml(label) + '</option>';
      }).join('');
    }

    function renderAccountList() {
      if (!state.accounts.length) {
        accountListEl.innerHTML = '<div class="empty" style="padding:12px;">还没有账户，请先新增一个。</div>';
        return;
      }

      accountListEl.innerHTML = state.accounts.map((account) => {
        const isActive = account.id === state.activeAccountId;
        const badge = isActive ? '<span class="meta">当前</span>' : '';
        const emailText = account.email || '不过滤收件地址';
        return '<div class="account-row" data-account-id="' + escapeHtml(account.id) + '">' +
          '<div class="account-row-main">' +
            '<div class="account-name">' + escapeHtml(account.name) + ' ' + badge + '</div>' +
            '<div class="account-email">' + escapeHtml(emailText) + '</div>' +
          '</div>' +
          '<div style="display:flex;gap:6px;">' +
            '<button class="btn-secondary" data-action="edit">编辑</button>' +
            '<button class="btn-secondary" data-action="use">切换</button>' +
            '<button class="btn-secondary" data-action="delete">删除</button>' +
          '</div>' +
        '</div>';
      }).join('');
    }

    function applyAccountFilter(messages) {
      const account = getActiveAccount();
      if (!account) return [];
      const target = normalizeEmail(account.email);
      if (!target) return messages;

      return messages.filter((msg) => {
        const toValue = normalizeEmail(msg.to);
        return toValue.includes(target);
      });
    }

    function openTokenModal(canUseSavedToken=false) {
      tokenModal.classList.add('show');
      tokenModal.setAttribute('aria-hidden', 'false');
      resetAccountForm();
      renderAccountList();
      tokenCancelBtn.style.display = 'inline-flex';
      setTimeout(() => accountNameInput.focus(), 0);
    }

    function closeTokenModal() {
      tokenModal.classList.remove('show');
      tokenModal.setAttribute('aria-hidden', 'true');
      resetAccountForm();
    }

    function setStatus(text, type='') {
      statusEl.textContent = text;
      statusEl.className = 'status ' + type;
    }

    function showValidationError(message) {
      setStatus(message, 'err');
      alert(message);
    }

    function authHeaders() {
      const token = getActiveAccount()?.token || '';
      if (!token) return {};
      return { Authorization: 'Bearer ' + token };
    }

    async function api(path, init={}) {
      const res = await fetch(path, {
        ...init,
        headers: {
          'content-type': 'application/json',
          ...authHeaders(),
          ...(init.headers || {})
        }
      });
      if (!res.ok) {
        const msg = await res.text();
        throw new Error('[' + res.status + '] ' + msg);
      }
      return res.json();
    }

    function renderList() {
      const filteredMessages = applyAccountFilter(state.messages);
      countEl.textContent = filteredMessages.length + ' 封';
      if (!filteredMessages.length) {
        listEl.innerHTML = '<div class="empty">当前账户暂无邮件，或被收件地址过滤。</div>';
        return;
      }

      if (!filteredMessages.some((msg) => msg.id === state.currentId)) {
        state.currentId = filteredMessages[0].id;
      }

      listEl.innerHTML = filteredMessages.map(msg => {
        const active = msg.id === state.currentId ? 'active' : '';
        return '<div class="item ' + active + '" data-id="' + msg.id + '">' +
          '<div class="subject">' + escapeHtml(msg.subject || '(No Subject)') + '</div>' +
          '<div class="meta">From: ' + escapeHtml(msg.from || '-') + '</div>' +
          '<div class="meta">At: ' + new Date(msg.receivedAt).toLocaleString() + '</div>' +
          '<div class="preview">' + escapeHtml((msg.preview || '').slice(0, 120)) + '</div>' +
        '</div>';
      }).join('');

      listEl.querySelectorAll('.item').forEach(el => {
        el.addEventListener('click', () => openMessage(el.dataset.id));
      });
    }

    async function refresh() {
      const account = getActiveAccount();
      if (!account) {
        state.messages = [];
        state.currentId = null;
        renderList();
        detailEl.className = 'mail-body empty';
        detailEl.textContent = '请先在“账户设置”中新增账户';
        setStatus('未配置账户', 'err');
        return;
      }

      try {
        setStatus('正在刷新...', '');
        const data = await api('/api/messages');
        state.messages = data.messages || [];
        renderList();
        if (state.currentId) {
          await openMessage(state.currentId, true);
        } else {
          detailEl.className = 'mail-body empty';
          detailEl.textContent = '请选择左侧邮件查看内容';
        }
        setStatus('刷新完成', 'ok');
      } catch (err) {
        setStatus('刷新失败: ' + err.message, 'err');
      }
    }

    async function openMessage(id, silent=false) {
      if (!id) return;
      try {
        state.currentId = id;
        renderList();
        const msg = await api('/api/messages/' + encodeURIComponent(id));
        detailEl.className = 'mail-body';
        detailEl.innerHTML =
          '<div class="mail-top">' +
            '<div><strong>' + escapeHtml(msg.subject || '(No Subject)') + '</strong></div>' +
            '<div class="meta">From: ' + escapeHtml(msg.from || '-') + '</div>' +
            '<div class="meta">To: ' + escapeHtml(msg.to || '-') + '</div>' +
            '<div class="meta">Size: ' + (msg.size || 0) + ' bytes</div>' +
            '<div class="meta">Received: ' + new Date(msg.receivedAt).toLocaleString() + '</div>' +
          '</div>' +
          '<div class="content">' + escapeHtml(msg.textBody || '(空正文)') + '</div>';
        if (!silent) setStatus('已加载邮件详情', 'ok');
      } catch (err) {
        detailEl.className = 'mail-body empty';
        detailEl.textContent = '邮件加载失败: ' + err.message;
        setStatus('详情加载失败: ' + err.message, 'err');
      }
    }

    async function deleteCurrent() {
      if (!state.currentId) return;
      try {
        const deletingId = state.currentId;
        await api('/api/messages/' + encodeURIComponent(deletingId), { method: 'DELETE' });
        state.messages = state.messages.filter(m => m.id !== deletingId);
        state.currentId = state.messages[0]?.id || null;
        renderList();
        if (state.currentId) {
          await openMessage(state.currentId, true);
        } else {
          detailEl.className = 'mail-body empty';
          detailEl.textContent = '没有可显示的邮件';
        }
        setStatus('删除成功', 'ok');
      } catch (err) {
        setStatus('删除失败: ' + err.message, 'err');
      }
    }

    async function clearAll() {
      if (!confirm('确认清空所有邮件吗？')) return;
      try {
        await api('/api/clear', { method: 'POST', body: '{}' });
        state.messages = [];
        state.currentId = null;
        renderList();
        detailEl.className = 'mail-body empty';
        detailEl.textContent = '所有邮件已清空';
        setStatus('清空成功', 'ok');
      } catch (err) {
        setStatus('清空失败: ' + err.message, 'err');
      }
    }

    function escapeHtml(v) {
      return String(v)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function validateNewAccount(name, email, token, editingAccountId='') {
      const normalizedName = name.trim();
      const normalizedEmail = normalizeEmail(email || '');
      const normalizedToken = token.trim();

      if (!normalizedName) return '请填写账户名称';
      if (normalizedName.length < 2 || normalizedName.length > 32) {
        return '账户名称长度需在 2-32 个字符之间';
      }

      if (!normalizedEmail) return '请填写收件地址';

      if (!normalizedToken) return '请填写 Dashboard Token';

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(normalizedEmail)) return '收件地址格式不正确';

      const nameExists = state.accounts.some((item) => item.id !== editingAccountId && item.name.trim().toLowerCase() === normalizedName.toLowerCase());
      if (nameExists) return '账户名称已存在，请使用其他名称';

      if (normalizedEmail) {
        const emailExists = state.accounts.some((item) => item.id !== editingAccountId && normalizeEmail(item.email) === normalizedEmail);
        if (emailExists) return '该收件地址已被其他账户使用';
      }

      return '';
    }

    async function ensureMailboxExists(email) {
      const normalizedEmail = normalizeEmail(email || '');
      try {
        const result = await api('/api/mailboxes/exists?address=' + encodeURIComponent(normalizedEmail));
        return !!result.exists;
      } catch (err) {
        showValidationError('邮箱存在性校验失败: ' + err.message);
        return false;
      }
    }

    async function saveTokenAndRefresh() {
      const name = accountNameInput.value.trim();
      const email = accountEmailInput.value.trim();
      const token = tokenModalInput.value.trim();
      const editingAccountId = state.editingAccountId || '';

      const validationError = validateNewAccount(name, email, token, editingAccountId);
      if (validationError) {
        showValidationError(validationError);
        return;
      }

      const mailboxExists = await ensureMailboxExists(email);
      if (!mailboxExists) {
        showValidationError('该收件地址不存在或当前账号无权限访问，请先确认邮箱路由已配置。');
        return;
      }

      if (editingAccountId) {
        const index = state.accounts.findIndex((item) => item.id === editingAccountId);
        if (index < 0) {
          showValidationError('账户不存在或已删除，请重试');
          resetAccountForm();
          renderAccountList();
          return;
        }

        state.accounts[index] = {
          ...state.accounts[index],
          name,
          email,
          token,
        };
      } else {
        const account = {
          id: 'acc-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7),
          name,
          email,
          token,
        };

        state.accounts.push(account);
        state.activeAccountId = account.id;
      }

      persistAccounts();
      renderAccountSelect();
      renderAccountList();
      resetAccountForm();

      closeTokenModal();
      setStatus(editingAccountId ? '账户已更新' : '账户已新增', 'ok');
      await refresh();
    }

    tokenSaveBtn.addEventListener('click', saveTokenAndRefresh);
    [accountNameInput, accountEmailInput, tokenModalInput].forEach((el) => el.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        saveTokenAndRefresh();
      }
    }));

    tokenCancelBtn.addEventListener('click', () => {
      closeTokenModal();
    });

    accountResetBtn.addEventListener('click', () => {
      resetAccountForm();
      setStatus('已取消编辑', 'ok');
    });

    manageAccountsBtn.addEventListener('click', () => {
      openTokenModal(true);
    });

    accountSelect.addEventListener('change', async () => {
      state.activeAccountId = accountSelect.value || null;
      state.currentId = null;
      persistAccounts();
      await refresh();
    });

    accountListEl.addEventListener('click', async (event) => {
      const btn = event.target.closest('button[data-action]');
      if (!btn) return;
      const row = event.target.closest('.account-row');
      if (!row) return;

      const accountId = row.dataset.accountId;
      if (!accountId) return;

      const action = btn.dataset.action;
      if (action === 'edit') {
        startEditAccount(accountId);
        setStatus('正在编辑账户', 'ok');
        return;
      }

      if (action === 'use') {
        state.activeAccountId = accountId;
        state.currentId = null;
        persistAccounts();
        renderAccountSelect();
        renderAccountList();
        closeTokenModal();
        await refresh();
        return;
      }

      if (action === 'delete') {
        const target = state.accounts.find((a) => a.id === accountId);
        if (!target) return;
        if (!confirm('确认删除账户：' + target.name + ' ?')) return;

        state.accounts = state.accounts.filter((a) => a.id !== accountId);
        if (state.editingAccountId === accountId) {
          resetAccountForm();
        }
        if (!state.accounts.length) {
          state.activeAccountId = null;
        } else if (state.activeAccountId === accountId) {
          state.activeAccountId = state.accounts[0].id;
        }

        persistAccounts();
        renderAccountSelect();
        renderAccountList();
        state.currentId = null;
        await refresh();
      }
    });

    document.getElementById('refreshBtn').addEventListener('click', refresh);
    document.getElementById('deleteBtn').addEventListener('click', deleteCurrent);
    document.getElementById('clearBtn').addEventListener('click', clearAll);

    renderAccountSelect();
    if (!state.accounts.length) {
      openTokenModal(true);
    } else {
      refresh();
    }

    (() => {
      const c = document.getElementById('particles');
      const ctx = c.getContext('2d');
      const pts = [];

      function resize() {
        c.width = window.innerWidth;
        c.height = window.innerHeight;
      }

      function spawn() {
        while (pts.length < 80) {
          pts.push({
            x: Math.random() * c.width,
            y: Math.random() * c.height,
            vx: (Math.random() - 0.5) * 0.35,
            vy: (Math.random() - 0.5) * 0.35,
            r: Math.random() * 1.8 + 0.6,
          });
        }
      }

      function step() {
        ctx.clearRect(0, 0, c.width, c.height);
        for (const p of pts) {
          p.x += p.vx;
          p.y += p.vy;
          if (p.x < -10) p.x = c.width + 10;
          if (p.x > c.width + 10) p.x = -10;
          if (p.y < -10) p.y = c.height + 10;
          if (p.y > c.height + 10) p.y = -10;

          ctx.beginPath();
          ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(129, 154, 147, 0.38)';
          ctx.fill();
        }

        for (let i = 0; i < pts.length; i++) {
          for (let j = i + 1; j < pts.length; j++) {
            const a = pts[i];
            const b = pts[j];
            const dx = a.x - b.x;
            const dy = a.y - b.y;
            const d = Math.hypot(dx, dy);
            if (d < 120) {
              const alpha = 1 - d / 120;
              ctx.strokeStyle = 'rgba(167, 146, 162,' + (alpha * 0.22).toFixed(3) + ')';
              ctx.lineWidth = 1;
              ctx.beginPath();
              ctx.moveTo(a.x, a.y);
              ctx.lineTo(b.x, b.y);
              ctx.stroke();
            }
          }
        }

        requestAnimationFrame(step);
      }

      window.addEventListener('resize', resize);
      resize();
      spawn();
      step();
    })();
  </script>
</body>
</html>`;
}
