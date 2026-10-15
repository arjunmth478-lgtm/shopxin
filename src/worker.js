
const ADMIN_EMAIL = "arjunmth2007@gmail.com";
const ADMIN_PASSWORD = "Raftaar@123";
const SESSION_DAYS = 7;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers
    }
  });

const bad = (error, status = 400) => json({ ok: false, error }, status);
const uid = () => crypto.randomUUID();
const enc = new TextEncoder();

async function sha256(value) {
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return [...new Uint8Array(hash)]
    .map(x => x.toString(16).padStart(2, "0")).join("");
}

async function passwordHash(password, salt) {
  return sha256(`${salt}:${password}`);
}

function cookieValue(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const item = cookie.split(";").map(v => v.trim())
    .find(v => v.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : "";
}

function sessionCookie(token, maxAge = SESSION_DAYS * 86400) {
  return `shopnix_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function getSession(request, env) {
  const token = cookieValue(request, "shopnix_session");
  if (!token) return null;

  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    "SELECT user_id, role, expires_at FROM sessions WHERE token_hash = ? AND expires_at > ?"
  ).bind(tokenHash, Math.floor(Date.now() / 1000)).first();

  return row ? { ...row, tokenHash } : null;
}

async function newSession(env, userId, role) {
  const token = `${uid()}${uid().replaceAll("-", "")}`;
  const tokenHash = await sha256(token);
  const expires = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;

  await env.DB.prepare(
    "INSERT INTO sessions (token_hash,user_id,role,expires_at) VALUES (?,?,?,?)"
  ).bind(tokenHash, userId, role, expires).run();

  return token;
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function str(value, max = 500) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function int(value, min = 0, max = 100000000) {
  const n = Number(value);
  return Number.isInteger(n) && n >= min && n <= max ? n : null;
}

async function allSettings(env) {
  const result = await env.DB.prepare(
    "SELECT key,value FROM settings"
  ).all();

  return Object.fromEntries(
    (result.results || []).map(row => [row.key, row.value])
  );
}

async function ensureColumn(env, table, column, definition) {
  const info = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
  const exists = (info.results || []).some(row => row.name === column);

  if (!exists) {
    await env.DB.prepare(
      `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
    ).run();
  }
}

async function ensureSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS visits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      visited_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','customer')),
      expires_at INTEGER NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await ensureColumn(env, "products", "description", "TEXT NOT NULL DEFAULT ''");
  await ensureColumn(env, "products", "category", "TEXT NOT NULL DEFAULT 'General'");
  await ensureColumn(env, "products", "price_paise", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(env, "products", "stock", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(env, "products", "image_url", "TEXT NOT NULL DEFAULT ''");
  await ensureColumn(env, "products", "active", "INTEGER NOT NULL DEFAULT 1");
  await ensureColumn(env, "products", "created_at", "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP");
}

function productOut(p) {
  return {
    id: p.id,
    name: p.name,
    description: p.description || "",
    category: p.category || "General",
    price: Number(p.price_paise || 0) / 100,
    stock: Number(p.stock || 0),
    imageUrl: p.image_url || "",
    active: Boolean(p.active)
  };
}

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (method === "GET" && path === "/api/health") {
    return json({ ok: true, app: "Shopnix" });
  }

  await ensureSchema(env);

  if (method === "GET" && path === "/api/bootstrap") {
    const [products, categories, settings, visits] = await Promise.all([
      env.DB.prepare(
        "SELECT * FROM products WHERE active=1 ORDER BY created_at DESC"
      ).all(),
      env.DB.prepare("SELECT id,name FROM categories ORDER BY name").all(),
      allSettings(env),
      env.DB.prepare("SELECT COUNT(*) AS n FROM visits").first()
    ]);

    return json({
      ok: true,
      products: (products.results || []).map(productOut),
      categories: categories.results || [],
      settings,
      visits: Number(visits?.n || 0)
    });
  }

  if (method === "POST" && path === "/api/visit") {
    await env.DB.prepare("INSERT INTO visits DEFAULT VALUES").run();
    return json({ ok: true });
  }

  if (method === "POST" && path === "/api/register") {
    const body = await readBody(request);
    if (!body) return bad("Invalid request.");

    const name = str(body.name, 100);
    const email = str(body.email, 254).toLowerCase();
    const password = typeof body.password === "string" ? body.password : "";

    if (name.length < 2 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return bad("Enter a valid name and email.");
    }

    if (password.length < 8) {
      return bad("Password must be at least 8 characters.");
    }

    const id = uid();
    const salt = uid();
    const hash = `${salt}:${await passwordHash(password, salt)}`;

    try {
      await env.DB.prepare(
        "INSERT INTO users (id,name,email,password_hash) VALUES (?,?,?,?)"
      ).bind(id, name, email, hash).run();

      const token = await newSession(env, id, "customer");

      return json({
        ok: true,
        user: { id, name, email, role: "customer" }
      }, 201, { "set-cookie": sessionCookie(token) });
    } catch (error) {
      console.error("Registration error:", String(error));
      return bad("Registration failed. This email may already be registered.", 409);
    }
  }

  if (method === "POST" && path === "/api/login") {
    const body = await readBody(request);
    if (!body) return bad("Invalid request.");

    const email = str(body.email, 254).toLowerCase();
    const password = typeof body.password === "string" ? body.password : "";

    if (email === ADMIN_EMAIL.toLowerCase()) {
      if (ADMIN_PASSWORD.startsWith("CHANGE_THIS_")) {
        return bad("Set ADMIN_PASSWORD in worker.js before admin login.", 500);
      }

      const valid = (await sha256(password)) === (await sha256(ADMIN_PASSWORD));
      if (!valid) return bad("Email or password is incorrect.", 401);

      const token = await newSession(env, "admin", "admin");
      return json({
        ok: true,
        user: {
          id: "admin",
          name: "Shopnix Admin",
          email: ADMIN_EMAIL,
          role: "admin"
        }
      }, 200, { "set-cookie": sessionCookie(token) });
    }

    const user = await env.DB.prepare(
      "SELECT id,name,email,password_hash FROM users WHERE email=? COLLATE NOCASE"
    ).bind(email).first();

    if (!user) return bad("Email or password is incorrect.", 401);

    const parts = String(user.password_hash).split(":");
    if (parts.length !== 2 ||
        await passwordHash(password, parts[0]) !== parts[1]) {
      return bad("Email or password is incorrect.", 401);
    }

    const token = await newSession(env, user.id, "customer");
    return json({
      ok: true,
      user: { id: user.id, name: user.name, email: user.email, role: "customer" }
    }, 200, { "set-cookie": sessionCookie(token) });
  }

  if (method === "GET" && path === "/api/me") {
    const session = await getSession(request, env);
    if (!session) return json({ ok: true, user: null });

    if (session.role === "admin") {
      return json({
        ok: true,
        user: {
          id: "admin",
          name: "Shopnix Admin",
          email: ADMIN_EMAIL,
          role: "admin"
        }
      });
    }

    const user = await env.DB.prepare(
      "SELECT id,name,email FROM users WHERE id=?"
    ).bind(session.user_id).first();

    return json({
      ok: true,
      user: user ? { ...user, role: "customer" } : null
    });
  }

  if (method === "POST" && path === "/api/logout") {
    const session = await getSession(request, env);

    if (session) {
      await env.DB.prepare(
        "DELETE FROM sessions WHERE token_hash=?"
      ).bind(session.tokenHash).run();
    }

    return json({ ok: true }, 200, {
      "set-cookie": sessionCookie("", 0)
    });
  }

  if (path.startsWith("/api/admin/")) {
    const session = await getSession(request, env);

    if (!session || session.role !== "admin") {
      return bad("Admin login required.", 401);
    }

    if (method === "GET" && path === "/api/admin/data") {
      const [products, categories, settings, visits, customers] = await Promise.all([
        env.DB.prepare("SELECT * FROM products ORDER BY created_at DESC").all(),
        env.DB.prepare("SELECT id,name FROM categories ORDER BY name").all(),
        allSettings(env),
        env.DB.prepare("SELECT COUNT(*) AS n FROM visits").first(),
        env.DB.prepare("SELECT COUNT(*) AS n FROM users").first()
      ]);

      return json({
        ok: true,
        products: (products.results || []).map(productOut),
        categories: categories.results || [],
        settings,
        visits: Number(visits?.n || 0),
        customers: Number(customers?.n || 0)
      });
    }

    if (method === "POST" && path === "/api/admin/products") {
      const body = await readBody(request);
      if (!body) return bad("Invalid request.");

      const id = str(body.id, 100) || uid();
      const name = str(body.name, 160);
      const description = str(body.description, 1000);
      const category = str(body.category, 100);
      const price = Number(body.price);
      const stock = int(body.stock, 0, 1000000);
      const imageUrl = str(body.imageUrl, 1500);

      if (!name || !category || !Number.isFinite(price) ||
          price < 0 || price > 10000000 || stock === null) {
        return bad("Check product name, category, price and stock.");
      }

      if (imageUrl && !/^https:\/\/|^data:image\//i.test(imageUrl)) {
        return bad("Product image must use HTTPS or an image data URL.");
      }

      await env.DB.prepare(`
        INSERT INTO products
          (id,name,description,category,price_paise,stock,image_url,active)
        VALUES (?,?,?,?,?,?,?,1)
        ON CONFLICT(id) DO UPDATE SET
          name=excluded.name,
          description=excluded.description,
          category=excluded.category,
          price_paise=excluded.price_paise,
          stock=excluded.stock,
          image_url=excluded.image_url,
          active=1
      `).bind(
        id, name, description, category,
        Math.round(price * 100), stock, imageUrl
      ).run();

      return json({ ok: true, id });
    }

    if (method === "DELETE" && path.startsWith("/api/admin/products/")) {
      const id = decodeURIComponent(path.split("/").pop());
      await env.DB.prepare("DELETE FROM products WHERE id=?").bind(id).run();
      return json({ ok: true });
    }

    if (method === "POST" && path === "/api/admin/categories") {
      const body = await readBody(request);
      const name = str(body?.name, 100);
      if (!name) return bad("Category name required.");

      const id = uid();

      try {
        await env.DB.prepare(
          "INSERT INTO categories (id,name) VALUES (?,?)"
        ).bind(id, name).run();

        return json({ ok: true, id, name });
      } catch {
        return bad("Category already exists.", 409);
      }
    }

    if (method === "DELETE" && path.startsWith("/api/admin/categories/")) {
      const id = decodeURIComponent(path.split("/").pop());
      const category = await env.DB.prepare(
        "SELECT name FROM categories WHERE id=?"
      ).bind(id).first();

      if (category) {
        const count = await env.DB.prepare(
          "SELECT COUNT(*) AS n FROM products WHERE category=?"
        ).bind(category.name).first();

        if (Number(count?.n || 0) > 0) {
          return bad("Move or delete products in this category first.");
        }

        await env.DB.prepare(
          "DELETE FROM categories WHERE id=?"
        ).bind(id).run();
      }

      return json({ ok: true });
    }

    if (method === "POST" && path === "/api/admin/settings") {
      const body = await readBody(request);
      const allowed = ["whatsapp", "telegram", "banner_text", "store_name"];

      for (const key of allowed) {
        if (typeof body?.[key] === "string") {
          const value = str(body[key], key === "banner_text" ? 300 : 160);

          await env.DB.prepare(`
            INSERT INTO settings (key,value) VALUES (?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
          `).bind(key, value).run();
        }
      }

      return json({ ok: true });
    }

    if (method === "GET" && path === "/api/admin/backup") {
      const [products, categories, settings, users] = await Promise.all([
        env.DB.prepare("SELECT * FROM products").all(),
        env.DB.prepare("SELECT * FROM categories").all(),
        env.DB.prepare("SELECT * FROM settings").all(),
        env.DB.prepare("SELECT id,name,email,created_at FROM users").all()
      ]);

      return json({
        ok: true,
        exportedAt: new Date().toISOString(),
        products: products.results || [],
        categories: categories.results || [],
        settings: settings.results || [],
        customers: users.results || []
      });
    }

    return bad("Admin endpoint not found.", 404);
  }

  return bad("API endpoint not found.", 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await api(request, env);
      } catch (error) {
        console.error("Shopnix API error:", error?.stack || String(error));
        return json({
          ok: false,
          error: "Server error. Check Cloudflare Workers > Observability > Logs."
        }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
