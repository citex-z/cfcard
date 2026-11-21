/**
 * 卡密验证后端 —— Cloudflare Pages Functions + D1 版
 *
 * D1 是 Cloudflare 免费的 SQLite 数据库（免费套餐无需绑卡）。
 * 与 R2 版接口完全一致，只是数据层换成 SQL。
 *
 * 数据库绑定名 DB。
 *
 * 接口：
 *   POST /api/verify    卡密验证/绑定
 *   POST /api/check     APK 签名校验
 *   GET  /api/notice    应用公告
 *   POST /api/admin     管理接口（act 分发）
 */

import { hashPassword, verifyPassword } from "../lib/password.js";
import { randomToken, sha256Hex, generateCardKey, generateAppId, nowIso, today, json } from "../lib/util.js";
import { md5 } from "../lib/md5.js";

const DB = env => env.DB;
const TOKEN_TTL = 86400 * 30;

/* ---------- 建表（幂等，首次请求自动建） ---------- */
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  // 表结构在建表.sql 里，已在 D1 控制台手动执行过。
  // 这里只做一次探测：确认 admin 表存在，不存在则给出明确提示。
  try {
    await DB(env).prepare("SELECT 1 FROM admin LIMIT 1").first();
  } catch (e) {
    throw new Error("数据库表尚未创建，请先在 D1 控制台执行 建表.sql（原始错误：" + (e.message || e) + "）");
  }
  schemaReady = true;
}



/* ============================== 客户端接口 ============================== */

/**
 * 取请求参数。网页后台发 multipart/form-data，安卓 App 端发
 * application/x-www-form-urlencoded；formData() 对后者在个别边缘环境会返回
 * null，所以留一个手工解析的兜底。
 */
async function formOf(request) {
  const q = await request.formData().catch(() => null);
  if (q) return q;
  const ct = request.headers.get("content-type") || "";
  if (!ct.startsWith("application/x-www-form-urlencoded")) return null;
  const text = await request.text().catch(() => "");
  const map = {};
  new URLSearchParams(text).forEach((v, k) => { map[k] = v; });
  return { get: k => (k in map ? map[k] : null) };
}

async function handleVerify(request, env) {
  await ensureSchema(env);
  const form = await formOf(request);
  if (!form) return json({ status: "error", message: "请求格式错误" });
  const app_id = (form.get("app_id") || "").trim();
  const card_key = (form.get("card_key") || "").trim();
  const device_id = (form.get("device_id") || "").trim();

  if (!app_id) return json({ status: "error", message: "缺少应用ID" });
  const app = await DB(env).prepare("SELECT status FROM apps WHERE app_id = ?").bind(app_id).first();
  if (!app) return json({ status: "error", message: "应用不存在" });
  if (app.status === 0) return json({ status: "error", message: "应用已被封禁" });

  const card = await DB(env).prepare(
    "SELECT device_id, banned, expiry_date FROM bindings WHERE card_key = ? AND app_id = ?"
  ).bind(card_key, app_id).first();
  if (!card) return json({ status: "error", message: "卡密不存在" });
  if (card.banned === 1) return json({ status: "error", message: "卡密已被封禁" });
  if (card.expiry_date < today()) return json({ status: "error", message: "卡密已过期" });

  if (!card.device_id) {
    await DB(env).prepare(
      "UPDATE bindings SET device_id = ?, bind_date = ? WHERE card_key = ? AND app_id = ?"
    ).bind(device_id, nowIso(), card_key, app_id).run();
    return json({ status: "success", message: "卡密绑定成功", expiry_date: card.expiry_date });
  }
  if (card.device_id === device_id) {
    return json({ status: "success", message: "验证成功", expiry_date: card.expiry_date });
  }
  return json({ status: "error", message: "该卡密已绑定到其他设备" });
}

async function handleCheck(request, env) {
  await ensureSchema(env);
  const form = await formOf(request);
  if (!form) return json({ status: "ok" });
  const app_id = (form.get("app_id") || "").trim();
  const sig_cert = form.get("sig_cert") || "";
  if (!app_id) return json({ status: "ok" });

  const app = await DB(env).prepare("SELECT sig_md5, sig_sha1, sig_sha256 FROM apps WHERE app_id = ?").bind(app_id).first();
  if (!app) return json({ status: "ok" });
  if (!(app.sig_md5 || app.sig_sha1 || app.sig_sha256)) return json({ status: "ok" });
  if (!sig_cert) return json({ status: "ok" });   // 取不到证书时放行，不能误判成破解

  const b64 = sig_cert.replace(/-/g, "+").replace(/_/g, "/");
  let certBytes;
  try {
    certBytes = Uint8Array.from(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "=")), c => c.charCodeAt(0));
  } catch (e) {
    return json({ status: "ok" });   // 非法 base64 同理：放行而不是 500
  }
  const md5fp = await md5Hex(certBytes);
  const sha1 = await digestHex("SHA-1", certBytes);
  const sha256 = await digestHex("SHA-256", certBytes);

  const norm = s => (s || "").toLowerCase().replace(/[^a-f0-9]/g, "");
  for (const [stored, computed] of [[app.sig_md5, md5fp], [app.sig_sha1, sha1], [app.sig_sha256, sha256]]) {
    if (stored && norm(stored) !== norm(computed)) return json({ status: "crack", message: "请勿破解" });
  }
  return json({ status: "ok" });
}

async function handleNotice(request, env) {
  await ensureSchema(env);
  const url = new URL(request.url);
  const app_id = (url.searchParams.get("app_id") || "").trim();
  if (!app_id) return json({ notice: "" });
  const app = await DB(env).prepare("SELECT status, notice FROM apps WHERE app_id = ?").bind(app_id).first();
  if (!app || app.status === 0) return json({ notice: "" });
  return json({ notice: app.notice || "" });
}

/* ============================== 管理端接口 ============================== */

async function handleAdmin(request, env) {
  await ensureSchema(env);
  const form = await formOf(request);
  const q = form || new URL(request.url).searchParams;
  const get = k => (q.get(k) || "").trim();
  const act = get("act");
  if (!act) return json({ ok: false, msg: "缺少 act 参数" });

  if (act === "login") {
    const u = get("username"), p = get("password");
    if (!u || !p) return json({ ok: false, msg: "请输入用户名和密码" });
    const admin = await DB(env).prepare("SELECT username, password_hash, salt FROM admin WHERE username = ?").bind(u).first();
    if (!admin) return json({ ok: false, msg: "用户名或密码错误" });
    if (!(await verifyPassword(p, admin.salt, admin.password_hash))) return json({ ok: false, msg: "用户名或密码错误" });
    const token = await issueToken(env, u);
    return json({ ok: true, token, username: u });
  }

  const username = await checkToken(env, get("token"));
  if (!username) return json({ ok: false, msg: "登录已失效，请重新登录" });

  switch (act) {
    case "logout": {
      await DB(env).prepare("DELETE FROM api_tokens WHERE token_hash = ?").bind(await sha256Hex(get("token"))).run();
      return json({ ok: true });
    }
    case "ping":
      return json({ ok: true, username });

    case "overview": return await overview(env, username);
    case "apps": return await listApps(env);
    case "create_app": return await createApp(env, get("app_name"));
    case "ban_app": return await setAppStatus(env, get("app_id"), 0);
    case "unban_app": return await setAppStatus(env, get("app_id"), 1);
    case "delete_app": return await deleteApp(env, get("app_id"));
    case "set_notice": return await setNotice(env, get("app_id"), get("notice"));
    case "set_signature": return await setSignature(env, get("app_id"), get("sig_md5"), get("sig_sha1"), get("sig_sha256"));

    case "cards": return await listCards(env, get("app_id"), get("keyword"), parseInt(get("limit") || "200", 10));
    case "generate_cards": return await generateCards(env, get("app_id"), get("expiry_date"), parseInt(get("quantity"), 10));
    case "ban_card": return await setCardBanned(env, get("app_id"), get("card_key"), 1);
    case "unban_card": return await setCardBanned(env, get("app_id"), get("card_key"), 0);
    case "unbind_card": return await unbindCard(env, get("app_id"), get("card_key"));
    case "delete_card": return await deleteCard(env, get("app_id"), get("card_key"));
    case "update_expiry": return await updateExpiry(env, get("app_id"), get("card_key"), get("new_expiry"));
    case "change_password": return await changePassword(env, username, get("old_password"), get("new_password"), get("new_password2"));
  }
  return json({ ok: false, msg: "未知操作：" + act });
}

/* ------------------------------ 概览 ------------------------------ */

async function overview(env, username) {
  const t = today();
  const one = async sql => Number((await DB(env).prepare(sql).first())["c"] || 0);
  const stats = {
    apps: await one("SELECT COUNT(*) c FROM apps"),
    apps_banned: await one("SELECT COUNT(*) c FROM apps WHERE status = 0"),
    cards: await one("SELECT COUNT(*) c FROM bindings"),
    bound: await one("SELECT COUNT(*) c FROM bindings WHERE device_id != ''"),
    expired: await one(`SELECT COUNT(*) c FROM bindings WHERE expiry_date < '${t}'`),
    cards_banned: await one("SELECT COUNT(*) c FROM bindings WHERE banned = 1"),
  };
  stats.unbound = stats.cards - stats.bound;
  const recent = await DB(env).prepare(
    "SELECT app_id, card_key, device_id, bind_date, banned, expiry_date FROM bindings ORDER BY id DESC LIMIT 10"
  ).all();
  return json({ ok: true, stats, recent: recent.results || [], username });
}

/* ------------------------------ 应用 ------------------------------ */

async function listApps(env) {
  const r = await DB(env).prepare(
    `SELECT a.app_id, a.app_name, a.status, a.notice, a.sig_md5, a.sig_sha1, a.sig_sha256, a.created_at,
            (SELECT COUNT(*) FROM bindings b WHERE b.app_id = a.app_id) AS card_count
       FROM apps a ORDER BY a.created_at DESC, a.app_id DESC`
  ).all();
  const apps = (r.results || []).map(a => ({ ...a, sig_on: !!(a.sig_md5 || a.sig_sha1 || a.sig_sha256) }));
  return json({ ok: true, apps });
}

async function createApp(env, name) {
  if (!name) return json({ ok: false, msg: "应用名不能为空" });
  let appId = generateAppId();
  for (let i = 0; i < 20; i++) {
    const e = await DB(env).prepare("SELECT 1 FROM apps WHERE app_id = ?").bind(appId).first();
    if (!e) break;
    appId = generateAppId();
  }
  await DB(env).prepare("INSERT INTO apps (app_id, app_name) VALUES (?, ?)").bind(appId, name).run();
  return json({ ok: true, app_id: appId, app_name: name, msg: "应用创建成功" });
}

async function setAppStatus(env, appId, status) {
  if (!appId) return json({ ok: false, msg: "缺少应用ID" });
  await DB(env).prepare("UPDATE apps SET status = ? WHERE app_id = ?").bind(status, appId).run();
  return json({ ok: true, msg: status === 0 ? "应用已封禁" : "应用已解封" });
}

async function deleteApp(env, appId) {
  if (!appId) return json({ ok: false, msg: "缺少应用ID" });
  // 不用 batch()：Cloudflare 打包时会丢掉 batch 对象里的 sql 字段
  await DB(env).prepare("DELETE FROM bindings WHERE app_id = ?").bind(appId).run();
  await DB(env).prepare("DELETE FROM apps WHERE app_id = ?").bind(appId).run();
  return json({ ok: true, msg: "应用及其卡密已删除" });
}

async function setNotice(env, appId, notice) {
  if (!appId) return json({ ok: false, msg: "请选择应用" });
  await DB(env).prepare("UPDATE apps SET notice = ? WHERE app_id = ?").bind(notice, appId).run();
  return json({ ok: true, msg: notice ? "公告已保存" : "公告已清除", notice });
}

async function setSignature(env, appId, md5v, sha1, sha256) {
  if (!appId) return json({ ok: false, msg: "请选择应用" });
  const norm = s => (s || "").toLowerCase().replace(/[^a-f0-9]/g, "");
  md5v = norm(md5v); sha1 = norm(sha1); sha256 = norm(sha256);
  for (const [s, len, label] of [[md5v, 32, "MD5"], [sha1, 40, "SHA1"], [sha256, 64, "SHA256"]]) {
    if (s && s.length !== len) return json({ ok: false, msg: `${label} 长度不对（应为 ${len} 位十六进制）` });
  }
  await DB(env).prepare("UPDATE apps SET sig_md5 = ?, sig_sha1 = ?, sig_sha256 = ? WHERE app_id = ?")
    .bind(md5v, sha1, sha256, appId).run();
  const on = !!(md5v || sha1 || sha256);
  return json({ ok: true, msg: on ? "签名指纹已保存" : "签名校验已关闭", sig_on: on });
}

/* ------------------------------ 卡密 ------------------------------ */

async function listCards(env, appId, keyword, limit) {
  if (!limit || limit <= 0 || limit > 1000) limit = 200;
  let sql = "SELECT app_id, card_key, device_id, bind_date, banned, expiry_date FROM bindings WHERE 1=1";
  const args = [];
  if (appId) { sql += " AND app_id = ?"; args.push(appId); }
  if (keyword) { sql += " AND (card_key LIKE ? OR device_id LIKE ?)"; args.push(`%${keyword}%`, `%${keyword}%`); }
  sql += " ORDER BY id DESC LIMIT ?";
  args.push(limit);
  const r = await DB(env).prepare(sql).bind(...args).all();
  return json({ ok: true, cards: r.results || [] });
}

async function generateCards(env, appId, expiryRaw, qty) {
  if (!appId) return json({ ok: false, msg: "请先选择应用" });
  if (!(await DB(env).prepare("SELECT 1 FROM apps WHERE app_id = ?").bind(appId).first()))
    return json({ ok: false, msg: "应用不存在" });
  if (!(qty > 0 && qty <= 100)) return json({ ok: false, msg: "生成数量需在 1~100 之间" });
  const digits = expiryRaw.replace(/-/g, "");
  if (!/^\d{8}$/.test(digits)) return json({ ok: false, msg: "到期时间格式应为 YYYYMMDD（例如 20261231）" });
  const exp = `${digits.slice(0, 4)}-${digits.slice(4, 6)}-${digits.slice(6, 8)}`;

  const stmt = DB(env).prepare("INSERT INTO bindings (app_id, card_key, expiry_date) VALUES (?, ?, ?)");
  const keys = [];
  for (let i = 0; i < qty; i++) {
    let ck = generateCardKey();
    for (let t = 0; t < 5; t++) {
      const e = await DB(env).prepare("SELECT 1 FROM bindings WHERE card_key = ? AND app_id = ?").bind(ck, appId).first();
      if (!e) break;
      ck = generateCardKey();
    }
    await stmt.bind(appId, ck, exp).run();
    keys.push(ck);
  }
  if (!keys.length) return json({ ok: false, msg: "生成失败，请重试" });
  return json({ ok: true, keys, msg: `成功生成 ${keys.length} 张卡密` });
}

async function setCardBanned(env, appId, cardKey, banned) {
  if (!cardKey) return json({ ok: false, msg: "缺少卡密" });
  await DB(env).prepare("UPDATE bindings SET banned = ? WHERE card_key = ? AND app_id = ?").bind(banned, cardKey, appId).run();
  return json({ ok: true, msg: banned ? "卡密已封禁" : "卡密已解封" });
}

async function unbindCard(env, appId, cardKey) {
  if (!cardKey) return json({ ok: false, msg: "缺少卡密" });
  await DB(env).prepare("UPDATE bindings SET device_id = '', bind_date = '' WHERE card_key = ? AND app_id = ?").bind(cardKey, appId).run();
  return json({ ok: true, msg: "设备已解绑" });
}

async function deleteCard(env, appId, cardKey) {
  if (!cardKey) return json({ ok: false, msg: "缺少卡密" });
  await DB(env).prepare("DELETE FROM bindings WHERE card_key = ? AND app_id = ?").bind(cardKey, appId).run();
  return json({ ok: true, msg: "卡密已删除" });
}

async function updateExpiry(env, appId, cardKey, newExpiry) {
  const digits = (newExpiry || "").replace(/-/g, "");
  if (!cardKey || !/^\d{8}$/.test(digits)) return json({ ok: false, msg: "参数不完整或日期格式不对（YYYYMMDD）" });
  const date = `${digits.slice(0, 4)}-${digits.slice(4, 6)}-${digits.slice(6, 8)}`;
  await DB(env).prepare("UPDATE bindings SET expiry_date = ? WHERE card_key = ? AND app_id = ?").bind(date, cardKey, appId).run();
  return json({ ok: true, msg: `到期时间已修改为 ${date}` });
}

async function changePassword(env, username, oldPw, newPw, newPw2) {
  if (!newPw || newPw !== newPw2) return json({ ok: false, msg: "两次输入的新密码不一致" });
  const admin = await DB(env).prepare("SELECT username, password_hash, salt FROM admin WHERE username = ?").bind(username).first();
  if (!admin) return json({ ok: false, msg: "管理员不存在" });
  if (!(await verifyPassword(oldPw, admin.salt, admin.password_hash))) return json({ ok: false, msg: "原密码错误" });
  const { salt, hash } = await hashPassword(newPw);
  await DB(env).prepare("UPDATE admin SET password_hash = ?, salt = ? WHERE username = ?").bind(hash, salt, username).run();
  return json({ ok: true, msg: "密码修改成功" });
}

/* ------------------------------ token ------------------------------ */

async function issueToken(env, username) {
  const token = randomToken(24);
  const now = Date.now();
  await DB(env).prepare("INSERT INTO api_tokens (token_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .bind(await sha256Hex(token), username, now, now + TOKEN_TTL * 1000).run();
  await DB(env).prepare("DELETE FROM api_tokens WHERE expires_at < ?").bind(now).run();
  return token;
}
async function checkToken(env, token) {
  if (!token) return null;
  const row = await DB(env).prepare("SELECT username, expires_at FROM api_tokens WHERE token_hash = ?")
    .bind(await sha256Hex(token)).first();
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    await DB(env).prepare("DELETE FROM api_tokens WHERE token_hash = ?").bind(await sha256Hex(token)).run();
    return null;
  }
  return row.username;
}

/* ============================== 入口 ============================== */

const BUILD_VERSION = "v6-20261121";

/*
 * 出错时也返回 HTTP 200，只把错误放进 JSON body：旧的 PHP 后端一直是这个行为，
 * 安卓 App 端见到 4xx/5xx 会直接抛 "HTTP xxx" 而丢掉具体错误信息。
 */
async function guard(env, fn) {
  if (!env.DB) {
    return json({ ok: false, msg: "后端未连接数据库：请在 Pages 项目 Settings → Functions → D1 database bindings 添加变量名 DB（并重新部署）", error: "DB_BINDING_MISSING" });
  }
  try {
    return await fn();
  } catch (e) {
    return json({ ok: false, msg: "服务器内部错误：" + (e && e.message ? e.message : String(e)), error: "INTERNAL" });
  }
}

export async function onRequestPost({ request, env }) {
  const path = new URL(request.url).pathname;
  if (path === "/api/verify") return guard(env, () => handleVerify(request, env));
  if (path === "/api/check") return guard(env, () => handleCheck(request, env));
  if (path === "/api/admin") return guard(env, () => handleAdmin(request, env));
  return json({ ok: false, msg: "未知接口：" + path, error: "NOT_FOUND" });
}
export async function onRequestGet({ request, env }) {
  const path = new URL(request.url).pathname;
  if (path === "/api/version") return json({ version: BUILD_VERSION });
  if (path === "/api/notice") return guard(env, () => handleNotice(request, env));
  if (path === "/api/admin") return guard(env, () => handleAdmin(request, env));
  return json({ ok: false, msg: "未知接口：" + path, error: "NOT_FOUND" });
}

/* ============================== 杂项 ============================== */

async function digestHex(algo, bytes) {
  const buf = await crypto.subtle.digest(algo, bytes);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function md5Hex(bytes) {
  try { return await digestHex("MD5", bytes); }
  catch (e) { return md5(bytes); }
}
