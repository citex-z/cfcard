/**
 * 安卓 App 端兼容性测试：
 *  App 用 application/x-www-form-urlencoded 发请求（网页后台用 multipart），
 *  这里跑一遍「登录 → 建应用 → 生成卡密 → 概览 → 删应用」全流程。
 */
import { DatabaseSync } from "node:sqlite";
import { onRequestPost, onRequestGet } from "./functions/api/[[route]].js";
import { hashPassword } from "./functions/lib/password.js";

function mockD1() {
  const db = new DatabaseSync(":memory:");
  return {
    prepare(sql) {
      const stmt = db.prepare(sql);
      const bound = params => ({
        async first() { const r = stmt.get(...params); return r === undefined ? null : r; },
        async all() { return { results: stmt.all(...params) }; },
        async run() { stmt.run(...params); return { success: true }; },
      });
      // 不带 bind() 的直接调用也支持（ensureSchema 用）
      return { bind: (...p) => bound(p), ...bound([]) };
    },
    async exec(sqlText) { db.exec(sqlText); return { count: 0, duration: 0 }; },
  };
}

const env = { DB: mockD1() };
let pass = 0, fail = 0;
function check(name, cond) { cond ? (pass++, console.log("  ✓", name)) : (fail++, console.log("  ✗", name)); }
const j = async r => await r.json();

// 与 ApiClient.call() 完全一致的请求构造
function urlReq(path, params) {
  const body = new URLSearchParams(params).toString();
  return new Request("https://x" + path, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
    body,
  });
}

const SCHEMA = `
CREATE TABLE admin (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
CREATE TABLE apps (app_id TEXT PRIMARY KEY, app_name TEXT NOT NULL, status INTEGER DEFAULT 1, notice TEXT DEFAULT '', sig_md5 TEXT DEFAULT '', sig_sha1 TEXT DEFAULT '', sig_sha256 TEXT DEFAULT '', created_at TEXT DEFAULT (datetime('now')));
CREATE TABLE bindings (id INTEGER PRIMARY KEY AUTOINCREMENT, app_id TEXT NOT NULL DEFAULT '', card_key TEXT NOT NULL, device_id TEXT DEFAULT '', bind_date TEXT DEFAULT '', banned INTEGER DEFAULT 0, expiry_date TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
CREATE TABLE api_tokens (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
`;
await env.DB.exec(SCHEMA);
const { salt, hash } = await hashPassword("123456");
await env.DB.prepare("INSERT INTO admin (username, password_hash, salt) VALUES (?, ?, ?)").bind("admin", hash, salt).run();

console.log("\n[1] urlencoded 登录（App 的 Content-Type）");
let TOKEN;
{
  const r = await j(await onRequestPost({ request: urlReq("/api/admin", { act: "login", username: "admin", password: "123456" }), env }));
  check("登录成功", r.ok === true && typeof r.token === "string" && r.token.length > 20);
  TOKEN = r.token;
  const bad = await j(await onRequestPost({ request: urlReq("/api/admin", { act: "login", username: "admin", password: "x" }), env }));
  check("错误密码被拒", bad.ok === false);
}

console.log("\n[2] urlencoded 管理操作");
let APPID, KEY;
{
  const r = await j(await onRequestPost({ request: urlReq("/api/admin", { act: "create_app", token: TOKEN, app_name: "手机App" }), env }));
  check("建应用", r.ok === true && r.app_id.length === 12);
  APPID = r.app_id;
  const g = await j(await onRequestPost({ request: urlReq("/api/admin", { act: "generate_cards", token: TOKEN, app_id: APPID, expiry_date: "20270101", quantity: "3" }), env }));
  check("生成 3 张卡密（quantity 是字符串，同 URLSearchParams 行为）", g.ok === true && g.keys.length === 3);
  KEY = g.keys[0];
  const ov = await j(await onRequestPost({ request: urlReq("/api/admin", { act: "overview", token: TOKEN }), env }));
  check("概览统计", ov.ok === true && ov.stats.apps === 1 && ov.stats.cards === 3);
  const cards = await j(await onRequestPost({ request: urlReq("/api/admin", { act: "cards", token: TOKEN, app_id: APPID, keyword: "" }), env }));
  check("卡密列表", cards.ok === true && cards.cards.length === 3);
}

console.log("\n[3] urlencoded 客户端接口");
{
  const r = await j(await onRequestPost({ request: urlReq("/api/verify", { app_id: APPID, card_key: KEY, device_id: "PHONE-1" }), env }));
  check("首次绑定成功", r.status === "success" && /绑定成功/.test(r.message));
  const n = await j(await onRequestGet({ request: new Request("https://x/api/notice?app_id=" + APPID), env }));
  check("公告接口", typeof n.notice === "string");
}

console.log("\n[4] 删除应用（原先用 batch()，Cloudflare 打包会丢 sql 字段）");
{
  const r = await j(await onRequestPost({ request: urlReq("/api/admin", { act: "delete_app", token: TOKEN, app_id: APPID }), env }));
  check("删除应用成功", r.ok === true);
  const apps = await j(await onRequestPost({ request: urlReq("/api/admin", { act: "apps", token: TOKEN }), env }));
  check("应用列表已空", apps.apps.length === 0);
  const ov = await j(await onRequestPost({ request: urlReq("/api/admin", { act: "overview", token: TOKEN }), env }));
  check("卡密随之清空", ov.stats.apps === 0 && ov.stats.cards === 0);
}

console.log(`\n===== App 兼容性: ${pass} 通过, ${fail} 失败 =====`);
process.exit(fail ? 1 : 0);