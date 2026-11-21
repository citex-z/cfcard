/**
 * D1 版本地逻辑测试：用 node:sqlite 模拟 Cloudflare D1 接口，跑真实 SQL。
 * 复用 R2 版同一套测试场景。
 */
import { DatabaseSync } from "node:sqlite";
import { onRequestPost, onRequestGet } from "./functions/api/[[route]].js";

/* ---- 模拟 D1：包住 node:sqlite ---- */
function mockD1() {
  const db = new DatabaseSync(":memory:");
  return {
    prepare(sql) {
      // node:sqlite: db.prepare(sql) → { run(...p), get(...p), all(...p) }
      const stmt = db.prepare(sql);
      return {
        bind(...params) {
          return {
            async first() {
              const row = stmt.get(...params);
              return row === undefined ? null : row;
            },
            async all() {
              return { results: stmt.all(...params) };
            },
            async run() {
              stmt.run(...params);
              return { success: true };
            },
          };
        },
        async first() { const r = stmt.get(); return r === undefined ? null : r; },
        async all() { return { results: stmt.all() }; },
        async run() { stmt.run(); return { success: true }; },
      };
    },
    async batch(statements) {
      // 严格跟真实 D1 一致：只接受 {sql, params} 对象
      for (const s of statements) {
        if (typeof s === "string" || !s || typeof s.sql !== "string") {
          throw new Error("Malformed input: should be {sql: string, params?: any[]} or an array of these query objects");
        }
        db.prepare(s.sql).run(...(s.params || []));
      }
      return [];
    },
  };
}

const env = { DB: mockD1() };
let pass = 0, fail = 0;
function check(name, cond) { cond ? (pass++, console.log("  ✓", name)) : (fail++, console.log("  ✗", name)); }

function adminReq(params) {
  const fd = new FormData();
  Object.entries(params).forEach(([k, v]) => fd.append(k, v));
  return new Request("https://x/api/admin", { method: "POST", body: fd });
}
function clientReq(path, params) {
  const fd = new FormData();
  Object.entries(params).forEach(([k, v]) => fd.append(k, v));
  return new Request("https://x" + path, { method: "POST", body: fd });
}
const j = async r => await r.json();

console.log("\n[1] 管理员初始化 & 登录（先手动建表+插管理员）");
import { hashPassword } from "./functions/lib/password.js";
{
  // 触发建表
  await onRequestPost({ request: adminReq({ act: "ping", token: "x" }), env });
  const { salt, hash } = await hashPassword("admin123");
  await env.DB.prepare("INSERT INTO admin (username, password_hash, salt) VALUES (?, ?, ?)").bind("boss", hash, salt).run();
  const r = await j(await onRequestPost({ request: adminReq({ act: "login", username: "boss", password: "admin123" }), env }));
  check("正确密码登录成功", r.ok && r.token && r.username === "boss");
  global.TOKEN = r.token;
}
{
  const r = await j(await onRequestPost({ request: adminReq({ act: "login", username: "boss", password: "wrong" }), env }));
  check("错误密码被拒", r.ok === false);
}
{
  const r = await j(await onRequestPost({ request: adminReq({ act: "ping", token: global.TOKEN }), env }));
  check("token 有效 ping", r.ok && r.username === "boss");
}

console.log("\n[2] 应用管理");
let APPID;
{
  const r = await j(await onRequestPost({ request: adminReq({ act: "create_app", token: global.TOKEN, app_name: "测试游戏" }), env }));
  check("创建应用", r.ok && r.app_id.length === 12);
  APPID = r.app_id;
}
{
  const r = await j(await onRequestPost({ request: adminReq({ act: "apps", token: global.TOKEN }), env }));
  check("应用列表含新应用", r.ok && r.apps.length === 1 && r.apps[0].app_name === "测试游戏" && r.apps[0].card_count === 0);
}
{
  await onRequestPost({ request: adminReq({ act: "set_notice", token: global.TOKEN, app_id: APPID, notice: "欢迎测试" }), env });
  const n = await j(await onRequestGet({ request: new Request("https://x/api/notice?app_id=" + APPID), env }));
  check("公告接口返回", n.notice === "欢迎测试");
}

console.log("\n[3] 签名校验");
{
  const md5 = "d41d8cd98f00b204e9800998ecf8427e";
  const r = await j(await onRequestPost({ request: adminReq({ act: "set_signature", token: global.TOKEN, app_id: APPID, sig_md5: md5 }), env }));
  check("设置签名指纹", r.ok && r.sig_on);
  const c = await j(await onRequestPost({ request: clientReq("/api/check", { app_id: APPID, sig_cert: btoa("") }), env }));
  check("签名匹配 → ok", c.status === "ok");
  const c2 = await j(await onRequestPost({ request: clientReq("/api/check", { app_id: APPID, sig_cert: btoa("abc") }), env }));
  check("签名不匹配 → crack", c2.status === "crack");
}

console.log("\n[4] 卡密生成 & 验证绑定");
let KEY;
{
  const r = await j(await onRequestPost({ request: adminReq({ act: "generate_cards", token: global.TOKEN, app_id: APPID, expiry_date: "20991231", quantity: 5 }), env }));
  check("生成 5 张卡密", r.ok && r.keys.length === 5);
  KEY = r.keys[0];
}
{
  const r = await j(await onRequestPost({ request: clientReq("/api/verify", { app_id: APPID, card_key: KEY, device_id: "DEV-A" }), env }));
  check("首次验证绑定成功", r.status === "success" && r.message === "卡密绑定成功");
  const r2 = await j(await onRequestPost({ request: clientReq("/api/verify", { app_id: APPID, card_key: KEY, device_id: "DEV-A" }), env }));
  check("同设备验证成功", r2.status === "success" && r2.message === "验证成功");
  const r3 = await j(await onRequestPost({ request: clientReq("/api/verify", { app_id: APPID, card_key: KEY, device_id: "DEV-B" }), env }));
  check("换设备被拒", r3.status === "error" && /其他设备/.test(r3.message));
  const r4 = await j(await onRequestPost({ request: clientReq("/api/verify", { app_id: APPID, card_key: "NOPE123456", device_id: "DEV-A" }), env }));
  check("不存在的卡密", r4.status === "error");
}

console.log("\n[5] 关键字搜索（D1 LIKE）");
{
  const r = await j(await onRequestPost({ request: adminReq({ act: "cards", token: global.TOKEN, app_id: APPID, keyword: KEY.slice(0, 4) }), env }));
  check("按关键字搜到卡密", r.ok && r.cards.some(c => c.card_key === KEY));
  const r2 = await j(await onRequestPost({ request: adminReq({ act: "cards", token: global.TOKEN, keyword: "DEV-A" }), env }));
  check("按设备搜到卡密", r2.ok && r2.cards.some(c => c.device_id === "DEV-A"));
}

console.log("\n[6] 封禁 / 解绑 / 改期 / 删除 / 概览 / 封应用");
{
  await onRequestPost({ request: adminReq({ act: "ban_card", token: global.TOKEN, app_id: APPID, card_key: KEY }), env });
  const v = await j(await onRequestPost({ request: clientReq("/api/verify", { app_id: APPID, card_key: KEY, device_id: "DEV-A" }), env }));
  check("封禁后验证失败", v.status === "error" && /封禁/.test(v.message));
  await onRequestPost({ request: adminReq({ act: "unban_card", token: global.TOKEN, app_id: APPID, card_key: KEY }), env });
  await onRequestPost({ request: adminReq({ act: "unbind_card", token: global.TOKEN, app_id: APPID, card_key: KEY }), env });
  const v2 = await j(await onRequestPost({ request: clientReq("/api/verify", { app_id: APPID, card_key: KEY, device_id: "DEV-B" }), env }));
  check("解绑后可重新绑定", v2.status === "success");
  await onRequestPost({ request: adminReq({ act: "update_expiry", token: global.TOKEN, app_id: APPID, card_key: KEY, new_expiry: "20200101" }), env });
  const v3 = await j(await onRequestPost({ request: clientReq("/api/verify", { app_id: APPID, card_key: KEY, device_id: "DEV-B" }), env }));
  check("过期卡密验证失败", v3.status === "error" && /过期/.test(v3.message));

  const ov = await j(await onRequestPost({ request: adminReq({ act: "overview", token: global.TOKEN }), env }));
  check("概览统计", ov.ok && ov.stats.apps === 1 && ov.stats.cards === 5 && ov.stats.unbound === ov.stats.cards - ov.stats.bound);

  await onRequestPost({ request: adminReq({ act: "ban_app", token: global.TOKEN, app_id: APPID }), env });
  const v4 = await j(await onRequestPost({ request: clientReq("/api/verify", { app_id: APPID, card_key: KEY, device_id: "DEV-B" }), env }));
  check("应用封禁后验证失败", v4.status === "error" && /封禁/.test(v4.message));
  const n = await j(await onRequestGet({ request: new Request("https://x/api/notice?app_id=" + APPID), env }));
  check("应用封禁后无公告", n.notice === "");
}

console.log(`\n===== D1 结果: ${pass} 通过, ${fail} 失败 =====`);
process.exit(fail ? 1 : 0);
