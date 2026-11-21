/**
 * 线上签名校验演练：把 App 注入产物那套 SigGuard 请求打到真实 /api/check。
 *
 * 用法：node live-check.mjs <用户名> <密码> <正确证书base64> <对照证书base64>
 * 建一个演练应用、登记指纹、测 6 种上报，最后删掉应用，不留垃圾。
 */
const BASE = "https://cfcard.pages.dev";
const [user, pass, goodCert, otherCert] = process.argv.slice(2);
let ok = 0, bad = 0;
function check(name, cond, extra = "") {
  cond ? (ok++, console.log("  ✓", name))
       : (bad++, console.log("  ✗", name, extra));
}

async function admin(params) {
  const r = await fetch(BASE + "/api/admin", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
    body: new URLSearchParams(params).toString(),
  });
  return r.json();
}

// SigGuard 就是这么发的：urlencoded 表单 + 同一个 UA
async function checkReq(appId, cert) {
  const r = await fetch(BASE + "/api/check", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": "CardKeyClient/1.0",
    },
    body: new URLSearchParams({ app_id: appId, sig_cert: cert }).toString(),
  });
  return r.json();
}

console.log("[0] 登录");
const t = await admin({ act: "login", username: user, password: pass });
check("登录成功", t.ok === true, t.msg);
const TOKEN = t.token;

let APPID;
console.log("\n[1] 建应用并登记签名指纹");
{
  const c = await admin({ act: "create_app", token: TOKEN, app_name: "签名校验演练" });
  check("建应用", c.ok === true && c.app_id.length === 12, c.msg);
  APPID = c.app_id;
  const s = await admin({ act: "set_signature", token: TOKEN, app_id: APPID,
    sig_md5: "7fef6abb795c7b79bf75cc0e4347db00",
    sig_sha1: "23c130849b885790dd53bc7e68347c7752f13c92",
    sig_sha256: "56cf383884a499934d23934d9063c30d9a1b41a3b2d4fd742aa725dfba334fec" });
  check("登记指纹", s.ok === true, s.msg);
}

console.log("\n[2] 客户端上报（/api/check）");
{
  const a = await checkReq(APPID, goodCert);
  check("正确证书放行", a.status === "ok", JSON.stringify(a));

  const b = await checkReq(APPID, otherCert);
  check("别的证书判为 crack", b.status === "crack", JSON.stringify(b));

  const c = await checkReq(APPID, "");
  check("取不到证书时放行（不误杀）", c.status === "ok", JSON.stringify(c));

  const d = await checkReq(APPID, "!!!not-base64@@@");
  check("畸形 base64 不 500", d.status === "ok", JSON.stringify(d));

  const e = await checkReq("NO_SUCH_APP_000", goodCert);
  check("未知应用放行", e.status === "ok", JSON.stringify(e));
}

console.log("\n[3] 清空指纹后回到放行态");
{
  const s = await admin({ act: "set_signature", token: TOKEN, app_id: APPID,
    sig_md5: "", sig_sha1: "", sig_sha256: "" });
  check("清空指纹", s.ok === true, s.msg);
  const a = await checkReq(APPID, goodCert);
  check("未配置指纹即放行", a.status === "ok", JSON.stringify(a));
  const list = await admin({ act: "apps", token: TOKEN });
  const me = (list.apps || []).find(x => x.app_id === APPID);
  check("应用状态 sig_on=false", me && me.sig_on === false, JSON.stringify(me));
}

console.log("\n[4] 清理");
{
  const d = await admin({ act: "delete_app", token: TOKEN, app_id: APPID });
  check("删除演练应用", d.ok === true, d.msg);
  const list = await admin({ act: "apps", token: TOKEN });
  check("演练应用已移除", !(list.apps || []).some(x => x.app_id === APPID));
  await admin({ act: "logout", token: TOKEN });
}

console.log("\n" + ok + "/" + (ok + bad) + " ok");
process.exit(bad ? 1 : 0);