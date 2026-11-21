# cfcard

基于 Cloudflare Pages + D1 的卡密验证后端。

## 接口

| 路径 | 方法 | 说明 |
|---|---|---|
| `/api/verify` | POST | 卡密验证 / 设备绑定（注入的 APK 调用） |
| `/api/check` | POST | APK 签名校验 |
| `/api/notice` | GET | 应用公告 |
| `/api/admin` | POST | 管理接口（`act` 分发，App 与网页后台共用） |

参数均为 `application/x-www-form-urlencoded` / `multipart/form-data`
（网页后台用 multipart，安卓 App 端用 urlencoded，两种都支持）。

出错时 HTTP 状态仍是 200，具体错误在 JSON 的 `msg` 里 —— 旧的 PHP 后端就是这个行为。

## 数据表

表结构在 [建表.sql](建表.sql)，**首次部署后在 D1 控制台手动执行一次**（D1 的
`exec()` 一次只接受一条语句，所以不再做运行时自动建表）。管理员账号也在那份 SQL 里。

- `admin` — 管理员（PBKDF2 加盐哈希）
- `apps` — 应用（名称/状态/公告/签名指纹）
- `bindings` — 卡密（设备绑定/到期/封禁）
- `api_tokens` — 登录 token（只存 sha256）

## 本地测试

```bash
node test-d1.mjs         # node:sqlite 模拟 D1，跑全部后端逻辑（22 项）
node test-app-compat.mjs # 模拟安卓 App 端（urlencoded 请求）全流程（11 项）
```

注意：**不要用 `DB.batch([{sql, params}])`**。Cloudflare 打包时会丢掉对象里的
`sql` 字段，线上会报 `Malformed input: [{"params":[...]}`。多语句请拆成几条
`prepare().bind().run()`。

## 部署

见 [部署说明.md](部署说明.md)。