# cfcard

基于 Cloudflare Pages + D1 的卡密验证后端。

## 接口

| 路径 | 方法 | 说明 |
|---|---|---|
| `/api/verify` | POST | 卡密验证 / 设备绑定（注入的 APK 调用） |
| `/api/check` | POST | APK 签名校验 |
| `/api/notice` | GET | 应用公告 |
| `/api/admin` | POST | 管理接口（`act` 分发，App 与网页后台共用） |

参数均为 `application/x-www-form-urlencoded` / `multipart/form-data`。

## 数据表（首次请求自动创建）

- `admin` — 管理员（PBKDF2 加盐哈希）
- `apps` — 应用（名称/状态/公告/签名指纹）
- `bindings` — 卡密（设备绑定/到期/封禁）
- `api_tokens` — 登录 token（只存 sha256）

## 本地测试

```bash
node test-d1.mjs      # 用 node:sqlite 模拟 D1，跑全部逻辑（22 项）
```

## 部署

见 [部署说明.md](部署说明.md)。