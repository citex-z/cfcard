/**
 * 生成创建管理员的 D1 命令。
 * 用法: node seed-d1.mjs <用户名> <密码>
 *
 * 因为密码要 PBKDF2 哈希，不能直接插 SQL，本脚本算好哈希后
 * 打印一条 wrangler d1 execute 命令，复制执行即可。
 */
import { hashPassword } from "./functions/lib/password.js";

const [user, pass] = process.argv.slice(2);
if (!user || !pass) {
  console.error("用法: node seed-d1.mjs <用户名> <密码>");
  process.exit(1);
}
const { salt, hash } = await hashPassword(pass);

const sql = `INSERT OR REPLACE INTO admin (username, password_hash, salt) VALUES ('${user}', '${hash}', '${salt}');`;
console.log("=== 复制执行（远程库）===\n");
console.log(`wrangler d1 execute cfcard --remote --command "${sql}"`);
console.log("\n=== 或本地库（开发用）===\n");
console.log(`wrangler d1 execute cfcard --local --command "${sql}"`);
