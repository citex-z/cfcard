/** 通用工具：随机 token、哈希、卡密/应用 ID 生成、时间、JSON 响应。 */

export function randomToken(nBytes) {
  const bytes = new Uint8Array(nBytes);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

const KEY_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

export function generateCardKey() {
  let k = "";
  for (let i = 0; i < 10; i++) k += KEY_CHARS[Math.floor(Math.random() * KEY_CHARS.length)];
  return k;
}

export function generateAppId() {
  let k = "";
  for (let i = 0; i < 12; i++) k += KEY_CHARS[Math.floor(Math.random() * KEY_CHARS.length)];
  return k;
}

export function nowIso() {
  return new Date().toISOString();
}

/** 本地日期 YYYY-MM-DD（用于到期比较） */
export function today() {
  const d = new Date();
  const p = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
