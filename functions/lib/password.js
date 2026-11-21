/**
 * 密码哈希 —— PBKDF2（Web Crypto）
 *
 * 存储：{ salt: <hex>, hash: <hex> }
 * 注意：老 PHP 后端是明文存的，迁移后老密码登不上，需要重新设置。
 */

const ITER = 100000;

async function pbkdf2(password, saltBytes) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: ITER, hash: "SHA-256" },
    key,
    256
  );
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(n) {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function hashPassword(password) {
  const salt = randomHex(16);
  const saltBytes = Uint8Array.from(salt.match(/../g).map(h => parseInt(h, 16)));
  const hash = await pbkdf2(password, saltBytes);
  return { salt, hash };
}

export async function verifyPassword(password, salt, expectedHash) {
  const saltBytes = Uint8Array.from(salt.match(/../g).map(h => parseInt(h, 16)));
  const hash = await pbkdf2(password, saltBytes);
  return hash === expectedHash;
}
