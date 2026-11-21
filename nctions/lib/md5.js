/**
 * 纯 JS MD5 —— 仅在运行环境不支持 crypto.subtle.digest("MD5") 时作为回退。
 * Cloudflare Workers 原生支持 MD5，会走 Web Crypto；本地 Node 测试走这里。
 * 输入/输出：Uint8Array → 小写十六进制字符串。
 */

const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
           5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
           4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
           6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];

const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);

export function md5(bytes) {
  const len = bytes.length;
  const withOne = len + 1;
  const totalLen = ((withOne + 8) >> 6) + 1 << 6;
  const buf = new Uint8Array(totalLen);
  buf.set(bytes);
  buf[len] = 0x80;
  const bitLen = len * 8;
  const dv = new DataView(buf.buffer);
  dv.setUint32(totalLen - 8, bitLen >>> 0, true);
  dv.setUint32(totalLen - 4, Math.floor(bitLen / 4294967296), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const w = new Uint32Array(16);
  for (let i = 0; i < totalLen; i += 64) {
    for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let j = 0; j < 64; j++) {
      let F, g;
      if (j < 16)      { F = (B & C) | (~B & D);        g = j; }
      else if (j < 32) { F = (D & B) | (~D & C);        g = (5 * j + 1) & 15; }
      else if (j < 48) { F = B ^ C ^ D;                 g = (3 * j + 5) & 15; }
      else             { F = C ^ (B | ~D);              g = (7 * j) & 15; }
      const tmp = D;
      D = C; C = B;
      B = (B + rotl((A + F + K[j] + w[g]) >>> 0, S[j])) >>> 0;
      A = tmp;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new DataView(new ArrayBuffer(16));
  out.setUint32(0, a0, true); out.setUint32(4, b0, true);
  out.setUint32(8, c0, true); out.setUint32(12, d0, true);
  return [...new Uint8Array(out.buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
