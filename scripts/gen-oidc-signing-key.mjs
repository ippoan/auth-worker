#!/usr/bin/env node
/**
 * Cloudflare Access 向け OIDC surface (`/oidc/*`) の ES256 署名鍵を生成する。
 *
 *   node scripts/gen-oidc-signing-key.mjs              # 新規 1 鍵の JSON 配列を出す
 *   node scripts/gen-oidc-signing-key.mjs --rotate -   # stdin の既存配列の先頭に新鍵を挿す
 *
 * 出力は `ACCESS_OIDC_SIGNING_KEY` にそのまま入れる **私有 JWK の JSON 配列**。
 * 先頭が現用鍵、以降は JWKS に出すだけの旧鍵 (`src/lib/oidc-signing-key.ts` 参照)。
 *
 * 投入 (値が shell 履歴・プロセス一覧に残らないよう file 経由で渡す):
 *   node scripts/gen-oidc-signing-key.mjs > /tmp/k.json
 *   npx wrangler secrets-store secret create <STORE_ID> \
 *     --name ACCESS_OIDC_SIGNING_KEY --scopes workers --value "$(cat /tmp/k.json)"
 *   shred -u /tmp/k.json
 *
 * ローテーション (無停止 2 段):
 *   1. 現在値を取得 → `--rotate` で新鍵を先頭に挿して更新 → deploy
 *      (JWKS に新旧両方が出るので、どちらで署名された id_token も検証できる)
 *   2. 旧 id_token の寿命 (既定 5 分) を過ぎたら末尾の旧鍵を削って更新 → deploy
 *
 * **秘密鍵は標準出力にしか出さない。** repo 内に書き出さないこと (.gitignore 済みの
 * 場所であっても、鍵の唯一の正本は Secrets Store 側に置く)。
 */
import { webcrypto as crypto } from "node:crypto";
import { readFileSync } from "node:fs";

async function generatePrivateJwk() {
  const { privateKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  // Worker 側 parser (`isPrivateEs256Jwk`) が要求する 5 field だけに絞る。
  // Node が付ける `key_ops` / `ext` は Secrets Store に入れても使わない。
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d };
}

/** RFC 7638 JWK Thumbprint — Worker 側 `jwkThumbprintKid` と同じ導出。 */
async function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return Buffer.from(digest).toString("base64url");
}

const args = process.argv.slice(2);
const rotateIdx = args.indexOf("--rotate");

let existing = [];
if (rotateIdx !== -1) {
  const src = args[rotateIdx + 1];
  if (!src) {
    console.error("--rotate には既存 JSON の path か `-` (stdin) を渡してください");
    process.exit(1);
  }
  const raw = readFileSync(src === "-" ? 0 : src, "utf8");
  const parsed = JSON.parse(raw);
  existing = Array.isArray(parsed) ? parsed : [parsed];
}

const fresh = await generatePrivateJwk();
const keys = [fresh, ...existing];

process.stdout.write(JSON.stringify(keys) + "\n");
console.error(`新しい kid: ${await thumbprint(fresh)}  (鍵 ${keys.length} 本)`);
