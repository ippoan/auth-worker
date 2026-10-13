/**
 * 機械用資格情報のチケット — 「この資格情報が、この中身 (sha256) を、この用途で受け渡した」を
 * auth-worker が署名した印 (Refs ohishi-exp/rust-leave-worker#1)。
 *
 * 流れ (休暇申請書の PDF):
 *   受け口 (nuxt-leave) が PUT の Basic と PDF の sha256 で `issueTicket` → R2 に置くときチケットを添える →
 *   取り込み側 (rust-leave-worker) が `verifyTicket` → 返った tenant で取り込み、sha256 の一致も確かめる。
 * 受け口も取り込み側も tenant を自分で決めない。**tenant を決めるのは auth-worker だけ** (発行時も検証時も)。
 *
 * 形式は HS256 の JWT (`lib/jwt.ts` の signJwt / verifyJwt をそのまま使う)。
 * ★ **鍵は新しい secret を作らず、`JWT_SECRET` から HKDF で派生させる**
 *   (info = `machine-ticket-v1:<MACHINE_CRED_ENV>`)。
 *   - ドメイン分離: 派生鍵なので、ブラウザの JWT・device JWT とは互いに検証が通らない
 *   - 環境の分離: `JWT_SECRET` は prod と staging で**同じ値** (wrangler.toml で同じ entry を指す) なので、
 *     info に環境名を入れて鍵そのものを分ける。さらに payload の `env` の照合と、資格情報の引き直し
 *     (`ALC_AUTH` の行き先が環境ごとに別の alc-auth-worker・別の DB) でも分かれる
 *
 * ★ **検証は署名と期限だけで済ませず、資格情報が今も有効かを alc-auth-worker で確かめる** —
 *   資格情報を失効させたら、まだ取り込まれていないファイルのチケットも通らなくなる (ユーザー要件)。
 */
import type { SecretBinding } from "./secret";
import { resolveSecret } from "./secret";
import { signJwt, verifyJwt } from "./jwt";
import {
  checkActiveMachineCredential,
  isMachineCredPurpose,
  machineCredEnvName,
  verifyBasic,
  type MachineCredEnv,
} from "./machine-credential";

/** チケットの寿命 (7 日)。Queue の再試行で取り込みが遅れても切れない長さ。 */
export const MACHINE_TICKET_TTL_SECONDS = 7 * 24 * 60 * 60;

/** HKDF の info の接頭辞。形式を変えるときは v を上げる (旧チケットは自然に通らなくなる)。 */
const HKDF_INFO_PREFIX = "machine-ticket-v1:";

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

export interface MachineTicketEnv extends MachineCredEnv {
  JWT_SECRET: SecretBinding;
}

interface MachineTicketPayload {
  v: 1;
  env: string;
  tenant_id: string;
  username: string;
  purpose: string;
  sha256: string;
  iat: number;
  exp: number;
}

/** `JWT_SECRET` と環境名からチケット用の鍵 (hex) を派生させる。どちらか無ければ null。 */
async function ticketKey(env: MachineTicketEnv, envName: string): Promise<string | null> {
  const secret = await resolveSecret(env.JWT_SECRET);
  if (!secret) return null;
  const enc = new TextEncoder();
  const ikm = await crypto.subtle.importKey("raw", enc.encode(secret), "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: enc.encode(HKDF_INFO_PREFIX + envName),
    },
    ikm,
    256,
  );
  return Array.from(new Uint8Array(bits), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Basic を照合し、通ったときだけチケットを発行する。
 * sha256 が 64 桁の小文字 hex でない・Basic が通らない・鍵が無い・環境名が無い → null (区別しない)。
 */
export async function issueTicket(
  env: MachineTicketEnv,
  authorization: string,
  purpose: string,
  sha256: string,
): Promise<{ ticket: string; tenantId: string; username: string } | null> {
  const envName = machineCredEnvName(env);
  if (!envName) return null;
  if (typeof sha256 !== "string" || !SHA256_HEX_RE.test(sha256)) return null;
  const cred = await verifyBasic(env, authorization, purpose);
  if (!cred) return null;
  const key = await ticketKey(env, envName);
  if (!key) return null;

  const iat = Math.floor(Date.now() / 1000);
  const payload: MachineTicketPayload = {
    v: 1,
    env: envName,
    tenant_id: cred.tenantId,
    username: cred.username,
    purpose,
    sha256,
    iat,
    exp: iat + MACHINE_TICKET_TTL_SECONDS,
  };
  const ticket = await signJwt({ ...payload }, key);
  return { ticket, tenantId: cred.tenantId, username: cred.username };
}

/** `verifyTicket` の「一時的な失敗」。無効 (null) とは区別する — 呼び手は再試行してよい。 */
export interface MachineTicketUnavailable {
  error: "unavailable";
}

/**
 * チケットを検証する。署名・期限・形式・環境・用途が合い、**資格情報が今も有効で tenant と用途が
 * 発行時のまま**のときだけ `{tenantId, username, sha256}` を返す。
 * 無効 (署名・期限・形式・環境・用途の不一致、資格情報の不在・失効、tenant・用途の不一致) は null。
 * ★ 資格情報を alc-auth-worker に確かめられなかった (binding / secret が無い・5xx・通信失敗・壊れた応答) ときは
 * null ではなく `{ error: "unavailable" }` (無効と取り違えて捨てさせない)。
 */
export async function verifyTicket(
  env: MachineTicketEnv,
  ticket: string,
  purpose: string,
): Promise<{ tenantId: string; username: string; sha256: string } | MachineTicketUnavailable | null> {
  const envName = machineCredEnvName(env);
  if (!envName || !isMachineCredPurpose(purpose)) return null;
  if (typeof ticket !== "string" || !ticket) return null;
  const key = await ticketKey(env, envName);
  if (!key) return null;
  const p = await verifyJwt(ticket, key);
  if (!p) return null;
  if (
    p.v !== 1 ||
    p.env !== envName ||
    p.purpose !== purpose ||
    typeof p.tenant_id !== "string" ||
    typeof p.username !== "string" ||
    typeof p.sha256 !== "string" ||
    !SHA256_HEX_RE.test(p.sha256)
  ) {
    return null;
  }
  const checked = await checkActiveMachineCredential(env, p.username);
  if (checked.status === "unavailable") return { error: "unavailable" };
  if (checked.status !== "active") return null;
  const cred = checked.credential;
  if (cred.tenant_id !== p.tenant_id || cred.purpose !== purpose) return null;
  return { tenantId: cred.tenant_id, username: cred.username, sha256: p.sha256 };
}
