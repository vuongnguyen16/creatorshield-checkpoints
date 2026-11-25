/**
 * Zero-dependency cryptographic verification & schema validation core for
 * CreatorShield public checkpoints and public-keys.json.
 *
 * Matches packages/evidence-core/src/canonical/jcs.ts,
 * packages/evidence-core/src/sign/ed25519.ts, and
 * packages/evidence-core/src/checkpoint/bulletin.ts byte-for-byte.
 */
import { createHash, createPublicKey, verify } from "node:crypto";

export const CHECKPOINT_FORMAT_V1 = "creatorshield-checkpoint/1";
export const CHECKPOINT_FORMAT_V2 = "creatorshield-checkpoint/2";
export const CHECKPOINT_DOMAIN_LABEL = "creatorshield/checkpoint/v1";
export const ALG_ED25519 = "Ed25519";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const KEYS_V1 = ["format", "day", "headSeq", "headEventHash", "issuedAt", "alg", "keyId"];
const KEYS_V2 = [...KEYS_V1, "treeSize", "merkleRoot"];

const VALID_STATUSES = new Set(["active", "retired", "compromised"]);
const VALID_ROLES = new Set(["checkpoint", "event", "legacy"]);

export function isHex64(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/i.test(value);
}

export function sha256Utf8(text) {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

function serializeJcsValue(value, path) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`Số không hữu hạn tại ${path}`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v, i) => serializeJcsValue(v, `${path}[${i}]`)).join(",")}]`;
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new Error(`Chỉ chấp nhận plain object tại ${path}`);
    }
    const entries = [];
    const seen = new Set();
    for (const rawKey of Object.keys(value)) {
      const v = value[rawKey];
      if (v === undefined) continue;
      const key = rawKey.normalize("NFC");
      if (seen.has(key)) {
        throw new Error(`Trùng khóa sau chuẩn hóa NFC tại ${path}.${key}`);
      }
      seen.add(key);
      entries.push([key, serializeJcsValue(v, `${path}.${rawKey}`)]);
    }
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${v}`).join(",")}}`;
  }
  throw new Error(`Kiểu không được phép (${typeof value}) tại ${path}`);
}

/** RFC 8785 JSON Canonicalization Scheme + Unicode NFC. */
export function canonicalizeJcs(value) {
  return serializeJcsValue(value, "$");
}

export function buildDomainMessage(domainLabel, hashHex) {
  const label = Buffer.from(domainLabel, "utf8");
  const hash = Buffer.from(hashHex, "hex");
  return Buffer.concat([label, Buffer.from([0x00]), hash]);
}

export function verifyEd25519DomainHash(domainLabel, hashHex, signatureB64, publicKeyHex) {
  try {
    if (typeof signatureB64 !== "string" || !isHex64(hashHex) || !isHex64(publicKeyHex)) {
      return false;
    }
    const sigBytes = Buffer.from(signatureB64, "base64");
    if (sigBytes.length !== 64) return false;
    const pubDer = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, "hex")]);
    const keyObj = createPublicKey({ key: pubDer, format: "der", type: "spki" });
    return verify(null, buildDomainMessage(domainLabel, hashHex), keyObj, sigBytes);
  } catch {
    return false;
  }
}

export function parseCheckpointPayload(input) {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
  const keys =
    input.format === CHECKPOINT_FORMAT_V2
      ? KEYS_V2
      : input.format === CHECKPOINT_FORMAT_V1
        ? KEYS_V1
        : null;
  if (!keys) return null;
  if (Object.keys(input).length !== keys.length || !keys.every((k) => k in input)) return null;
  if (input.alg !== ALG_ED25519) return null;
  if (
    typeof input.day !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(input.day) ||
    Number.isNaN(Date.parse(`${input.day}T00:00:00Z`))
  ) {
    return null;
  }
  if (!Number.isSafeInteger(input.headSeq) || input.headSeq < 1) return null;
  if (!isHex64(input.headEventHash)) return null;
  if (
    typeof input.issuedAt !== "string" ||
    !input.issuedAt.endsWith("Z") ||
    Number.isNaN(Date.parse(input.issuedAt))
  ) {
    return null;
  }
  if (typeof input.keyId !== "string" || !input.keyId) return null;

  const base = {
    day: input.day,
    headSeq: input.headSeq,
    headEventHash: input.headEventHash.toLowerCase(),
    issuedAt: input.issuedAt,
    alg: ALG_ED25519,
    keyId: input.keyId,
  };
  if (keys === KEYS_V1) {
    return { format: CHECKPOINT_FORMAT_V1, ...base };
  }
  if (input.treeSize !== base.headSeq || !isHex64(input.merkleRoot)) return null;
  return {
    format: CHECKPOINT_FORMAT_V2,
    ...base,
    treeSize: base.headSeq,
    merkleRoot: input.merkleRoot.toLowerCase(),
  };
}

/**
 * Verifies structure, RFC 8785 canonical JSON, SHA-256 bulletinHash, and
 * Ed25519 signature under domain `creatorshield/checkpoint/v1`. Never throws.
 */
export function verifyCheckpointBulletin(doc, keyMap) {
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    return { ok: false, reason: "Tệp bản tin không phải đối tượng JSON hợp lệ" };
  }
  const payload = parseCheckpointPayload(doc.payload);
  if (!payload) {
    return { ok: false, reason: "Payload bản tin sai định dạng (/1 hoặc /2)" };
  }
  let canonical;
  try {
    canonical = canonicalizeJcs(payload);
  } catch (err) {
    return { ok: false, reason: `Không thể chuẩn hóa RFC 8785: ${err.message}` };
  }
  if (doc.bulletin !== canonical) {
    return { ok: false, reason: "Văn bản bản tin không khớp nội dung chuẩn hóa RFC 8785" };
  }
  const recomputedHash = sha256Utf8(canonical);
  if (typeof doc.bulletinHash !== "string" || doc.bulletinHash.toLowerCase() !== recomputedHash) {
    return { ok: false, reason: "Mã băm SHA-256 bản tin không khớp nội dung" };
  }
  if (doc.signatureDomain && doc.signatureDomain !== CHECKPOINT_DOMAIN_LABEL) {
    return { ok: false, reason: `Nhãn miền chữ ký không hợp lệ: ${doc.signatureDomain}` };
  }
  const key = keyMap.get(payload.keyId);
  if (!key || key.alg !== payload.alg) {
    return {
      ok: false,
      reason: `Không tìm thấy khóa công khai ${payload.keyId} trong public-keys.json`,
      payload,
    };
  }
  const sigOk = verifyEd25519DomainHash(
    CHECKPOINT_DOMAIN_LABEL,
    recomputedHash,
    doc.signature,
    key.publicKeyHex,
  );
  if (!sigOk) {
    return {
      ok: false,
      reason: `Chữ ký Ed25519 không hợp lệ với khóa ${payload.keyId}`,
      payload,
    };
  }
  return { ok: true, payload };
}

function normalizeIsoOrNull(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  return Number.isNaN(Date.parse(value)) ? null : value.trim();
}

/**
 * Validates and normalizes `public-keys.json` while preserving backward
 * compatibility with minimal 3-field `{ keyId, alg, publicKeyHex }` entries.
 */
export function validatePublicKeys(raw) {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error("public-keys.json phải là mảng JSON khác rỗng.");
  }
  const seenIds = new Set();
  return raw.map((item, idx) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error(`public-keys.json[${idx}] phải là object.`);
    }
    if (typeof item.keyId !== "string" || !item.keyId.trim()) {
      throw new Error(`public-keys.json[${idx}] thiếu keyId hợp lệ.`);
    }
    const keyId = item.keyId.trim();
    if (seenIds.has(keyId)) {
      throw new Error(`Trùng keyId trong public-keys.json: ${keyId}`);
    }
    seenIds.add(keyId);

    if (item.alg !== ALG_ED25519) {
      throw new Error(`Khóa ${keyId} phải dùng thuật toán ${ALG_ED25519}.`);
    }
    if (!isHex64(item.publicKeyHex)) {
      throw new Error(`Khóa ${keyId} có publicKeyHex không phải 64 ký tự hex.`);
    }

    const status = VALID_STATUSES.has(item.status) ? item.status : "unknown";
    const role = VALID_ROLES.has(item.role) ? item.role : "unspecified";
    const safeUpToSeq =
      Number.isSafeInteger(item.safeUpToSeq) && item.safeUpToSeq >= 0
        ? item.safeUpToSeq
        : null;

    return {
      keyId,
      alg: ALG_ED25519,
      publicKeyHex: item.publicKeyHex.toLowerCase(),
      status,
      role,
      label: typeof item.label === "string" && item.label.trim() ? item.label.trim() : null,
      activeFrom: normalizeIsoOrNull(item.activeFrom),
      retiredAt: normalizeIsoOrNull(item.retiredAt),
      safeUpToSeq,
      note: typeof item.note === "string" && item.note.trim() ? item.note.trim() : null,
    };
  });
}
