/**
 * Zero-dependency static site generator for vuongnguyen16/creatorshield-checkpoints.
 *
 * Reads public-keys.json + checkpoints/**\/*.json, cryptographically validates
 * every bulletin (RFC 8785 + NFC + SHA-256 + Ed25519), resolves Git commit SHAs,
 * and outputs a self-contained pre-rendered static portal into dist/.
 */
import { execFileSync } from "node:child_process";
import { cp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CHECKPOINT_DOMAIN_LABEL,
  CHECKPOINT_FORMAT_V2,
  validatePublicKeys,
  verifyCheckpointBulletin,
} from "./verify-core.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_ROOT = resolve(__dirname, "..");
const DEFAULT_REPO_SLUG = "vuongnguyen16/creatorshield-checkpoints";
const DEFAULT_APP_BASE_URL = "https://creatorshield-mentor.vercel.app";

const ICONS = {
  checkCircle:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>',
  clockHistory:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>',
  alertOctagon:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>',
  helpCircle:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>',
  copy:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>',
  terminal:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>',
  externalLink:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>',
  chevronRight:
    '<svg class="icon chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="m9 18 6-6-6-6"/></svg>',
  shieldCheck:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>',
  shieldAlert:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
};

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const VN_DATE_FMT = new Intl.DateTimeFormat("vi-VN", {
  timeZone: "Asia/Ho_Chi_Minh",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
});

const VN_DATETIME_FMT = new Intl.DateTimeFormat("vi-VN", {
  timeZone: "Asia/Ho_Chi_Minh",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

export function formatVnDate(isoOrDay) {
  if (!isoOrDay) return "—";
  const parsed = /^\d{4}-\d{2}-\d{2}$/.test(isoOrDay)
    ? Date.parse(`${isoOrDay}T12:00:00Z`)
    : Date.parse(isoOrDay);
  if (Number.isNaN(parsed)) return String(isoOrDay);
  return VN_DATE_FMT.format(new Date(parsed));
}

export function formatVnDateTime(iso) {
  if (!iso) return "—";
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) return String(iso);
  return `${VN_DATETIME_FMT.format(new Date(parsed))} (giờ VN)`;
}

function statusMeta(status) {
  switch (status) {
    case "active":
      return { label: "Đang hoạt động", tone: "status-active", icon: ICONS.checkCircle };
    case "retired":
      return {
        label: "Đã nghỉ · hợp lệ lịch sử",
        tone: "status-retired",
        icon: ICONS.clockHistory,
      };
    case "compromised":
      return { label: "Cảnh báo · đã thu hồi", tone: "status-danger", icon: ICONS.alertOctagon };
    default:
      return { label: "Chưa khai báo trạng thái", tone: "status-unknown", icon: ICONS.helpCircle };
  }
}

function roleLabel(role) {
  switch (role) {
    case "checkpoint":
      return "Ký điểm kiểm chứng";
    case "event":
      return "Ký sự kiện ký gửi (web)";
    case "legacy":
      return "Khóa thử nghiệm lịch sử";
    default:
      return "Khóa hệ thống Ed25519";
  }
}

function defaultResolveCommitSha(rootDir, relPosixPath) {
  try {
    const out = execFileSync("git", ["log", "-1", "--format=%H", "--", relPosixPath], {
      cwd: rootDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return /^[0-9a-f]{40}$/i.test(out) ? out : "main";
  } catch {
    return "main";
  }
}

async function collectJsonFiles(dir) {
  const results = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...(await collectJsonFiles(full)));
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      results.push(full);
    }
  }
  return results;
}

function sortKeysForDisplay(keys) {
  const statusRank = { active: 0, compromised: 1, retired: 2, unknown: 3 };
  const roleRank = { checkpoint: 0, event: 1, legacy: 2, unspecified: 3 };
  return [...keys].sort((a, b) => {
    const sr = (statusRank[a.status] ?? 9) - (statusRank[b.status] ?? 9);
    if (sr !== 0) return sr;
    const rr = (roleRank[a.role] ?? 9) - (roleRank[b.role] ?? 9);
    if (rr !== 0) return rr;
    return a.keyId.localeCompare(b.keyId);
  });
}

function renderActiveKeysPlate(activeKeys, statsByKey, activeCopyBundle, activeCliCommand) {
  if (activeKeys.length === 0) {
    return `
      <div class="trust-plate">
        <div class="trust-plate-head">
          <div>
            <span class="pill status-warning">${ICONS.shieldAlert}<span>Chưa có khóa đang hoạt động</span></span>
            <h2 class="trust-plate-title">Không tìm thấy khóa ở trạng thái hoạt động</h2>
            <p class="trust-plate-lead">Kiểm tra danh sách toàn bộ khóa bên dưới hoặc xem trực tiếp tệp public-keys.json.</p>
          </div>
        </div>
      </div>`;
  }

  const rowsHtml = activeKeys
    .map((k) => {
      const stats = statsByKey.get(k.keyId);
      const pinValue = `${k.keyId}:${k.publicKeyHex}`;
      const cliFlag = `--trusted-key ${pinValue}`;
      const metaParts = [];
      if (k.activeFrom) metaParts.push(`Hiệu lực từ ${formatVnDate(k.activeFrom)}`);
      if (stats && stats.count > 0) {
        metaParts.push(`Đã ký ${stats.count} bản tin (đầu chuỗi mới nhất #${stats.maxHeadSeq})`);
      } else if (k.role === "event") {
        metaParts.push("Dùng xác minh chữ ký phiên bản tác phẩm trong evidence.json");
      }

      return `
        <article class="active-key-item" id="key-${escapeHtml(k.keyId)}">
          <div class="active-key-top">
            <div class="active-key-title-group">
              <span class="role-tag role-${escapeHtml(k.role)}">${escapeHtml(roleLabel(k.role))}</span>
              <h3 class="active-key-id"><code class="mono">${escapeHtml(k.keyId)}</code></h3>
              ${k.label ? `<p class="active-key-label">${escapeHtml(k.label)}</p>` : ""}
            </div>
            <span class="pill on-dark-active">${ICONS.checkCircle}<span>Đang hoạt động</span></span>
          </div>

          <div class="key-hex-well">
            <span class="key-hex-caption">Khóa công khai ${escapeHtml(k.alg)} (64 ký tự hex đầy đủ)</span>
            <code class="full-hash plate-hex">${escapeHtml(k.publicKeyHex)}</code>
          </div>

          <div class="active-key-foot">
            <p class="active-key-meta">${escapeHtml(metaParts.join(" · "))}</p>
            <div class="btn-row">
              <button type="button" class="btn btn-dark-subtle btn-sm" data-copy="${escapeHtml(pinValue)}" data-copy-label="khóa ${escapeHtml(k.keyId)} định dạng keyId:hex">
                ${ICONS.copy}<span>Sao chép keyId:hex</span>
              </button>
              <button type="button" class="btn btn-dark-subtle btn-sm" data-copy="${escapeHtml(cliFlag)}" data-copy-label="cờ CLI của ${escapeHtml(k.keyId)}">
                ${ICONS.terminal}<span>Sao chép --trusted-key</span>
              </button>
              <button type="button" class="btn btn-dark-subtle btn-sm" data-copy="${escapeHtml(k.publicKeyHex)}" data-copy-label="mã hex64 của ${escapeHtml(k.keyId)}">
                ${ICONS.copy}<span>Sao chép hex64</span>
              </button>
            </div>
          </div>
        </article>`;
    })
    .join("\n");

  return `
    <section class="trust-plate" aria-labelledby="active-keys-heading">
      <div class="trust-plate-head">
        <div>
          <p class="trust-plate-eyebrow">${activeKeys.length} khóa Ed25519 đang hoạt động</p>
          <h2 id="active-keys-heading" class="trust-plate-title">Khóa công khai đang hoạt động</h2>
          <p class="trust-plate-lead">
            Dùng trọn bộ khóa bên dưới để ghim khóa tin cậy khi kiểm chứng gói <code class="mono inline-dark">evidence.json</code> (bao gồm cả chữ ký tác phẩm lẫn bản tin Merkle).
          </p>
        </div>
        <div class="trust-plate-actions">
          <button type="button" class="btn btn-gold" data-copy="${escapeHtml(activeCopyBundle)}" data-copy-label="bộ ${activeKeys.length} khóa đang hoạt động (keyId:hex)">
            ${ICONS.copy}<span>Sao chép bộ khóa đang hoạt động</span>
          </button>
          <button type="button" class="btn btn-dark-outline" data-copy="${escapeHtml(activeCliCommand)}" data-copy-label="lệnh kiểm chứng CLI kèm bộ khóa đang hoạt động">
            ${ICONS.terminal}<span>Sao chép lệnh CLI đầy đủ</span>
          </button>
        </div>
      </div>

      <div class="active-key-list">
        ${rowsHtml}
      </div>
    </section>`;
}

function renderNonActiveKeyRows(nonActiveKeys, statsByKey) {
  if (nonActiveKeys.length === 0) {
    return `<li class="ledger-row"><p class="muted">Hiện chưa có khóa nào đã nghỉ hoặc bị thu hồi; toàn bộ khóa đang hoạt động được hiển thị trên tấm gốc tin cậy phía trên.</p></li>`;
  }
  return nonActiveKeys
    .map((k) => {
      const meta = statusMeta(k.status);
      const stats = statsByKey.get(k.keyId);
      const pinValue = `${k.keyId}:${k.publicKeyHex}`;
      const cliFlag = `--trusted-key ${pinValue}`;
      const facts = [];
      facts.push(`Thuật toán: ${k.alg}`);
      facts.push(`Vai trò: ${roleLabel(k.role)}`);
      if (k.activeFrom) facts.push(`Hiệu lực từ: ${formatVnDate(k.activeFrom)}`);
      if (k.retiredAt) facts.push(`Ngừng ký mới từ: ${formatVnDate(k.retiredAt)}`);
      if (stats && stats.count > 0) {
        facts.push(`Bản tin đã ký: ${stats.count} (${formatVnDate(stats.minDay)} – ${formatVnDate(stats.maxDay)})`);
      }

      const compromisedBanner =
        k.status === "compromised"
          ? `<div class="notice notice-danger" role="alert">
               ${ICONS.alertOctagon}
               <div>
                 <strong>Khóa này đã được gắn cờ cảnh báo / thu hồi.</strong>
                 ${
                   k.safeUpToSeq !== null
                     ? ` Các bản ghi tại hoặc trước đầu chuỗi <code class="mono">#${k.safeUpToSeq}</code> đã được neo công khai trước thời điểm sự cố.`
                     : " Đối chiếu thông báo sự cố và các điểm kiểm chứng đã công bố trước khi tin cậy bản ghi mới."
                 }
               </div>
             </div>`
          : "";

      return `
        <li class="ledger-row key-ledger-row is-${escapeHtml(k.status)}" id="key-${escapeHtml(k.keyId)}">
          <div class="ledger-row-head">
            <div class="ledger-row-title-wrap">
              <h3 class="ledger-row-title"><code class="mono">${escapeHtml(k.keyId)}</code></h3>
              ${k.label ? `<p class="ledger-row-sub">${escapeHtml(k.label)}</p>` : ""}
            </div>
            <span class="pill ${meta.tone}">${meta.icon}<span>${escapeHtml(meta.label)}</span></span>
          </div>

          ${compromisedBanner}

          <p class="ledger-facts">${escapeHtml(facts.join(" · "))}</p>

          <div class="code-field">
            <code class="full-hash code-block">${escapeHtml(k.publicKeyHex)}</code>
          </div>

          ${k.note ? `<p class="ledger-note">${escapeHtml(k.note)}</p>` : ""}

          <div class="btn-row">
            <button type="button" class="btn btn-secondary btn-sm" data-copy="${escapeHtml(pinValue)}" data-copy-label="khóa ${escapeHtml(k.keyId)} định dạng keyId:hex">
              ${ICONS.copy}<span>Sao chép keyId:hex</span>
            </button>
            <button type="button" class="btn btn-secondary btn-sm" data-copy="${escapeHtml(cliFlag)}" data-copy-label="cờ CLI của ${escapeHtml(k.keyId)}">
              ${ICONS.terminal}<span>Sao chép --trusted-key</span>
            </button>
            <button type="button" class="btn btn-secondary btn-sm" data-copy="${escapeHtml(k.publicKeyHex)}" data-copy-label="mã hex64 của ${escapeHtml(k.keyId)}">
              ${ICONS.copy}<span>Sao chép hex64</span>
            </button>
          </div>
        </li>`;
    })
    .join("\n");
}

function renderCheckpointRows(checkpoints) {
  if (checkpoints.length === 0) {
    return `<li class="ledger-row"><p class="muted">Chưa có bản tin điểm kiểm chứng nào trong thư mục checkpoints/.</p></li>`;
  }

  return checkpoints
    .map((cp) => {
      const isV2 = cp.format === CHECKPOINT_FORMAT_V2;
      const formatBadge = isV2
        ? `<span class="pill pill-gold">Merkle /2 · ${cp.treeSize} bản ghi</span>`
        : `<span class="pill pill-neutral">Đầu chuỗi /1 (lịch sử)</span>`;

      const sigBadge = cp.buildVerified
        ? `<span class="pill status-active" data-cp-sig-badge="${escapeHtml(cp.bulletinHash)}">${ICONS.shieldCheck}<span>Đã kiểm lúc dựng trang · Ed25519</span></span>`
        : `<span class="pill status-danger" data-cp-sig-badge="${escapeHtml(cp.bulletinHash)}">${ICONS.shieldAlert}<span>Không hợp lệ: ${escapeHtml(cp.buildVerifyReason ?? "Lỗi chữ ký")}</span></span>`;

      const merkleBlock = cp.merkleRoot
        ? `<div class="cp-hash-item">
             <div class="cp-hash-label-row">
               <span class="cp-hash-label">Gốc Merkle RFC 6962 (${cp.treeSize} bản ghi)</span>
               <button type="button" class="btn btn-ghost btn-xs" data-copy="${escapeHtml(cp.merkleRoot)}" data-copy-label="gốc Merkle ngày ${escapeHtml(cp.day)}">
                 ${ICONS.copy}<span>Sao chép</span>
               </button>
             </div>
             <code class="full-hash code-block">${escapeHtml(cp.merkleRoot)}</code>
           </div>`
        : `<p class="cp-v1-note">Bản tin giai đoạn M5 định dạng <code class="mono">creatorshield-checkpoint/1</code>: chỉ cố định đầu chuỗi, chưa kèm gốc Merkle RFC 6962.</p>`;

      const searchHaystack = [
        cp.day,
        formatVnDate(cp.day),
        `#${cp.headSeq}`,
        String(cp.headSeq),
        cp.keyId,
        cp.headEventHash,
        cp.merkleRoot ?? "",
        cp.bulletinHash,
        cp.format,
      ]
        .join(" ")
        .toLowerCase();

      return `
        <li class="ledger-row cp-row" data-cp-row="${escapeHtml(cp.bulletinHash)}" data-cp-key="${escapeHtml(cp.keyId)}" data-cp-search="${escapeHtml(searchHaystack)}">
          <div class="ledger-row-head">
            <div class="cp-heading-group">
              <h3 class="cp-title">Ngày ${escapeHtml(formatVnDate(cp.day))}</h3>
              <span class="pill pill-navy">Đầu chuỗi #${cp.headSeq}</span>
              ${formatBadge}
            </div>
            ${sigBadge}
          </div>

          <p class="ledger-facts">
            Khóa ký: <code class="mono">${escapeHtml(cp.keyId)}</code> · Phát hành: <time datetime="${escapeHtml(cp.issuedAt)}">${escapeHtml(formatVnDateTime(cp.issuedAt))}</time>
          </p>

          <div class="cp-hashes">
            ${merkleBlock}
            <div class="cp-hash-item">
              <div class="cp-hash-label-row">
                <span class="cp-hash-label">Mã băm đầu chuỗi (#${cp.headSeq})</span>
                <button type="button" class="btn btn-ghost btn-xs" data-copy="${escapeHtml(cp.headEventHash)}" data-copy-label="mã băm đầu chuỗi #${cp.headSeq}">
                  ${ICONS.copy}<span>Sao chép</span>
                </button>
              </div>
              <code class="full-hash code-block">${escapeHtml(cp.headEventHash)}</code>
            </div>
          </div>

          <div class="cp-footer">
            <a class="ext-link" href="${escapeHtml(cp.githubBlobUrl)}" target="_blank" rel="noopener noreferrer">
              <span>Mở tệp JSON gốc trên GitHub</span>
              ${ICONS.externalLink}
              <span class="sr-only"> (mở thẻ mới)</span>
            </a>

            <details class="disclosure">
              <summary>
                ${ICONS.chevronRight}
                <span>Xem chi tiết bản tin đã ký</span>
              </summary>
              <div class="disclosure-body">
                <p class="detail-label">Văn bản chuẩn hóa RFC 8785 (bulletin)</p>
                <code class="full-hash code-block">${escapeHtml(cp.bulletin)}</code>
                <div class="cp-hash-label-row">
                  <span class="detail-label">SHA-256 bản tin (bulletinHash)</span>
                  <button type="button" class="btn btn-ghost btn-xs" data-copy="${escapeHtml(cp.bulletinHash)}" data-copy-label="bulletinHash ngày ${escapeHtml(cp.day)}">
                    ${ICONS.copy}<span>Sao chép</span>
                  </button>
                </div>
                <code class="full-hash code-block">${escapeHtml(cp.bulletinHash)}</code>
                <p class="detail-label">Chữ ký Ed25519 (base64 · nhãn miền ${escapeHtml(CHECKPOINT_DOMAIN_LABEL)})</p>
                <code class="full-hash code-block">${escapeHtml(cp.signature)}</code>
              </div>
            </details>
          </div>
        </li>`;
    })
    .join("\n");
}

export async function buildSite({
  rootDir = DEFAULT_ROOT,
  outDir = join(DEFAULT_ROOT, "dist"),
  repoSlug = DEFAULT_REPO_SLUG,
  appBaseUrl = DEFAULT_APP_BASE_URL,
  resolveCommitSha = (relPosixPath) => defaultResolveCommitSha(rootDir, relPosixPath),
} = {}) {
  const cleanAppUrl = appBaseUrl.replace(/\/+$/, "");
  const repoWebUrl = `https://github.com/${repoSlug}`;

  // 1. Read & validate public-keys.json
  const rawKeysText = await readFile(join(rootDir, "public-keys.json"), "utf8");
  const normalizedKeys = validatePublicKeys(JSON.parse(rawKeysText));
  const sortedKeys = sortKeysForDisplay(normalizedKeys);
  const keyMap = new Map(sortedKeys.map((k) => [k.keyId, k]));

  // 2. Read & verify all checkpoints/**/*.json
  const checkpointFiles = await collectJsonFiles(join(rootDir, "checkpoints"));
  const checkpoints = [];

  for (const absPath of checkpointFiles) {
    const relPosixPath = relative(rootDir, absPath).split("\\").join("/");
    const doc = JSON.parse(await readFile(absPath, "utf8"));
    const check = verifyCheckpointBulletin(doc, keyMap);
    const payload = check.payload ?? doc.payload ?? {};
    const commitSha = resolveCommitSha(relPosixPath) || "main";

    checkpoints.push({
      path: relPosixPath,
      commitSha,
      githubBlobUrl: `${repoWebUrl}/blob/${commitSha}/${relPosixPath}`,
      format: payload.format ?? "unknown",
      day: payload.day ?? "",
      headSeq: payload.headSeq ?? 0,
      headEventHash: payload.headEventHash ?? "",
      treeSize: payload.treeSize ?? null,
      merkleRoot: payload.merkleRoot ?? null,
      issuedAt: payload.issuedAt ?? "",
      alg: payload.alg ?? "Ed25519",
      keyId: payload.keyId ?? "",
      bulletin: typeof doc.bulletin === "string" ? doc.bulletin : "",
      bulletinHash: typeof doc.bulletinHash === "string" ? doc.bulletinHash : "",
      signature: typeof doc.signature === "string" ? doc.signature : "",
      signatureDomain: doc.signatureDomain ?? CHECKPOINT_DOMAIN_LABEL,
      buildVerified: check.ok,
      buildVerifyReason: check.ok ? null : check.reason,
    });
  }

  // Sort strictly by issuedAt descending, tie-breaking headSeq desc, bulletinHash asc
  checkpoints.sort((a, b) => {
    const dt = Date.parse(b.issuedAt) - Date.parse(a.issuedAt);
    if (!Number.isNaN(dt) && dt !== 0) return dt;
    if (b.headSeq !== a.headSeq) return b.headSeq - a.headSeq;
    return a.bulletinHash.localeCompare(b.bulletinHash);
  });

  // Compute per-key checkpoint stats
  const statsByKey = new Map();
  for (const cp of checkpoints) {
    const prev = statsByKey.get(cp.keyId) ?? {
      count: 0,
      maxHeadSeq: 0,
      minDay: cp.day,
      maxDay: cp.day,
    };
    prev.count += 1;
    if (cp.headSeq > prev.maxHeadSeq) prev.maxHeadSeq = cp.headSeq;
    if (cp.day && cp.day < prev.minDay) prev.minDay = cp.day;
    if (cp.day && cp.day > prev.maxDay) prev.maxDay = cp.day;
    statsByKey.set(cp.keyId, prev);
  }

  const activeKeys = sortedKeys.filter((k) => k.status === "active");
  const nonActiveKeys = sortedKeys.filter((k) => k.status !== "active");
  const activeCopyBundle = activeKeys.map((k) => `${k.keyId}:${k.publicKeyHex}`).join("\n");
  const activeCliFlags = activeKeys.map((k) => `--trusted-key ${k.keyId}:${k.publicKeyHex}`).join(" ");
  const activeCliCommand = activeCliFlags
    ? `node creatorshield-verify.mjs evidence.json --file <tep-goc> ${activeCliFlags}`
    : "node creatorshield-verify.mjs evidence.json --file <tep-goc>";

  const verifiedCount = checkpoints.filter((c) => c.buildVerified).length;
  const latestCp = checkpoints[0] ?? null;
  const buildSummaryMeta = latestCp
    ? `Gồm ${sortedKeys.length} khóa công khai (${activeKeys.length} đang hoạt động) và ${checkpoints.length} bản tin điểm kiểm chứng (mới nhất ngày ${formatVnDate(latestCp.day)}, đầu chuỗi #${latestCp.headSeq}).`
    : `Gồm ${sortedKeys.length} khóa công khai (${activeKeys.length} đang hoạt động).`;

  const filterKeyIds = [...new Set(checkpoints.map((c) => c.keyId).filter(Boolean))];
  const keyFilterOptionsHtml = filterKeyIds
    .map((id) => {
      const count = statsByKey.get(id)?.count ?? 0;
      return `<option value="${escapeHtml(id)}">${escapeHtml(id)} (${count} bản tin)</option>`;
    })
    .join("\n");

  // 3. Render HTML from site/template.html
  const templateHtml = await readFile(join(rootDir, "site/template.html"), "utf8");
  const replacements = new Map([
    ["{{REPO_SLUG}}", escapeHtml(repoSlug)],
    ["{{REPO_WEB_URL}}", escapeHtml(repoWebUrl)],
    ["{{APP_BASE_URL}}", escapeHtml(cleanAppUrl)],
    ["{{BUILD_SUMMARY_META}}", escapeHtml(buildSummaryMeta)],
    ["{{ACTIVE_KEYS_PLATE}}", renderActiveKeysPlate(activeKeys, statsByKey, activeCopyBundle, activeCliCommand)],
    ["{{KEY_COUNT}}", String(nonActiveKeys.length)],
    ["{{KEY_REGISTRY_ROWS}}", renderNonActiveKeyRows(nonActiveKeys, statsByKey)],
    ["{{CLI_EXAMPLE_COMMAND}}", escapeHtml(activeCliCommand)],
    ["{{CHECKPOINT_COUNT}}", String(checkpoints.length)],
    ["{{VERIFIED_CHECKPOINT_COUNT}}", String(verifiedCount)],
    ["{{KEY_FILTER_OPTIONS}}", keyFilterOptionsHtml],
    ["{{CHECKPOINT_ROWS}}", renderCheckpointRows(checkpoints)],
  ]);

  let renderedHtml = templateHtml;
  for (const [token, value] of replacements) {
    renderedHtml = renderedHtml.replaceAll(token, value);
  }

  // 4. Emit static dist/
  await rm(outDir, { recursive: true, force: true });
  await mkdir(join(outDir, "data"), { recursive: true });

  const registryData = {
    generatedAt: new Date().toISOString(),
    repoSlug,
    repoWebUrl,
    appBaseUrl: cleanAppUrl,
    activeCopyBundle,
    activeCliCommand,
    keys: sortedKeys.map((k) => ({
      ...k,
      signedBulletinCount: statsByKey.get(k.keyId)?.count ?? 0,
      maxHeadSeq: statsByKey.get(k.keyId)?.maxHeadSeq ?? null,
    })),
    checkpoints,
  };

  await writeFile(join(outDir, "index.html"), renderedHtml, "utf8");
  await writeFile(join(outDir, "data/registry.json"), `${JSON.stringify(registryData, null, 2)}\n`, "utf8");
  await writeFile(join(outDir, "public-keys.json"), rawKeysText, "utf8");
  await writeFile(join(outDir, ".nojekyll"), "", "utf8");

  await cp(join(rootDir, "site/styles.css"), join(outDir, "styles.css"));
  await cp(join(rootDir, "site/app.js"), join(outDir, "app.js"));
  await cp(join(rootDir, "site/favicon.svg"), join(outDir, "favicon.svg"));

  try {
    await cp(join(rootDir, "site/assets"), join(outDir, "assets"), { recursive: true });
  } catch {
    /* allow minimal fixtures without font assets */
  }
  try {
    await cp(join(rootDir, "checkpoints"), join(outDir, "checkpoints"), { recursive: true });
  } catch {
    /* allow empty checkpoints in minimal fixtures */
  }

  return {
    keyCount: sortedKeys.length,
    activeKeyCount: activeKeys.length,
    checkpointCount: checkpoints.length,
    verifiedCheckpointCount: verifiedCount,
    outDir,
  };
}

// CLI entry point
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const summary = await buildSite();
  console.log(
    `Built CreatorShield public trust portal → ${summary.outDir} (${summary.keyCount} keys, ${summary.activeKeyCount} active, ${summary.verifiedCheckpointCount}/${summary.checkpointCount} checkpoints verified).`,
  );
}
