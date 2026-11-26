/**
 * Zero-dependency static site generator for vuongnguyen16/creatorshield-checkpoints.
 *
 * Designed for calm, zero-overwhelm progressive disclosure:
 * - Active keys shown in a compact 3-row table with 1 copy action per key
 * - Retired/historical keys tucked into a clean expandable drawer (unless compromised)
 * - Latest checkpoint highlighted cleanly; full history rendered as compact 1-line
 *   expandable accordion rows so all 10+ checkpoints fit in one screen glance.
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
      return "Ký tác phẩm trên web";
    case "legacy":
      return "Khóa thử nghiệm cũ";
    default:
      return "Khóa Ed25519";
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

function renderNonActiveDrawer(nonActiveKeys) {
  if (nonActiveKeys.length === 0) return "";
  const hasCompromised = nonActiveKeys.some((k) => k.status === "compromised");
  const openAttr = hasCompromised ? " open" : "";

  const itemsHtml = nonActiveKeys
    .map((k) => {
      const meta = statusMeta(k.status);
      const pinValue = `${k.keyId}:${k.publicKeyHex}`;
      const compromisedAlert =
        k.status === "compromised"
          ? `<div class="notice notice-danger" role="alert">
               ${ICONS.alertOctagon}
               <div>
                 <strong>Cảnh báo thu hồi khóa.</strong>
                 ${
                   k.safeUpToSeq !== null
                     ? ` Chỉ bản ghi tại hoặc trước <code class="mono">#${k.safeUpToSeq}</code> đã neo trước sự cố.`
                     : " Kiểm tra thông báo sự cố trước khi tin cậy bản ghi mới."
                 }
               </div>
             </div>`
          : "";

      return `
        <div class="retired-key-card" id="key-${escapeHtml(k.keyId)}">
          <div class="retired-key-head">
            <div>
              <strong class="mono">${escapeHtml(k.keyId)}</strong>
              ${k.label ? `<span class="retired-key-label"> — ${escapeHtml(k.label)}</span>` : ""}
            </div>
            <span class="pill ${meta.tone}">${meta.icon}<span>${escapeHtml(meta.label)}</span></span>
          </div>
          ${compromisedAlert}
          <div class="compact-key-code-row">
            <code class="full-hash plate-hex">${escapeHtml(k.publicKeyHex)}</code>
            <button type="button" class="btn btn-dark-subtle btn-xs" data-copy="${escapeHtml(pinValue)}" data-copy-label="khóa ${escapeHtml(k.keyId)}">
              ${ICONS.copy}<span>Sao chép</span>
            </button>
          </div>
          ${k.note ? `<p class="retired-key-note">${escapeHtml(k.note)}</p>` : ""}
        </div>`;
    })
    .join("\n");

  return `
    <details class="plate-drawer"${openAttr} id="khoa-cong-khai">
      <summary>
        ${ICONS.chevronRight}
        <span>Khóa cũ đã nghỉ &amp; lịch sử xoay khóa (${nonActiveKeys.length} khóa — vẫn hợp lệ cho bản ghi cũ)</span>
      </summary>
      <div class="plate-drawer-body">
        ${itemsHtml}
      </div>
    </details>`;
}

function renderActiveKeysPlate(activeKeys, nonActiveKeys, activeCopyBundle, activeCliCommand) {
  if (activeKeys.length === 0) {
    return `
      <section class="trust-plate" aria-labelledby="active-keys-heading">
        <div class="trust-plate-head">
          <div>
            <span class="pill status-warning">${ICONS.shieldAlert}<span>Chưa có khóa đang hoạt động</span></span>
            <h2 id="active-keys-heading" class="trust-plate-title">Danh sách khóa công khai</h2>
          </div>
        </div>
        ${renderNonActiveDrawer(nonActiveKeys)}
      </section>`;
  }

  const rowsHtml = activeKeys
    .map((k) => {
      const pinValue = `${k.keyId}:${k.publicKeyHex}`;
      return `
        <article class="active-key-row" id="key-${escapeHtml(k.keyId)}">
          <div class="active-key-info">
            <span class="role-tag role-${escapeHtml(k.role)}">${escapeHtml(roleLabel(k.role))}</span>
            <h3 class="active-key-id"><code class="mono">${escapeHtml(k.keyId)}</code></h3>
            ${k.label ? `<span class="active-key-desc">${escapeHtml(k.label)}</span>` : ""}
          </div>
          <div class="compact-key-code-row">
            <code class="full-hash plate-hex">${escapeHtml(k.publicKeyHex)}</code>
            <button type="button" class="btn btn-dark-subtle btn-xs" data-copy="${escapeHtml(pinValue)}" data-copy-label="khóa ${escapeHtml(k.keyId)}">
              ${ICONS.copy}<span>Sao chép</span>
            </button>
          </div>
        </article>`;
    })
    .join("\n");

  return `
    <section class="trust-plate" aria-labelledby="active-keys-heading">
      <div class="trust-plate-head">
        <div>
          <h2 id="active-keys-heading" class="trust-plate-title">Khóa công khai đang hoạt động (${activeKeys.length})</h2>
          <p class="trust-plate-lead">
            Bấm nút vàng để chép toàn bộ khóa đang hoạt động rồi dán vào mục <em>Ghim khóa tin cậy</em> khi kiểm chứng gói <code class="mono inline-dark">evidence.json</code>.
          </p>
        </div>
        <div class="trust-plate-actions">
          <button type="button" class="btn btn-gold" data-copy="${escapeHtml(activeCopyBundle)}" data-copy-label="bộ ${activeKeys.length} khóa đang hoạt động">
            ${ICONS.copy}<span>Sao chép bộ khóa (dán vào Web)</span>
          </button>
          <button type="button" class="btn btn-dark-outline btn-sm" data-copy="${escapeHtml(activeCliCommand)}" data-copy-label="lệnh kiểm chứng CLI">
            ${ICONS.terminal}<span>Sao chép lệnh CLI</span>
          </button>
        </div>
      </div>

      <div class="active-key-list">
        ${rowsHtml}
      </div>

      ${renderNonActiveDrawer(nonActiveKeys)}
    </section>`;
}

function renderLatestCheckpointSpotlight(latest) {
  if (!latest) return "";
  const sigBadge = latest.buildVerified
    ? `<span class="pill status-active" data-cp-sig-badge="${escapeHtml(latest.bulletinHash)}">${ICONS.shieldCheck}<span>Chữ ký hợp lệ · Ed25519</span></span>`
    : `<span class="pill status-danger" data-cp-sig-badge="${escapeHtml(latest.bulletinHash)}">${ICONS.shieldAlert}<span>Không hợp lệ: ${escapeHtml(latest.buildVerifyReason ?? "Lỗi")}</span></span>`;

  return `
    <article class="cp-spotlight" aria-labelledby="cp-spotlight-heading">
      <div class="cp-spotlight-head">
        <div class="cp-spotlight-title-wrap">
          <div class="cp-badge-row">
            <span class="pill pill-spotlight">Điểm kiểm chứng mới nhất đang neo chuỗi</span>
            <span class="pill pill-navy">${escapeHtml(latest.coverageLabel)}</span>
            <span class="pill ${latest.deltaType === "expanded" ? "pill-delta-new" : "pill-neutral"}">${escapeHtml(latest.deltaLabel)}</span>
          </div>
          <h3 id="cp-spotlight-heading" class="cp-spotlight-title">
            Ngày ${escapeHtml(formatVnDate(latest.day))} · Phát hành lúc ${escapeHtml(formatVnDateTime(latest.issuedAt))}
          </h3>
        </div>
        ${sigBadge}
      </div>

      ${
        latest.merkleRoot
          ? `<div class="cp-hash-item">
               <div class="cp-hash-label-row">
                 <span class="cp-hash-label">Gốc Merkle RFC 6962 (${latest.treeSize} bản ghi từ #1 đến #${latest.headSeq})</span>
                 <button type="button" class="btn btn-secondary btn-xs" data-copy="${escapeHtml(latest.merkleRoot)}" data-copy-label="gốc Merkle mới nhất">
                   ${ICONS.copy}<span>Sao chép gốc Merkle</span>
                 </button>
               </div>
               <code class="full-hash code-block">${escapeHtml(latest.merkleRoot)}</code>
             </div>`
          : ""
      }

      <div class="cp-spotlight-foot">
        <span class="muted">Khóa ký: <code class="mono">${escapeHtml(latest.keyId)}</code></span>
        <a class="ext-link" href="${escapeHtml(latest.githubBlobUrl)}" target="_blank" rel="noopener noreferrer">
          <span>Mở tệp JSON gốc trên GitHub</span>
          ${ICONS.externalLink}
          <span class="sr-only"> (mở thẻ mới)</span>
        </a>
      </div>
    </article>`;
}

function renderCheckpointQuickFilters(checkpoints) {
  const total = checkpoints.length;
  const changedCount = checkpoints.filter((c) => c.deltaType !== "reconfirmed").length;
  const v2Count = checkpoints.filter((c) => c.format === CHECKPOINT_FORMAT_V2).length;
  const v1Count = total - v2Count;

  return `
    <div class="cp-quick-filters" role="group" aria-label="Bộ lọc nhanh điểm kiểm chứng">
      <button type="button" class="chip-btn is-selected" data-cp-quick-filter="all" aria-pressed="true">
        Tất cả (${total})
      </button>
      <button type="button" class="chip-btn" data-cp-quick-filter="changed" aria-pressed="false">
        Mốc có bản ghi mới (${changedCount})
      </button>
      <button type="button" class="chip-btn" data-cp-quick-filter="v2" aria-pressed="false">
        Có gốc Merkle /2 (${v2Count})
      </button>
      <button type="button" class="chip-btn" data-cp-quick-filter="v1" aria-pressed="false">
        Lịch sử /1 (${v1Count})
      </button>
    </div>`;
}

function renderCheckpointRows(checkpoints) {
  if (checkpoints.length === 0) {
    return `<li class="cp-accordion-item"><p class="muted">Chưa có bản tin điểm kiểm chứng nào.</p></li>`;
  }

  return checkpoints
    .map((cp) => {
      const isV2 = cp.format === CHECKPOINT_FORMAT_V2;
      const deltaTone =
        cp.deltaType === "expanded"
          ? "pill-delta-new"
          : cp.deltaType === "initial"
            ? "pill-gold"
            : "pill-neutral";

      const sigBadge = cp.buildVerified
        ? `<span class="pill status-active" data-cp-sig-badge="${escapeHtml(cp.bulletinHash)}">${ICONS.shieldCheck}<span>Hợp lệ</span></span>`
        : `<span class="pill status-danger" data-cp-sig-badge="${escapeHtml(cp.bulletinHash)}">${ICONS.shieldAlert}<span>Lỗi chữ ký</span></span>`;

      const searchHaystack = [
        cp.day,
        formatVnDate(cp.day),
        `#${cp.headSeq}`,
        String(cp.headSeq),
        cp.coverageLabel,
        cp.deltaLabel,
        cp.keyId,
        cp.keyLabel,
        cp.headEventHash,
        cp.merkleRoot ?? "",
        cp.bulletinHash,
        cp.format,
      ]
        .join(" ")
        .toLowerCase();

      return `
        <li
          class="cp-accordion-item"
          data-cp-row="${escapeHtml(cp.bulletinHash)}"
          data-cp-key="${escapeHtml(cp.keyId)}"
          data-cp-format="${isV2 ? "v2" : "v1"}"
          data-cp-changed="${cp.deltaType !== "reconfirmed" ? "true" : "false"}"
          data-cp-search="${escapeHtml(searchHaystack)}"
        >
          <details class="cp-accordion">
            <summary class="cp-accordion-summary">
              <div class="cp-row-left">
                ${ICONS.chevronRight}
                <strong class="cp-row-date">${escapeHtml(formatVnDate(cp.day))}</strong>
                <span class="pill pill-navy">${escapeHtml(cp.coverageLabel)}</span>
                <span class="pill ${deltaTone}">${escapeHtml(cp.deltaLabel)}</span>
                ${!isV2 ? `<span class="pill pill-neutral">Bản /1</span>` : ""}
              </div>
              <div class="cp-row-right">
                <span class="cp-row-time">${escapeHtml(formatVnDateTime(cp.issuedAt))}</span>
                ${sigBadge}
              </div>
            </summary>

            <div class="cp-accordion-body">
              <p class="ledger-facts">
                Khóa ký: <strong>${escapeHtml(cp.keyLabel)}</strong> (<code class="mono">${escapeHtml(cp.keyId)}</code>) · Định dạng: <code class="mono">${escapeHtml(cp.format)}</code> · <span data-cp-step3-text="${escapeHtml(cp.bulletinHash)}">${cp.buildVerified ? "Đã xác minh chữ ký Ed25519 &amp; RFC 8785" : escapeHtml(cp.buildVerifyReason ?? "Lỗi")}</span>
              </p>

              ${
                cp.merkleRoot
                  ? `<div class="cp-hash-item">
                       <div class="cp-hash-label-row">
                         <span class="cp-hash-label">Gốc Merkle RFC 6962 (${cp.treeSize} bản ghi)</span>
                         <button type="button" class="btn btn-ghost btn-xs" data-copy="${escapeHtml(cp.merkleRoot)}" data-copy-label="gốc Merkle ngày ${escapeHtml(cp.day)}">
                           ${ICONS.copy}<span>Sao chép gốc Merkle</span>
                         </button>
                       </div>
                       <code class="full-hash code-block">${escapeHtml(cp.merkleRoot)}</code>
                     </div>`
                  : `<p class="cp-v1-note">Bản tin giai đoạn M5 (<code class="mono">creatorshield-checkpoint/1</code>): cố định đầu chuỗi #${cp.headSeq}, chưa kèm gốc Merkle.</p>`
              }

              <div class="cp-hash-item">
                <div class="cp-hash-label-row">
                  <span class="cp-hash-label">Mã băm đầu chuỗi (#${cp.headSeq})</span>
                  <button type="button" class="btn btn-ghost btn-xs" data-copy="${escapeHtml(cp.headEventHash)}" data-copy-label="mã băm đầu chuỗi #${cp.headSeq}">
                    ${ICONS.copy}<span>Sao chép đầu chuỗi</span>
                  </button>
                </div>
                <code class="full-hash code-block">${escapeHtml(cp.headEventHash)}</code>
              </div>

              <div class="cp-hash-item">
                <div class="cp-hash-label-row">
                  <span class="cp-hash-label">SHA-256 bản tin (bulletinHash)</span>
                  <button type="button" class="btn btn-ghost btn-xs" data-copy="${escapeHtml(cp.bulletinHash)}" data-copy-label="bulletinHash ngày ${escapeHtml(cp.day)}">
                    ${ICONS.copy}<span>Sao chép mã bản tin</span>
                  </button>
                </div>
                <code class="full-hash code-block">${escapeHtml(cp.bulletinHash)}</code>
              </div>

              <div class="cp-accordion-foot">
                <a class="ext-link" href="${escapeHtml(cp.githubBlobUrl)}" target="_blank" rel="noopener noreferrer">
                  <span>Mở tệp JSON gốc trên GitHub</span>
                  ${ICONS.externalLink}
                  <span class="sr-only"> (mở thẻ mới)</span>
                </a>
              </div>
            </div>
          </details>
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

  const rawKeysText = await readFile(join(rootDir, "public-keys.json"), "utf8");
  const normalizedKeys = validatePublicKeys(JSON.parse(rawKeysText));
  const sortedKeys = sortKeysForDisplay(normalizedKeys);
  const keyMap = new Map(sortedKeys.map((k) => [k.keyId, k]));

  const checkpointFiles = await collectJsonFiles(join(rootDir, "checkpoints"));
  const checkpoints = [];

  for (const absPath of checkpointFiles) {
    const relPosixPath = relative(rootDir, absPath).split("\\").join("/");
    const doc = JSON.parse(await readFile(absPath, "utf8"));
    const check = verifyCheckpointBulletin(doc, keyMap);
    const payload = check.payload ?? doc.payload ?? {};
    const commitSha = resolveCommitSha(relPosixPath) || "main";
    const keyInfo = keyMap.get(payload.keyId ?? "");
    const headSeq = payload.headSeq ?? 0;

    checkpoints.push({
      path: relPosixPath,
      commitSha,
      githubBlobUrl: `${repoWebUrl}/blob/${commitSha}/${relPosixPath}`,
      format: payload.format ?? "unknown",
      day: payload.day ?? "",
      headSeq,
      coverageLabel: headSeq > 1 ? `Bảo chứng bản ghi #1 – #${headSeq}` : `Bảo chứng bản ghi #1`,
      headEventHash: payload.headEventHash ?? "",
      treeSize: payload.treeSize ?? null,
      merkleRoot: payload.merkleRoot ?? null,
      issuedAt: payload.issuedAt ?? "",
      alg: payload.alg ?? "Ed25519",
      keyId: payload.keyId ?? "",
      keyLabel: keyInfo?.label ?? (payload.keyId || "Khóa hệ thống"),
      bulletin: typeof doc.bulletin === "string" ? doc.bulletin : "",
      bulletinHash: typeof doc.bulletinHash === "string" ? doc.bulletinHash : "",
      signature: typeof doc.signature === "string" ? doc.signature : "",
      signatureDomain: doc.signatureDomain ?? CHECKPOINT_DOMAIN_LABEL,
      buildVerified: check.ok,
      buildVerifyReason: check.ok ? null : check.reason,
      isLatest: false,
      deltaType: "initial",
      deltaLabel: "",
    });
  }

  checkpoints.sort((a, b) => {
    const dt = Date.parse(b.issuedAt) - Date.parse(a.issuedAt);
    if (!Number.isNaN(dt) && dt !== 0) return dt;
    if (b.headSeq !== a.headSeq) return b.headSeq - a.headSeq;
    return a.bulletinHash.localeCompare(b.bulletinHash);
  });

  for (let i = checkpoints.length - 1; i >= 0; i--) {
    const cp = checkpoints[i];
    cp.isLatest = i === 0;
    if (i === checkpoints.length - 1) {
      cp.deltaType = "initial";
      cp.deltaLabel = `Mốc đầu tiên (#1 – #${cp.headSeq})`;
    } else {
      const older = checkpoints[i + 1];
      const diff = cp.headSeq - older.headSeq;
      if (diff > 0) {
        const rangeText =
          diff === 1 ? `#${cp.headSeq}` : `#${older.headSeq + 1} – #${cp.headSeq}`;
        cp.deltaType = "expanded";
        cp.deltaLabel = `+${diff} bản ghi mới (${rangeText})`;
      } else {
        cp.deltaType = "reconfirmed";
        cp.deltaLabel = `Tái xác nhận`;
      }
    }
  }

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

  const filterKeyIds = [...new Set(checkpoints.map((c) => c.keyId).filter(Boolean))];
  const keyFilterOptionsHtml = filterKeyIds
    .map((id) => {
      const count = statsByKey.get(id)?.count ?? 0;
      return `<option value="${escapeHtml(id)}">${escapeHtml(id)} (${count})</option>`;
    })
    .join("\n");

  const templateHtml = await readFile(join(rootDir, "site/template.html"), "utf8");
  const replacements = new Map([
    ["{{REPO_SLUG}}", escapeHtml(repoSlug)],
    ["{{REPO_WEB_URL}}", escapeHtml(repoWebUrl)],
    ["{{APP_BASE_URL}}", escapeHtml(cleanAppUrl)],
    ["{{ACTIVE_KEYS_PLATE}}", renderActiveKeysPlate(activeKeys, nonActiveKeys, activeCopyBundle, activeCliCommand)],
    ["{{CLI_EXAMPLE_COMMAND}}", escapeHtml(activeCliCommand)],
    ["{{CHECKPOINT_COUNT}}", String(checkpoints.length)],
    ["{{VERIFIED_CHECKPOINT_COUNT}}", String(verifiedCount)],
    ["{{LATEST_CHECKPOINT_SPOTLIGHT}}", renderLatestCheckpointSpotlight(latestCp)],
    ["{{CHECKPOINT_QUICK_FILTERS}}", renderCheckpointQuickFilters(checkpoints)],
    ["{{KEY_FILTER_OPTIONS}}", keyFilterOptionsHtml],
    ["{{CHECKPOINT_ROWS}}", renderCheckpointRows(checkpoints)],
  ]);

  let renderedHtml = templateHtml;
  for (const [token, value] of replacements) {
    renderedHtml = renderedHtml.replaceAll(token, value);
  }

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
    /* allow minimal fixtures */
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

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const summary = await buildSite();
  console.log(
    `Built CreatorShield public trust portal → ${summary.outDir} (${summary.keyCount} keys, ${summary.activeKeyCount} active, ${summary.verifiedCheckpointCount}/${summary.checkpointCount} checkpoints verified).`,
  );
}
