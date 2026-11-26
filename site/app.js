/**
 * Progressive enhancement for CreatorShield Public Trust-Root Portal.
 * - 1-click clipboard copy with ARIA status announcements
 * - Local 64-hex / keyId Quick Match verifier (zero network calls)
 * - Checkpoint filtering by keyId and free-text query
 * - Live in-browser Ed25519 signature verification via Web Crypto API with honest fallback
 */

const CHECKPOINT_DOMAIN = "creatorshield/checkpoint/v1";
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

const announcer = document.getElementById("live-announcer");

function announce(message) {
  if (!announcer) return;
  announcer.textContent = "";
  requestAnimationFrame(() => {
    announcer.textContent = message;
  });
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.className = "sr-only";
  document.body.appendChild(ta);
  ta.select();
  const ok = document.execCommand("copy");
  document.body.removeChild(ta);
  if (!ok) throw new Error("Clipboard fallback failed");
}

function setupCopyButtons() {
  document.addEventListener("click", async (event) => {
    const btn = event.target.closest("button[data-copy]");
    if (!btn) return;
    const value = btn.getAttribute("data-copy") ?? "";
    const label = btn.getAttribute("data-copy-label") ?? "nội dung";
    const span = btn.querySelector("span");
    const originalText = btn.dataset.originalLabel ?? (span ? span.textContent : btn.textContent);
    btn.dataset.originalLabel = originalText;

    try {
      await copyText(value);
      btn.classList.add("is-copied");
      if (span) span.textContent = "Đã sao chép";
      announce(`Đã sao chép ${label}.`);
      clearTimeout(Number(btn.dataset.copyTimer || 0));
      const timer = setTimeout(() => {
        btn.classList.remove("is-copied");
        if (span) span.textContent = btn.dataset.originalLabel;
      }, 2200);
      btn.dataset.copyTimer = String(timer);
    } catch {
      announce(`Không thể tự sao chép ${label}. Hãy bôi đen và sao chép thủ công.`);
    }
  });
}

function setupCheckpointFilters() {
  const keySelect = document.getElementById("cp-key-filter");
  const searchInput = document.getElementById("cp-search-input");
  const list = document.getElementById("cp-list");
  const countEl = document.getElementById("cp-filter-count");
  const emptyEl = document.getElementById("cp-empty");
  const clearBtn = document.getElementById("cp-clear-filters");
  const quickButtons = Array.from(document.querySelectorAll("[data-cp-quick-filter]"));

  if (!list || !keySelect || !searchInput) return;
  const rows = Array.from(list.querySelectorAll("[data-cp-row]"));
  const total = rows.length;
  let activeQuickMode = "all";

  function setQuickMode(mode) {
    activeQuickMode = mode;
    for (const btn of quickButtons) {
      const selected = btn.getAttribute("data-cp-quick-filter") === mode;
      btn.classList.toggle("is-selected", selected);
      btn.setAttribute("aria-pressed", selected ? "true" : "false");
    }
  }

  function applyFilter() {
    const selectedKey = keySelect.value.trim();
    const query = searchInput.value.trim().toLowerCase();
    let visible = 0;
    for (const row of rows) {
      const matchesKey = !selectedKey || row.getAttribute("data-cp-key") === selectedKey;
      const haystack = row.getAttribute("data-cp-search") ?? "";
      const matchesQuery = !query || haystack.includes(query);
      let matchesQuick = true;
      if (activeQuickMode === "changed") {
        matchesQuick = row.getAttribute("data-cp-changed") === "true";
      } else if (activeQuickMode === "v2") {
        matchesQuick = row.getAttribute("data-cp-format") === "v2";
      } else if (activeQuickMode === "v1") {
        matchesQuick = row.getAttribute("data-cp-format") === "v1";
      }
      const show = matchesKey && matchesQuery && matchesQuick;
      row.hidden = !show;
      if (show) visible += 1;
    }
    if (countEl) {
      countEl.textContent = `Đang hiển thị ${visible} / ${total} bản tin.`;
    }
    if (emptyEl) {
      emptyEl.hidden = visible > 0 || total === 0;
    }
  }

  for (const btn of quickButtons) {
    btn.addEventListener("click", () => {
      setQuickMode(btn.getAttribute("data-cp-quick-filter") ?? "all");
      applyFilter();
    });
  }

  keySelect.addEventListener("change", applyFilter);
  searchInput.addEventListener("input", applyFilter);
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      keySelect.value = "";
      searchInput.value = "";
      setQuickMode("all");
      applyFilter();
      searchInput.focus();
    });
  }
}

function formatDayVn(day) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(day || ""));
  return m ? `${m[3]}/${m[2]}/${m[1]}` : String(day || "");
}

function setBanner(toneClass, message) {
  const banner = document.getElementById("browser-verify-banner");
  const textEl = document.getElementById("browser-verify-text");
  if (!banner) return;
  banner.className = `notice ${toneClass}`;
  if (textEl) textEl.textContent = message;
  else banner.textContent = message;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function setupQuickMatch(registry) {
  const input = document.getElementById("quick-match-input");
  const clearBtn = document.getElementById("quick-match-clear");
  const box = document.getElementById("quick-match-result");
  if (!input || !box) return;

  function renderResult(toneClass, heading, detail, links = []) {
    box.className = `quick-match-result ${toneClass}`;
    box.replaceChildren();

    const head = document.createElement("div");
    head.className = "qm-head";
    head.textContent = heading;
    box.appendChild(head);

    const p = document.createElement("p");
    p.className = "qm-detail";
    p.textContent = detail;
    box.appendChild(p);

    if (links.length > 0) {
      const linkRow = document.createElement("div");
      linkRow.className = "qm-links";
      for (const item of links) {
        const a = document.createElement("a");
        a.className = "ext-link";
        a.href = item.href;
        if (item.external) {
          a.target = "_blank";
          a.rel = "noopener noreferrer";
        }
        a.textContent = item.label;
        linkRow.appendChild(a);
      }
      box.appendChild(linkRow);
    }

    box.hidden = false;
  }

  function evaluate() {
    const raw = input.value.trim();
    if (clearBtn) clearBtn.hidden = raw.length === 0;
    if (!raw) {
      box.hidden = true;
      return;
    }

    // Support pasted "keyId:hex64" or plain hex64 or keyId
    let candidateId = null;
    let candidateValue = raw;
    const colon = raw.indexOf(":");
    if (colon > 0) {
      candidateId = raw.slice(0, colon).trim();
      candidateValue = raw.slice(colon + 1).trim();
    }
    const lowerVal = candidateValue.toLowerCase();
    const lowerRaw = raw.toLowerCase();

    // 1. Match public keys
    const keyMatch = registry.keys.find((k) => {
      if (candidateId) {
        return k.keyId === candidateId && k.publicKeyHex.toLowerCase() === lowerVal;
      }
      return (
        k.publicKeyHex.toLowerCase() === lowerVal ||
        k.keyId.toLowerCase() === lowerRaw
      );
    });

    if (keyMatch) {
      const links = [{ href: `#key-${keyMatch.keyId}`, label: "Xem chi tiết khóa bên dưới" }];
      if (keyMatch.status === "active") {
        renderResult(
          "is-match",
          `Khớp khóa công khai đang hoạt động: ${keyMatch.keyId}`,
          `${keyMatch.label ?? "Khóa hệ thống Ed25519"} (${keyMatch.alg}). Khóa này hợp lệ để đối chiếu chữ ký hiện hành.`,
          links,
        );
      } else if (keyMatch.status === "retired") {
        renderResult(
          "is-retired",
          `Khớp khóa công khai đã nghỉ (hợp lệ lịch sử): ${keyMatch.keyId}`,
          keyMatch.note ?? "Khóa đã ngừng ký mới, nhưng các bản ghi lịch sử ký bằng khóa này vẫn hợp lệ.",
          links,
        );
      } else if (keyMatch.status === "compromised") {
        renderResult(
          "is-danger",
          `Cảnh báo: khớp khóa đã thu hồi ${keyMatch.keyId}`,
          keyMatch.safeUpToSeq !== null
            ? `Khóa này đã gắn cờ cảnh báo. Chỉ bản ghi tại hoặc trước #${keyMatch.safeUpToSeq} được neo trước sự cố.`
            : "Khóa này đã gắn cờ cảnh báo / thu hồi.",
          links,
        );
      } else {
        renderResult(
          "is-retired",
          `Khớp khóa công khai trong public-keys.json: ${keyMatch.keyId}`,
          "Khóa có mặt trong public-keys.json nhưng chưa khai báo trường trạng thái.",
          links,
        );
      }
      return;
    }

    // Check keyId match with mismatched hex!
    if (candidateId) {
      const sameId = registry.keys.find((k) => k.keyId === candidateId);
      if (sameId) {
        renderResult(
          "is-danger",
          `Cảnh báo không khớp khóa cho ${candidateId}`,
          `Mã khóa ${candidateId} có trong kho công khai nhưng chuỗi hex bạn dán KHÁC với khóa đã công bố. Không nên tin cậy chuỗi vừa dán.`,
          [{ href: `#key-${sameId.keyId}`, label: "Đối chiếu khóa công bố chính thức" }],
        );
        return;
      }
    }

    // 2. Match checkpoints (merkleRoot, headEventHash, bulletinHash)
    const cpMatches = registry.checkpoints.filter(
      (cp) =>
        (cp.merkleRoot && cp.merkleRoot.toLowerCase() === lowerVal) ||
        cp.headEventHash.toLowerCase() === lowerVal ||
        cp.bulletinHash.toLowerCase() === lowerVal,
    );

    if (cpMatches.length > 0) {
      const latest = cpMatches[0];
      const fieldMatched =
        latest.merkleRoot && latest.merkleRoot.toLowerCase() === lowerVal
          ? "gốc Merkle RFC 6962"
          : latest.headEventHash.toLowerCase() === lowerVal
            ? `mã băm đầu chuỗi #${latest.headSeq}`
            : "mã băm bản tin (bulletinHash)";
      const extra =
        cpMatches.length > 1
          ? ` (xuất hiện trong ${cpMatches.length} bản tin, mới nhất ngày ${formatDayVn(latest.day)})`
          : "";
      renderResult(
        "is-match",
        `Khớp ${fieldMatched} trong bản tin ngày ${formatDayVn(latest.day)} (đầu chuỗi #${latest.headSeq})`,
        `Ký bởi ${latest.keyId}${extra}.`,
        [
          { href: latest.githubBlobUrl, label: "Mở tệp JSON gốc trên GitHub", external: true },
        ],
      );
      return;
    }

    if (raw.length < 8) {
      box.hidden = true;
      return;
    }

    renderResult(
      "is-miss",
      "Không tìm thấy mã này trong kho công khai",
      "Chuỗi bạn nhập không khớp với bất kỳ khóa công khai, gốc Merkle, đầu chuỗi hay mã băm bản tin nào trong creatorshield-checkpoints. Kiểm tra lại từng ký tự hoặc đối chiếu trên trang xác minh.",
    );
  }

  input.addEventListener("input", evaluate);
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      input.value = "";
      evaluate();
      input.focus();
    });
  }
}

async function verifyAllCheckpointsInBrowser(registry) {
  const banner = document.getElementById("browser-verify-banner");
  if (!banner || !registry.checkpoints.length) return;

  if (!window.crypto || !window.crypto.subtle) {
    setBanner(
      "notice-warning",
      "Trình duyệt này chưa hỗ trợ Web Crypto API — trạng thái hiển thị lấy từ bước kiểm lúc dựng trang (GitHub Actions); dùng verifier-cli để tự kiểm độc lập.",
    );
    return;
  }

  const keyById = new Map(registry.keys.map((k) => [k.keyId, k]));
  const importedKeys = new Map();

  // Probe Web Crypto Ed25519 support with first key
  try {
    const probeKey = registry.keys[0];
    const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + 32);
    spki.set(ED25519_SPKI_PREFIX, 0);
    spki.set(hexToBytes(probeKey.publicKeyHex), ED25519_SPKI_PREFIX.length);
    const ck = await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
    importedKeys.set(probeKey.keyId, ck);
  } catch {
    setBanner(
      "notice-warning",
      "Trình duyệt này chưa hỗ trợ tự kiểm Ed25519 qua Web Crypto — trạng thái hiển thị lấy từ bước kiểm lúc dựng trang (GitHub Actions); dùng verifier-cli để tự kiểm độc lập.",
    );
    return;
  }

  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(CHECKPOINT_DOMAIN);
  let passed = 0;
  let failed = 0;

  for (const cp of registry.checkpoints) {
    const badges = document.querySelectorAll(`[data-cp-sig-badge="${CSS.escape(cp.bulletinHash)}"]`);
    const step3Texts = document.querySelectorAll(`[data-cp-step3-text="${CSS.escape(cp.bulletinHash)}"]`);
    let ok = false;
    let reason = "";

    try {
      const digestBuf = await crypto.subtle.digest("SHA-256", encoder.encode(cp.bulletin));
      const recomputedHash = bytesToHex(new Uint8Array(digestBuf));
      if (recomputedHash !== cp.bulletinHash.toLowerCase()) {
        reason = "SHA-256 bản tin không khớp";
      } else {
        const keyRecord = keyById.get(cp.keyId);
        if (!keyRecord) {
          reason = `Thiếu khóa ${cp.keyId}`;
        } else {
          let cryptoKey = importedKeys.get(cp.keyId);
          if (!cryptoKey) {
            const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + 32);
            spki.set(ED25519_SPKI_PREFIX, 0);
            spki.set(hexToBytes(keyRecord.publicKeyHex), ED25519_SPKI_PREFIX.length);
            cryptoKey = await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
            importedKeys.set(cp.keyId, cryptoKey);
          }

          const hashBytes = hexToBytes(recomputedHash);
          const message = new Uint8Array(domainBytes.length + 1 + hashBytes.length);
          message.set(domainBytes, 0);
          message[domainBytes.length] = 0x00;
          message.set(hashBytes, domainBytes.length + 1);

          const sigBytes = base64ToBytes(cp.signature);
          ok = sigBytes.length === 64 && (await crypto.subtle.verify("Ed25519", cryptoKey, sigBytes, message));
          if (!ok) reason = "Chữ ký Ed25519 không khớp";
        }
      }
    } catch {
      reason = "Lỗi xác minh tại trình duyệt";
    }

    if (ok) {
      passed += 1;
      for (const badge of badges) {
        badge.className = "pill status-active";
        const span = badge.querySelector("span");
        if (span) span.textContent = "Trình duyệt vừa tự kiểm · Ed25519";
      }
      for (const s3 of step3Texts) {
        s3.textContent = `Trình duyệt vừa xác minh hợp lệ với khóa ${cp.keyId}`;
      }
    } else {
      failed += 1;
      for (const badge of badges) {
        badge.className = "pill status-danger";
        const span = badge.querySelector("span");
        if (span) span.textContent = `Không hợp lệ: ${reason}`;
      }
      for (const s3 of step3Texts) {
        s3.textContent = `Không hợp lệ: ${reason}`;
      }
    }
  }

  if (failed === 0) {
    setBanner(
      "notice-success",
      `Trình duyệt vừa tự kiểm lại chữ ký Ed25519 (nhãn miền ${CHECKPOINT_DOMAIN}): ${passed}/${registry.checkpoints.length} bản tin hợp lệ.`,
    );
  } else {
    setBanner(
      "notice-danger",
      `Cảnh báo: ${failed}/${registry.checkpoints.length} bản tin không vượt qua bước tự kiểm Ed25519 tại trình duyệt. Kiểm tra chi tiết từng dòng bên dưới.`,
    );
  }
}

async function init() {
  setupCopyButtons();
  setupCheckpointFilters();

  try {
    const resp = await fetch("./data/registry.json", { cache: "no-cache" });
    if (!resp.ok) return;
    const registry = await resp.json();
    setupQuickMatch(registry);
    await verifyAllCheckpointsInBrowser(registry);
  } catch {
    /* Graceful degradation when opened offline via file:// */
  }
}

init();
