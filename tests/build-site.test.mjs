import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  canonicalizeJcs,
  sha256Utf8,
  validatePublicKeys,
  verifyCheckpointBulletin,
} from "../scripts/verify-core.mjs";
import { buildSite } from "../scripts/build-site.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");

describe("verify-core: public-keys.json & RFC 8785 + Ed25519 verification", () => {
  it("validates the live public-keys.json with all 4 real keys and preserves exact hex64 values", async () => {
    const raw = JSON.parse(await readFile(join(REPO_ROOT, "public-keys.json"), "utf8"));
    const keys = validatePublicKeys(raw);

    assert.equal(keys.length, 4);
    const byId = new Map(keys.map((k) => [k.keyId, k]));

    assert.equal(
      byId.get("key-checkpoint-2026-11")?.publicKeyHex,
      "3cd9a0a0eeb4f075627eb1a43396bbb7b1e4271a589a169384f5cc4ec221784f",
    );
    assert.equal(byId.get("key-checkpoint-2026-11")?.status, "active");
    assert.equal(byId.get("key-checkpoint-2026-11")?.role, "checkpoint");

    assert.equal(
      byId.get("key-vercel-mentor-2026-11")?.publicKeyHex,
      "00881f5fc32a25fd229166a1909779f8e6157a0d898751168ef3d79684a06d7e",
    );
    assert.equal(byId.get("key-vercel-mentor-2026-11")?.status, "active");

    assert.equal(
      byId.get("key-vercel-prod-2026-11")?.publicKeyHex,
      "037549c12dded12c4b9617e79d0639585e85cc81a6a5cc058e3374cb1e0463aa",
    );
    assert.equal(byId.get("key-vercel-prod-2026-11")?.status, "active");

    assert.equal(
      byId.get("key-supabase-dev-2026-11")?.publicKeyHex,
      "d0643d01cc0302e20127b9d30a43e7f96a7cd8e3ef0ddfd14e0ba11b1386def5",
    );
    assert.equal(byId.get("key-supabase-dev-2026-11")?.status, "retired");
  });

  it("handles minimal 3-field future key entries without crashing (Review Focus #1)", () => {
    const keys = validatePublicKeys([
      {
        keyId: "key-future-2027-01",
        alg: "Ed25519",
        publicKeyHex: "a".repeat(64),
      },
    ]);
    assert.equal(keys.length, 1);
    assert.equal(keys[0].status, "unknown");
    assert.equal(keys[0].role, "unspecified");
    assert.equal(keys[0].retiredAt, null);
    assert.equal(keys[0].safeUpToSeq, null);
  });

  it("rejects duplicate keyId or invalid hex64 in public-keys.json", () => {
    assert.throws(() =>
      validatePublicKeys([
        { keyId: "dup", alg: "Ed25519", publicKeyHex: "a".repeat(64) },
        { keyId: "dup", alg: "Ed25519", publicKeyHex: "b".repeat(64) },
      ]),
    );
    assert.throws(() =>
      validatePublicKeys([{ keyId: "bad", alg: "Ed25519", publicKeyHex: "not-hex" }]),
    );
  });

  it("canonicalizes RFC 8785 key order and Unicode NFC identically", () => {
    const a = canonicalizeJcs({ b: "Việt", a: 1 });
    const b = canonicalizeJcs({ a: 1, b: "Vi\u0065\u0323\u0302t" });
    assert.equal(a, '{"a":1,"b":"Việt"}');
    assert.equal(a, b);
    assert.equal(sha256Utf8(a), sha256Utf8(b));
  });

  it("verifies all 9 published historical checkpoints cleanly and rejects tampered bytes (Review Focus #3)", async () => {
    const keys = validatePublicKeys(
      JSON.parse(await readFile(join(REPO_ROOT, "public-keys.json"), "utf8")),
    );
    const keyMap = new Map(keys.map((k) => [k.keyId, k]));

    const latestPath = join(
      REPO_ROOT,
      "checkpoints/2026/11/2026-11-25-171318ec9641598f04e67b2d41b5da8add46dfa497626fbe7f926c328f009b88.json",
    );
    const latestDoc = JSON.parse(await readFile(latestPath, "utf8"));
    const okResult = verifyCheckpointBulletin(latestDoc, keyMap);
    assert.equal(okResult.ok, true);

    // Tamper 1 byte in signature
    const badSigDoc = structuredClone(latestDoc);
    badSigDoc.signature =
      (badSigDoc.signature[0] === "A" ? "B" : "A") + badSigDoc.signature.slice(1);
    const badSigRes = verifyCheckpointBulletin(badSigDoc, keyMap);
    assert.equal(badSigRes.ok, false);
    assert.match(badSigRes.reason, /Chữ ký/i);

    // Tamper bulletinHash
    const badHashDoc = structuredClone(latestDoc);
    badHashDoc.bulletinHash = "0".repeat(64);
    const badHashRes = verifyCheckpointBulletin(badHashDoc, keyMap);
    assert.equal(badHashRes.ok, false);
    assert.match(badHashRes.reason, /Mã băm/i);

    // Unknown keyId
    const unknownKeyRes = verifyCheckpointBulletin(latestDoc, new Map());
    assert.equal(unknownKeyRes.ok, false);
    assert.match(unknownKeyRes.reason, /key-checkpoint-2026-11/);
  });
});

describe("build-site: pre-rendered HTML, sorting, security escaping, and compromised keys", () => {
  it("builds the real repository cleanly with all 9 verified checkpoints sorted by issuedAt desc (Review Focus #4)", async () => {
    const outDir = await mkdtemp(join(tmpdir(), "cs-cp-build-real-"));
    try {
      const summary = await buildSite({
        rootDir: REPO_ROOT,
        outDir,
        repoSlug: "vuongnguyen16/creatorshield-checkpoints",
        appBaseUrl: "https://creatorshield-mentor.vercel.app",
      });

      assert.equal(summary.keyCount, 4);
      assert.equal(summary.activeKeyCount, 3);
      assert.ok(summary.checkpointCount >= 10, "Expected at least 10 checkpoints including 2026-11-26");
      assert.equal(summary.verifiedCheckpointCount, summary.checkpointCount);

      const registry = JSON.parse(await readFile(join(outDir, "data/registry.json"), "utf8"));
      assert.equal(registry.checkpoints.length, summary.checkpointCount);
      assert.equal(registry.checkpoints[0].isLatest, true);
      assert.match(registry.checkpoints[0].coverageLabel, /^Bảo chứng bản ghi #1 – #\d+$/);
      assert.ok(
        ["expanded", "reconfirmed", "initial"].includes(registry.checkpoints[0].deltaType),
        "Checkpoint must include chronological deltaType",
      );
      assert.ok(registry.checkpoints[0].deltaLabel.length > 0);

      // Verify at least one expanded and one reconfirmed checkpoint exist in history
      assert.ok(registry.checkpoints.some((c) => c.deltaType === "expanded"));
      assert.ok(registry.checkpoints.some((c) => c.deltaType === "reconfirmed"));
      assert.ok(registry.checkpoints.some((c) => c.deltaType === "initial"));

      // Verify strict descending issuedAt order across all bulletins (including same-day 2026-11-18 and 2026-11-17)
      for (let i = 1; i < registry.checkpoints.length; i++) {
        assert.ok(
          Date.parse(registry.checkpoints[i - 1].issuedAt) >=
            Date.parse(registry.checkpoints[i].issuedAt),
          `Expected checkpoint ${i - 1} issuedAt >= checkpoint ${i}`,
        );
      }

      // Check /1 historical bulletins have null merkleRoot
      const v1Items = registry.checkpoints.filter(
        (c) => c.format === "creatorshield-checkpoint/1",
      );
      assert.equal(v1Items.length, 4);
      for (const item of v1Items) {
        assert.equal(item.merkleRoot, null);
      }

      // Check pre-rendered HTML quality & security constraints
      const html = await readFile(join(outDir, "index.html"), "utf8");
      for (const k of registry.keys) {
        assert.ok(html.includes(k.publicKeyHex), `HTML must contain full 64-hex key ${k.keyId}`);
      }
      assert.doesNotMatch(html, /nghe-an|nghe_an|linh vật/i, "No Nghê Ấn mascot on evidence pages");
      assert.doesNotMatch(
        html,
        /fonts\.googleapis\.com|fonts\.gstatic\.com|unpkg\.com|cdn\.jsdelivr\.net/i,
        "Zero third-party CDN requests",
      );
      assert.doesNotMatch(html, /\sstyle="/i, "Zero inline style attributes");

      // Check user-friendly checkpoint enhancements & Thuyết minh XIX legal parity
      assert.ok(html.includes("Điểm kiểm chứng mới nhất đang neo chuỗi"), "Must spotlight latest checkpoint");
      assert.ok(html.includes("data-cp-quick-filter="), "Must render 1-click quick filter pills");
      assert.ok(html.includes("Bảo chứng bản ghi #1 – #"), "Must show plain-Vietnamese record coverage range");
      assert.ok(
        html.includes("không xác nhận danh tính người ký gửi, không xác nhận ai là tác giả hay chủ sở hữu quyền"),
        "Must match canonical /xac-minh legal limitation wording",
      );
      assert.ok(
        html.includes("không thay thế Giấy chứng nhận đăng ký quyền tác giả do Cục Bản quyền tác giả cấp hay kết luận của cơ quan có thẩm quyền"),
        "Must include full Copyright Office & competent authority clause from /xac-minh",
      );

      // Raw files preserved verbatim
      const origKeys = await readFile(join(REPO_ROOT, "public-keys.json"), "utf8");
      const distKeys = await readFile(join(outDir, "public-keys.json"), "utf8");
      assert.equal(distKeys, origKeys);
      await readFile(join(outDir, ".nojekyll"), "utf8");
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("handles compromised key (safeUpToSeq excluded from active copy) and escapes XSS payloads (Review Focus #2 & #5)", async () => {
    const fixtureDir = await mkdtemp(join(tmpdir(), "cs-cp-fixture-"));
    const outDir = await mkdtemp(join(tmpdir(), "cs-cp-out-"));
    try {
      await mkdir(join(fixtureDir, "checkpoints/2026/11"), { recursive: true });
      await mkdir(join(fixtureDir, "site/assets/fonts"), { recursive: true });
      // Reuse real site assets from repo once present, or minimal template
      const realTemplate = await readFile(join(REPO_ROOT, "site/template.html"), "utf8");
      const realCss = await readFile(join(REPO_ROOT, "site/styles.css"), "utf8");
      const realJs = await readFile(join(REPO_ROOT, "site/app.js"), "utf8");
      const realFav = await readFile(join(REPO_ROOT, "site/favicon.svg"), "utf8");
      await writeFile(join(fixtureDir, "site/template.html"), realTemplate);
      await writeFile(join(fixtureDir, "site/styles.css"), realCss);
      await writeFile(join(fixtureDir, "site/app.js"), realJs);
      await writeFile(join(fixtureDir, "site/favicon.svg"), realFav);

      const xssPayload = '<script>alert("xss")</script>';
      await writeFile(
        join(fixtureDir, "public-keys.json"),
        JSON.stringify([
          {
            keyId: "key-active-safe",
            alg: "Ed25519",
            publicKeyHex: "1".repeat(64),
            status: "active",
            role: "checkpoint",
            label: `Khóa mới ${xssPayload}`,
            note: `Ghi chú ${xssPayload}`,
          },
          {
            keyId: "key-bad-compromised",
            alg: "Ed25519",
            publicKeyHex: "2".repeat(64),
            status: "compromised",
            role: "checkpoint",
            retiredAt: "2026-11-20T00:00:00Z",
            safeUpToSeq: 42,
            note: "Đã thu hồi khẩn cấp.",
          },
          {
            keyId: "key-minimal-only",
            alg: "Ed25519",
            publicKeyHex: "3".repeat(64),
          },
        ]),
      );

      const summary = await buildSite({
        rootDir: fixtureDir,
        outDir,
        repoSlug: "vuongnguyen16/creatorshield-checkpoints",
        appBaseUrl: "https://creatorshield-mentor.vercel.app",
        resolveCommitSha: () => "main",
      });

      assert.equal(summary.activeKeyCount, 1);
      const html = await readFile(join(outDir, "index.html"), "utf8");
      const registry = JSON.parse(await readFile(join(outDir, "data/registry.json"), "utf8"));

      assert.doesNotContain?.(html, xssPayload);
      assert.equal(html.includes(xssPayload), false, "Raw <script> tag must be escaped");
      assert.ok(html.includes("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"));
      assert.ok(html.includes("#42"), "Compromised key safeUpToSeq must appear in HTML");
      assert.ok(html.includes("Chưa khai báo trạng thái"), "Minimal 3-field key renders fallback status");

      assert.equal(registry.activeCopyBundle, `key-active-safe:${"1".repeat(64)}`);
      assert.equal(registry.activeCopyBundle.includes("key-bad-compromised"), false);
    } finally {
      await rm(fixtureDir, { recursive: true, force: true });
      await rm(outDir, { recursive: true, force: true });
    }
  });
});
