# Kho khóa công khai & điểm kiểm chứng CreatorShield

> **Trang web hiển thị thân thiện (GitHub Pages):**  
> **[Mở Kho khóa công khai & Điểm kiểm chứng CreatorShield](https://vuongnguyen16.github.io/creatorshield-checkpoints/)**  
> *(Xem trực quan trạng thái từng khóa, sao chép 1 chạm `keyId:hex64` hoặc lệnh CLI, đối chiếu nhanh mã băm và tự kiểm chữ ký Ed25519 ngay trên trình duyệt.)*

Đây là **kho công bố độc lập** chứa danh sách khóa công khai (`public-keys.json`) và các bản tin điểm kiểm chứng đầu chuỗi đã ký (`checkpoints/YYYY/MM/*.json`) của nền tảng xác lập chứng cứ số **CreatorShield** (Đội Nghê Ấn, ACL 2026). Kho **không chứa** nội dung tệp gốc, tên tác phẩm, tên tệp, email hay danh tính người ký gửi, và tuyệt đối không chứa khóa riêng.

---

## Khóa công khai đã công bố (`public-keys.json`)

| Mã khóa (`keyId`) | Vai trò | Trạng thái | Khóa công khai Ed25519 (`publicKeyHex`) |
|---|---|---|---|
| `key-checkpoint-2026-11` | Ký điểm kiểm chứng hằng ngày | **Đang hoạt động** *(từ 18/11/2026)* | `3cd9a0a0eeb4f075627eb1a43396bbb7b1e4271a589a169384f5cc4ec221784f` |
| `key-vercel-mentor-2026-11` | Ký sự kiện ký gửi (`creatorshield-mentor.vercel.app`) | **Đang hoạt động** *(từ 19/11/2026)* | `00881f5fc32a25fd229166a1909779f8e6157a0d898751168ef3d79684a06d7e` |
| `key-vercel-prod-2026-11` | Ký sự kiện ký gửi (`creatorshield-pi.vercel.app`) | **Đang hoạt động** *(từ 18/11/2026)* | `037549c12dded12c4b9617e79d0639585e85cc81a6a5cc058e3374cb1e0463aa` |
| `key-supabase-dev-2026-11` | Khóa thử nghiệm giai đoạn đầu | **Đã nghỉ** *(vẫn hợp lệ cho 5 bản tin lịch sử 17–18/11)* | `d0643d01cc0302e20127b9d30a43e7f96a7cd8e3ef0ddfd14e0ba11b1386def5` |

### Sao chép nhanh để ghim khóa tin cậy

**Dán vào ô *"Ghim khóa công khai tin cậy"* tại [creatorshield-mentor.vercel.app/xac-minh/goi-chung-cu](https://creatorshield-mentor.vercel.app/xac-minh/goi-chung-cu):**

```text
key-checkpoint-2026-11:3cd9a0a0eeb4f075627eb1a43396bbb7b1e4271a589a169384f5cc4ec221784f
key-vercel-mentor-2026-11:00881f5fc32a25fd229166a1909779f8e6157a0d898751168ef3d79684a06d7e
key-vercel-prod-2026-11:037549c12dded12c4b9617e79d0639585e85cc81a6a5cc058e3374cb1e0463aa
```

**Hoặc kiểm chứng ngoại tuyến bằng CLI (Node.js 22+):**

```bash
node creatorshield-verify.mjs evidence.json --file <tep-goc> \
  --trusted-key key-checkpoint-2026-11:3cd9a0a0eeb4f075627eb1a43396bbb7b1e4271a589a169384f5cc4ec221784f \
  --trusted-key key-vercel-mentor-2026-11:00881f5fc32a25fd229166a1909779f8e6157a0d898751168ef3d79684a06d7e \
  --trusted-key key-vercel-prod-2026-11:037549c12dded12c4b9617e79d0639585e85cc81a6a5cc058e3374cb1e0463aa
```

---

## Lịch sử xoay khóa và tính toàn vẹn bản tin

- **Xoay khóa ngày 18/11/2026:** 5 bản tin điểm kiểm chứng đầu tiên (4 bản tin ngày 17/11 định dạng `creatorshield-checkpoint/1` cho đầu chuỗi `#5..#7`, và bản tin theo yêu cầu ngày 18/11 cho đầu chuỗi `#7`) được ký bằng `key-supabase-dev-2026-11`. Khóa này đã ngừng ký bản tin mới từ 18/11/2026; mọi chữ ký lịch sử lập trước thời điểm đó vẫn giữ nguyên và xác minh hợp lệ. Từ bản tin hằng ngày 18/11 (đầu chuỗi `#9`) trở đi, bản tin được ký bằng khóa chuyên dụng `key-checkpoint-2026-11` theo định dạng `creatorshield-checkpoint/2` kèm gốc Merkle RFC 6962.
- **Tách khóa ký sự kiện và khóa ký điểm kiểm chứng:** ứng dụng web ký sự kiện bằng `key-vercel-mentor-2026-11` (và `key-vercel-prod-2026-11` cho bản `creatorshield-pi.vercel.app`), tách biệt với khóa ký điểm kiểm chứng `key-checkpoint-2026-11`.
- **Không ghi đè lịch sử:** mọi tệp trong `checkpoints/YYYY/MM/*.json` đều chứa văn bản chuẩn hóa RFC 8785 (`bulletin`), SHA-256 (`bulletinHash`), chữ ký Ed25519 (`signature`) với nhãn miền `creatorshield/checkpoint/v1`, và không bao giờ bị sửa hay thay thế.

---

## Phạm vi tin cậy và giới hạn pháp lý *(đồng bộ nguyên văn Thuyết minh chương XIX & `/xac-minh`)*

- **Ý nghĩa kỹ thuật của điểm kiểm chứng:** Mỗi bản tin hợp lệ cho biết mã băm đầu chuỗi và gốc Merkle RFC 6962 đã được ghi nhận, ký bằng khóa hệ thống Ed25519 tại thời điểm nêu trên và chuỗi bản ghi từ `#1` đến đầu chuỗi đó chưa bị sửa đổi kể từ khi công bố.
- **Bảo vệ quyền riêng tư (không lưu tệp gốc hay danh tính):** Kho công khai này chỉ lưu khóa công khai Ed25519 và các bản tin đầu chuỗi/gốc Merkle; hoàn toàn không chứa nội dung tệp gốc, tên tác phẩm, tên tệp, email hay thông tin định danh người ký gửi.
- **Giới hạn về nguồn thời gian và quản trị kho Git:** Thời điểm phát hành (`issuedAt`) sử dụng đồng hồ máy chủ kết hợp điểm kiểm chứng công khai; thời gian tác giả/người commit trong Git là giá trị tự khai, **không phải** dấu thời gian độc lập RFC 3161 từ tổ chức cung cấp dịch vụ tin cậy được cấp phép (TSA — thuộc lộ trình năm 2027). Lần tải ẩn danh qua HTTPS chỉ chứng minh dữ liệu đã công khai chậm nhất tại thời điểm tải. Quản trị viên kho GitHub có khả năng kỹ thuật viết lại lịch sử nhánh từ xa; bên kiểm chứng nên tự lưu giữ bản sao độc lập của `public-keys.json`, các tệp bản tin JSON và gói `evidence.json`.
- **Dữ liệu nghiệm thu M5 ngày 17/11/2026:** Các bản tin đầu chuỗi `#6` và `#7` ngày 17/11/2026 thuộc bộ dữ liệu kiểm thử nghiệm thu M5 có nhãn synthetic trong ứng dụng (tiêu chí nghiệm thu M5 điều chỉnh ngày 17/11/2026 cho phép 3 checkpoint thật trong cùng ngày, không chứng minh hệ thống đã vận hành 3 ngày tính đến thời điểm đó).
- **Giới hạn của kết quả xác minh (Thuyết minh chương XIX):** Kết quả không xác nhận danh tính người ký gửi, không xác nhận ai là tác giả hay chủ sở hữu quyền, và không thay thế Giấy chứng nhận đăng ký quyền tác giả do Cục Bản quyền tác giả cấp hay kết luận của cơ quan có thẩm quyền. Hai người ký gửi cùng một tệp sẽ có cùng mã băm; trang xác minh công khai chỉ hiển thị bản ghi sớm nhất. Thông tin mang tính tham khảo, không phải tư vấn pháp lý.

---

## English Technical Provenance Summary

Public signed chain-head bulletins and Ed25519 trust-root keys for **CreatorShield**. Browse the interactive portal at **[https://vuongnguyen16.github.io/creatorshield-checkpoints/](https://vuongnguyen16.github.io/creatorshield-checkpoints/)** or inspect raw files directly:

- `public-keys.json` — machine-readable JSON array of all published Ed25519 public keys (`keyId`, `alg`, `publicKeyHex`, plus optional status/role/lifecycle metadata).
- `checkpoints/YYYY/MM/*.json` — immutable signed checkpoint bulletins (`creatorshield-checkpoint/1` and `creatorshield-checkpoint/2` with RFC 6962 Merkle roots), signed under domain label `creatorshield/checkpoint/v1`.
- No work titles, file names, file contents, owner identities, or private keys are published here. Git author/committer timestamps are self-reported and are not an independent RFC 3161 timestamp authority.
- Build and verify locally with Node.js 22+ (zero npm dependencies):
  ```bash
  node --test tests/build-site.test.mjs
  node scripts/build-site.mjs
  ```
