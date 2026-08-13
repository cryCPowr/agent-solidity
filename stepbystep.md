# Step by Step — `setup_agent.py`

Dokumen ini merangkum urutan eksekusi & logic yang dijalanin `setup_agent.py` dari awal sampai akhir (`main()`). Silakan dikoreksi.

Urutan pemanggilan di `main()`:
```
setup_hardhat() → setup_foundry() → generate_test_files()
```

---

## Bagian A — Hardhat (`setup_hardhat`)

1. **Cek status Hardhat**
   - Jalankan `npx hardhat --version`.
   - Cek juga apakah file config (`hardhat.config.ts` / `.js` / `.cjs` / `.mjs`) sudah ada.
   - **Tool ada + config ada** → dianggap sudah siap, langsung lompat ke Bagian B (Foundry).
   - **Tool ada tapi config belum ada** → lanjut init.
   - **Tool belum ada sama sekali** → lanjut init (init sekaligus install).
2. **Init project** (non-interaktif):
   ```
   npx hardhat --init --template minimal
   ```
   Pakai flag `--template` resmi Hardhat 3, jadi tidak ada prompt yang perlu dijawab manual (beda dari versi awal yang sempat error karena stdin dikira jawaban prompt).
3. **Install Hardhat sebagai dev dependency**:
   ```
   npm install --save-dev hardhat
   ```
4. **Install OpenZeppelin contracts**:
   ```
   npm install @openzeppelin/contracts
   ```

---

## Bagian B — Foundry (`setup_foundry`)

1. **Cek status Foundry**
   - Jalankan `forge --version`.
   - Cek juga apakah `foundry.toml` sudah punya `src = "contracts"` (bukan default `src = "src"`).
   - **Tool ada + sudah dikonfigurasi** → dianggap sudah siap, lompat ke Bagian C.
   - **Tool ada tapi belum dikonfigurasi untuk project ini** → langsung `forge init --force .` + tulis ulang `foundry.toml` (skip instalasi Foundry, karena toolnya memang sudah ada di sistem).
   - **Tool belum ada sama sekali** → install dari awal (step 2–6 di bawah).
2. **Install Foundry**:
   ```
   curl -L https://getfoundry.sh/install | bash
   ```
3. **Source shell config** — coba `source ~/.zshrc`, kalau tidak ada coba `~/.bashrc`.
   > ⚠️ Kemungkinan besar tidak efektif, karena `source` dari dalam subprocess Python tidak mengubah environment shell asli kamu.
4. **Jalankan `foundryup`**
5. **Init project Foundry**: `forge init --force .`
6. **Tulis ulang `foundry.toml`** (fungsi `write_foundry_toml`):
   ```toml
   [profile.default]
   src = "contracts"
   out = "out"
   test = "test"
   script = "script"
   libs = ["node_modules", "lib"]
   ```

---

## Bagian C — Generate Test (`generate_test_files`)

### C.1 — Cek isi folder `contracts/`
- Folder di-**auto-create** kalau belum ada (`mkdir(exist_ok=True)`).
- Yang jadi syarat berhenti adalah **isinya**, bukan keberadaan foldernya.
- Kalau tidak ada file `.sol` sama sekali → `[STOP]`, minta user isi folder dulu, `sys.exit(1)`.

### C.2 — Cek import (`check_imports`) — dijalankan LEBIH DULU sebelum cek versi
Untuk setiap `import` di tiap file `.sol`:
- **Import relative** (`./...`, `../...`) → dianggap file custom milik user sendiri (interface/lib).
  - Ada di disk → dicatat sebagai `[OK] File lokal sudah tersedia`.
  - Tidak ada → dicatat sebagai `missing_local`.
- **Import package** (`@openzeppelin/...`, dsb, diambil nama package-nya lewat `npm_package_name`) →
  - Cek dulu di `node_modules/<package>`. Kalau sudah ada → `[OK] Package sudah tersedia`.
  - Kalau belum ada → coba `npm install <package>`.
    - Berhasil → masuk `ok_packages`.
    - Gagal → masuk `failed_packages` (kemungkinan bukan package publik di npm, misal private/proprietary).

**Setelah semua file discan:**
1. Print daftar `[OK] Package sudah tersedia`.
2. Print daftar `[OK] File lokal sudah tersedia`.
3. Kalau ada `missing_local` → `[STOP]`, list file yang hilang + pesan bahwa itu bukan package open-source jadi tidak bisa di-download otomatis → `sys.exit(1)`.
4. Kalau ada `failed_packages` → `[STOP]`, list package yang gagal + minta install manual → `sys.exit(1)`.
5. Kalau semua lolos → `"Semua import (local file & package) sudah lengkap."`, lanjut ke C.3.

> Alasan urutan ini didahulukan (sebelum cek versi Solidity): kalau import lokal masih ada yang hilang, `hardhat compile` / `forge build` bakal gagal duluan dengan dump error compiler mentah yang bikin bingung. Dengan urutan ini, agent berhenti rapi duluan sebelum sempat coba compile.

### C.3 — Sinkronisasi versi Solidity (`sync_solidity_version`)
1. Ambil `pragma solidity` dari tiap file `.sol` (`extract_pragma_versions`), disederhanakan ke angka bersih (misal `^0.8.28` → `0.8.28`).
2. Kalau tidak ketemu pragma sama sekali → skip (`[INFO]`).
3. Kalau versi beda-beda antar file → `[WARNING]`, pakai versi **tertinggi** sebagai target.
4. **Auto-update config:**
   - `_update_hardhat_solc_version` — cari pola `solidity: "x.y.z"` di `hardhat.config.*` pakai regex, replace ke versi target.
     - Ketemu & berhasil → `[UPDATED]`.
     - Tidak ketemu polanya (misal config multi-compiler) → `[WARNING]`, minta user sesuaikan manual — **tidak diam-diam skip**.
   - `_update_foundry_solc_version` — update/tambahkan baris `solc = "x.y.z"` di `[profile.default]` pada `foundry.toml` → `[UPDATED]`.
5. **Auto-install compiler**: jalankan `npx hardhat compile` dan `forge build` — keduanya otomatis fetch binary solc versi yang dibutuhkan kalau belum ada di cache lokal.

### C.4 — Generate file test (Step 17)
Untuk setiap `<nama>.sol` di `contracts/`:
- `test/<nama>.ts` → template test Hardhat (chai + ethers): deploy kontrak, cek alamat valid.
- `test/<nama>.t.sol` → template test Foundry: `new <Nama>()` di `setUp()`, assert alamat bukan 0.
- Kalau file test dengan nama yang sama sudah ada → **di-skip**, tidak ditimpa (`[SKIP]`).

---

## Ringkasan urutan penuh (kalau semua dari nol)

```
1.  Cek Hardhat (tool + config)
2.  npx hardhat --init --template minimal
3.  npm install --save-dev hardhat
4.  npm install @openzeppelin/contracts
5.  Cek Foundry (tool + config)
6.  curl -L https://getfoundry.sh/install | bash
7.  source ~/.zshrc atau ~/.bashrc
8.  foundryup
9.  forge init --force .
10. Tulis foundry.toml
11. mkdir contracts (kalau belum ada)
12. Cek isi contracts/*.sol -> stop kalau kosong
13. Cek semua import (local file & package) -> stop kalau ada yang hilang/gagal install
14. Sinkronkan versi Solidity ke hardhat.config & foundry.toml
15. hardhat compile & forge build (auto-download solc)
16. Generate test/*.ts dan test/*.t.sol per contract
```

## Hal-hal yang mungkin perlu dikoreksi / didiskusikan

- [ ] Apakah `check_imports` perlu dibedain juga: package yang **beda nama di npm vs di import path** (misal `forge-std/Test.sol` bukan package npm, tapi library Foundry yang di-install lewat `forge install`, bukan `npm install`)?
- [ ] Apakah versi Solidity yang dipakai kalau beda-beda antar file harus selalu "yang tertinggi", atau ada skenario lain (misal harus sama persis semua)?
- [ ] Apakah perlu opsi override supaya user bisa pilih overwrite test yang sudah ada, bukan selalu skip?
- [ ] Apakah step "source shell config" sebaiknya dihapus saja (karena tidak efektif dari subprocess Python) dan diganti instruksi manual ke user?
