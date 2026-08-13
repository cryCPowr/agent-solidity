# Cara Pakai Recon System (Simple Version)

## 1. Ekstrak file

```bash
tar xzf recon-system.tar.gz
cd recon-system
```

## 2. Install compiler Solidity-nya (sekali aja)

```bash
npm install
```

Ini bakal download `solc` (compiler Solidity) lewat npm. Butuh Node.js udah terinstall di komputer lo.

## 3. Jalanin analisis ke repo Solidity lo

```bash
python3 -m recon.cli /path/ke/repo/lo -o hasil/
```

Ganti `/path/ke/repo/lo` dengan folder project Solidity yang mau di-scan. Ganti `hasil/` kalau mau nama folder output beda.

**Contoh gampang** — coba dulu pake contoh yang udah disediain:

```bash
python3 -m recon.cli tests/fixtures -o hasil/
```

## 4. Lihat hasilnya

Semua hasil ada di folder `hasil/`:

| File | Isinya |
|---|---|
| `facts.jsonl` | Data utama — semua "fakta" tentang kode lo (function apa aja, baca/nulis state dimana, manggil kontrak lain dimana, dll) |
| `graph.json` | Peta hubungan antar contract/function (siapa manggil siapa) |
| `summary.json` | Ringkasan angka — jumlah contract, function, dll |
| `metadata.json` | Info run-nya — file mana yang berhasil/gagal di-analisis |
| `snippets/` | Potongan source code buat bukti tiap fakta |

Buka `facts.jsonl` pake text editor, atau kalau mau lebih enak dibaca:

```bash
python3 -c "import json; [print(json.dumps(json.loads(l), indent=2)) for l in open('hasil/facts.jsonl')]" | less
```

## 5. (Opsional) Cek semua fungsinya jalan normal

```bash
python3 -m pytest tests/ -v
```

Kalau semua ijo (`passed`), berarti sistemnya jalan normal di komputer lo.

## Troubleshooting cepat

- **`node: command not found`** → install Node.js dulu (https://nodejs.org)
- **`python3: command not found`** → pastiin Python 3.10+ udah ada
- **Ada file `.sol` yang gagal di-analisis** → cek `hasil/metadata.json`, bagian `files_failed` dan `warnings`, biasanya karena versi pragma Solidity yang aneh/gak ketemu di npm

---

Itu aja, 3 langkah inti: **extract → `npm install` → `python3 -m recon.cli`**. Sisanya tinggal baca `facts.jsonl` / `graph.json` di folder output.
