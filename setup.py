#!/usr/bin/env python3
"""
Environment setup/preparation script for the Solidity security-audit agent pipeline.

This script only prepares Hardhat/Foundry, dependencies, Solidity versions,
remappings, and compilation. It does NOT search for vulnerabilities or
generate exploit/security tests.

Usage:
    python3 setup.py

Run from the root of the Solidity repository.
"""

import subprocess
import sys
import os
import re
from pathlib import Path

CONTRACTS_DIR = Path("contracts")
TEST_DIR = Path("test")

# Hardhat 3 punya mode non-interaktif resmi lewat --template, jadi kita
# tidak perlu lagi menebak-nebak jawaban prompt (path project, pilihan
# menu arrow-key, dll — itu yang bikin kemarin ke-generate folder "y").
# Pilihan template lain: "minimal" (JS polos) atau sesuaikan kalau mau TS.
HARDHAT_INIT_TEMPLATE = "minimal"



def run(cmd, check=True, input_text=None):
    """Jalankan command shell, tampilkan output langsung ke terminal."""
    print(f"\n>>> Menjalankan: {cmd}")
    result = subprocess.run(cmd, shell=True, text=True, input=input_text)
    if check and result.returncode != 0:
        print(f"[ERROR] Command gagal (exit code {result.returncode}): {cmd}")
    return result


def check_command_has_version(cmd):
    """True kalau command berhasil dijalankan DAN outputnya mengandung angka (versi)."""
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0 and any(ch.isdigit() for ch in output):
        print(f"[OK] {cmd} -> {output.strip()}")
        return True
    print(f"[INFO] '{cmd}' tidak menghasilkan versi / error.")
    return False


# ---------- STEP 1-9: HARDHAT ----------
def hardhat_project_already_initialized():
    """True kalau folder ini sudah punya config Hardhat (bukan cuma tool-nya ada di sistem)."""
    config_files = [
        "hardhat.config.ts", "hardhat.config.js",
        "hardhat.config.cjs", "hardhat.config.mjs",
    ]
    return any(Path(f).exists() for f in config_files)


def setup_hardhat():
    print("\n=== STEP 1: Cek apakah Hardhat sudah terinstall & project sudah di-init ===")
    tool_ok = check_command_has_version("npx hardhat --version")
    project_ok = hardhat_project_already_initialized()

    if tool_ok and project_ok:
        print("Hardhat sudah terinstall DAN project ini sudah di-init, skip ke bagian Foundry.")
        return
    elif tool_ok and not project_ok:
        print("Hardhat ada di sistem, tapi folder ini BELUM di-init sebagai project Hardhat. Lanjut init...")
    else:
        print("Hardhat belum terinstall. Lanjut install...")

    print("\n=== STEP 2-6: Init Hardhat (non-interaktif) ===")
    proc = run(f"npx hardhat --init --template {HARDHAT_INIT_TEMPLATE}", check=False)
    if proc.returncode != 0:
        print("[WARNING] 'npx hardhat --init' gagal. Coba jalankan manual: "
              f"npx hardhat --init --template {HARDHAT_INIT_TEMPLATE}")

    print("\n=== STEP 7: Hardhat terinstall ===")

    print("\n=== STEP 8: npm install --save-dev hardhat ===")
    run("npm install --save-dev hardhat")

    print("\n=== STEP 9: npm install @openzeppelin/contracts ===")
    run("npm install @openzeppelin/contracts")


# ---------- STEP 10-15: FOUNDRY ----------
def foundry_project_already_initialized():
    """True kalau foundry.toml sudah ada DAN sudah dikonfigurasi sesuai profile kita
    (src = contracts). Kalau foundry.toml ada tapi masih default (src = src), berarti
    belum di-setup untuk project ini."""
    toml_path = Path("foundry.toml")
    if not toml_path.exists():
        return False
    content = toml_path.read_text()
    return 'src = "contracts"' in content


# ---------- CLEANUP BOILERPLATE FOUNDRY ----------
FOUNDRY_BOILERPLATE_FILES = [
    "script/Counter.s.sol",
    "src/Counter.sol",
    "test/Counter.t.sol",
]


def cleanup_foundry_boilerplate():
    """'forge init --force .' selalu nyipratin file contoh bawaan
    (Counter.sol dkk). Kita hapus sebelum compile biar gak ganggu
    (gak relevan sama contract project sendiri, dan bisa bikin
    generate_test_files()/compile jadi berantakan)."""
    print("\n=== Bersihin boilerplate default Foundry ===")
    removed = []
    for rel_path in FOUNDRY_BOILERPLATE_FILES:
        p = Path(rel_path)
        if p.exists():
            p.unlink()
            removed.append(rel_path)
    if removed:
        print("[REMOVED] File boilerplate bawaan 'forge init' dihapus:")
        for r in removed:
            print(f"  - {r}")
    else:
        print("[INFO] Gak ada file boilerplate yang ketemu (mungkin sudah dihapus sebelumnya).")


def setup_foundry():
    print("\n=== STEP 10: Cek apakah Foundry (forge) sudah terinstall & project sudah di-init ===")
    tool_ok = check_command_has_version("forge --version")
    project_ok = foundry_project_already_initialized()

    if tool_ok and project_ok:
        print("Foundry sudah terinstall DAN project ini sudah dikonfigurasi, skip ke bagian generate test.")
        return
    elif tool_ok and not project_ok:
        print("Foundry ada di sistem, tapi project ini belum di-init/dikonfigurasi. Lanjut init...")
        # skip step 11-13 (install foundry) karena tool sudah ada, tapi tetap forge init + toml
        run("forge init --force .")
        cleanup_foundry_boilerplate()
        write_foundry_toml()
        return
    else:
        print("Foundry belum terinstall. Lanjut install dari awal...")

    print("\n=== STEP 11: Install Foundry ===")
    run("curl -L https://getfoundry.sh/install | bash")

    print("\n=== STEP 12: Source shell config ===")
    for rc in ("~/.zshrc", "~/.bashrc"):
        rc_path = os.path.expanduser(rc)
        if os.path.exists(rc_path):
            # 'source' hanya berlaku di dalam proses shell yang sama,
            # jadi ini hanya efektif kalau shell ini interaktif.
            run(f"source {rc_path}", check=False)
            break
    else:
        print("[INFO] Tidak ketemu ~/.zshrc atau ~/.bashrc, lanjut saja.")

    print("\n=== STEP 13: foundryup ===")
    run("foundryup")

    print("\n=== STEP 14: forge init --force . ===")
    run("forge init --force .")
    cleanup_foundry_boilerplate()

    print("\n=== STEP 15: Update foundry.toml ===")
    write_foundry_toml()


def write_foundry_toml():
    foundry_toml_content = (
        '[profile.default]\n'
        'src = "contracts"\n'
        'out = "out"\n'
        'test = "test"\n'
        'script = "script"\n'
        'libs = ["node_modules", "lib"]\n'
    )
    Path("foundry.toml").write_text(foundry_toml_content)
    print("foundry.toml berhasil diupdate.")


# ---------- CEK VERSI SOLIDITY (pragma) ----------
def extract_pragma_versions(sol_files):
    """Ambil versi solidity (angka bersih, misal '0.8.28') dari tiap file .sol."""
    versions = {}
    for sol_file in sol_files:
        text = sol_file.read_text()
        m = re.search(r'pragma\s+solidity\s+([^;]+);', text)
        if not m:
            continue
        raw = m.group(1).strip()
        v = re.search(r'(\d+\.\d+\.\d+)', raw)
        if v:
            versions[sol_file.name] = v.group(1)
    return versions


# ---------- AUTO-FIX "STACK TOO DEEP" (viaIR + optimizer) ----------
def _find_hardhat_config():
    for candidate in ("hardhat.config.ts", "hardhat.config.js",
                       "hardhat.config.cjs", "hardhat.config.mjs"):
        if Path(candidate).exists():
            return Path(candidate)
    return None


def enable_via_ir_hardhat():
    """Sisipkan settings.viaIR + optimizer ke hardhat.config.* TANPA mengubah
    isi lain. Return True kalau berhasil (atau sudah ada), False kalau config
    gak ketemu / polanya gak dikenali (biar caller tau harus fallback jujur,
    bukan asal klaim berhasil)."""
    config_path = _find_hardhat_config()
    if not config_path:
        return False

    content = config_path.read_text()

    if re.search(r'viaIR\s*:\s*true', content):
        return True  # udah aktif, gak perlu ubah apa-apa

    settings_block = (
        '\n    settings: {\n'
        '      viaIR: true,\n'
        '      optimizer: { enabled: true, runs: 200 },\n'
        '    },'
    )

    # Bentuk object: solidity: { version: "x.y.z", ... }
    m = re.search(r'solidity\s*:\s*\{', content)
    if m:
        obj_start = m.end()
        version_m = re.search(r'version\s*:\s*["\'][\d.]+["\']\s*,?', content[obj_start:])
        insert_pos = obj_start + (version_m.end() if version_m else 0)
        new_content = content[:insert_pos] + settings_block + content[insert_pos:]
        config_path.write_text(new_content)
        return True

    # Bentuk string langsung: solidity: "x.y.z"
    m2 = re.search(r'solidity\s*:\s*(["\'])([\d.]+)\1', content)
    if m2:
        version = m2.group(2)
        replacement = (
            'solidity: {\n'
            f'    version: "{version}",\n'
            '    settings: {\n'
            '      viaIR: true,\n'
            '      optimizer: { enabled: true, runs: 200 },\n'
            '    },\n'
            '  }'
        )
        new_content = content[:m2.start()] + replacement + content[m2.end():]
        config_path.write_text(new_content)
        return True

    return False  # pola 'solidity' gak dikenali, gak berani sentuh file


def enable_via_ir_foundry():
    """Sisipkan via_ir = true + optimizer = true ke [profile.default] di
    foundry.toml TANPA mengubah baris lain. Return True/False sesuai berhasil
    atau tidak."""
    toml_path = Path("foundry.toml")
    if not toml_path.exists():
        return False

    content = toml_path.read_text()

    if re.search(r'^via_ir\s*=\s*true', content, flags=re.MULTILINE):
        return True  # udah aktif

    lines_to_add = []
    if not re.search(r'^optimizer\s*=', content, flags=re.MULTILINE):
        lines_to_add.append('optimizer = true')
    lines_to_add.append('via_ir = true')
    insertion = "\n".join(lines_to_add) + "\n"

    new_content, n = re.subn(
        r'(\[profile\.default\]\s*\n)',
        rf'\g<1>{insertion}',
        content,
        count=1,
    )
    if n == 0:
        return False  # gak nemu header [profile.default], gak berani sentuh
    toml_path.write_text(new_content)
    return True


def compile_with_stack_too_deep_fix():
    """Jalankan 'npx hardhat compile' & 'forge build'. Kalau gagal karena
    'stack too deep': JANGAN langsung tampilin raw error compiler ke
    terminal - coba fix otomatis dulu (viaIR + optimizer), lalu compile ULANG
    buat VERIFIKASI beneran fixed sebelum declare [FIXED]. Kalau ternyata
    masih gagal setelah di-fix, tampilkan error terbaru apa adanya (jujur,
    bukan over-claim)."""
    print("\n=== Auto-install & compile compiler Solidity yang sesuai ===")

    # --- Hardhat ---
    print(">>> Menjalankan: npx hardhat compile")
    result = subprocess.run("npx hardhat compile", shell=True, text=True, capture_output=True)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0:
        print(output.strip() or "[OK] Compile Hardhat berhasil.")
    elif "stack too deep" in output.lower():
        print("[INFO] Compile Hardhat gagal karena 'stack too deep'. "
              "Mencoba fix otomatis: aktifkan viaIR + optimizer di hardhat.config.*...")
        if not enable_via_ir_hardhat():
            print("[WARNING] Gak nemu hardhat.config.* atau pola 'solidity' yang dikenal, "
                  "gak bisa auto-fix. Error asli:")
            print(output.strip())
        else:
            retry = subprocess.run("npx hardhat compile", shell=True, text=True, capture_output=True)
            retry_output = (retry.stdout or "") + (retry.stderr or "")
            if retry.returncode == 0:
                print("[FIXED] hardhat.config.* diupdate (viaIR: true, optimizer enabled) "
                      "-> compile Hardhat sudah diverifikasi ULANG dan berhasil.")
            else:
                print("[WARNING] Sudah dicoba enable viaIR + optimizer, tapi compile Hardhat "
                      "MASIH gagal. Error terbaru (bukan yang lama):")
                print(retry_output.strip())
    else:
        print(f"[ERROR] Compile Hardhat gagal (exit code {result.returncode}), bukan karena stack too deep:")
        print(output.strip())

    # --- Foundry ---
    print("\n>>> Menjalankan: forge build")
    result = subprocess.run("forge build", shell=True, text=True, capture_output=True)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0:
        print(output.strip() or "[OK] Compile Foundry berhasil.")
    elif "stack too deep" in output.lower():
        print("[INFO] Compile Foundry gagal karena 'stack too deep'. "
              "Mencoba fix otomatis: aktifkan via_ir + optimizer di foundry.toml...")
        if not enable_via_ir_foundry():
            print("[WARNING] Gak nemu foundry.toml atau gagal sisip config, gak bisa auto-fix. "
                  "Error asli:")
            print(output.strip())
        else:
            retry = subprocess.run("forge build", shell=True, text=True, capture_output=True)
            retry_output = (retry.stdout or "") + (retry.stderr or "")
            if retry.returncode == 0:
                print("[FIXED] foundry.toml diupdate (via_ir = true, optimizer = true) "
                      "-> compile Foundry sudah diverifikasi ULANG dan berhasil.")
            else:
                print("[WARNING] Sudah dicoba enable via_ir + optimizer, tapi compile Foundry "
                      "MASIH gagal. Error terbaru (bukan yang lama):")
                print(retry_output.strip())
    else:
        print(f"[ERROR] Compile Foundry gagal (exit code {result.returncode}), bukan karena stack too deep:")
        print(output.strip())


def sync_solidity_version(sol_files):
    print("\n=== Cek versi Solidity di contracts ===")
    versions = extract_pragma_versions(sol_files)
    if not versions:
        print("[INFO] Tidak menemukan 'pragma solidity' di file manapun, skip pengecekan versi.")
        return

    distinct = sorted(set(versions.values()))
    if len(distinct) > 1:
        print(f"[WARNING] Ketemu versi Solidity yang beda-beda antar file: {versions}")
        print(f"Pakai versi tertinggi ({distinct[-1]}) buat konfigurasi.")
    target_version = distinct[-1]
    print(f"Versi Solidity target: {target_version}")

    _update_hardhat_solc_version(target_version)
    _update_foundry_solc_version(target_version)

    # 'compile'/'build' otomatis men-download binary solc versi yang
    # dibutuhkan (baik Hardhat maupun Foundry punya mekanisme built-in
    # buat fetch compiler version yang belum ada di cache lokal).
    # Kalau gagal karena 'stack too deep', otomatis dicoba fix (viaIR +
    # optimizer) dan di-verifikasi ulang - lihat compile_with_stack_too_deep_fix().
    compile_with_stack_too_deep_fix()


def _update_hardhat_solc_version(version):
    config_path = None
    for candidate in ("hardhat.config.ts", "hardhat.config.js",
                       "hardhat.config.cjs", "hardhat.config.mjs"):
        if Path(candidate).exists():
            config_path = Path(candidate)
            break
    if not config_path:
        print("[INFO] hardhat.config.* tidak ditemukan, skip update Hardhat.")
        return

    content = config_path.read_text()
    new_content, n = re.subn(
        r'(solidity\s*:\s*(?:\{\s*version\s*:\s*)?["\'])([\d.]+)(["\'])',
        rf'\g<1>{version}\g<3>',
        content,
    )
    if n > 0:
        config_path.write_text(new_content)
        print(f"[UPDATED] {config_path} -> solidity version di-set ke {version}")
    else:
        print(f"[WARNING] Gak nemu pola 'solidity: \"x.y.z\"' di {config_path}. "
              f"Sesuaikan manual ke versi {version}.")


def _update_foundry_solc_version(version):
    toml_path = Path("foundry.toml")
    if not toml_path.exists():
        print("[INFO] foundry.toml tidak ditemukan, skip update Foundry.")
        return

    content = toml_path.read_text()
    if re.search(r'^solc\s*=', content, flags=re.MULTILINE):
        new_content = re.sub(
            r'^solc\s*=\s*["\'][\d.]+["\']',
            f'solc = "{version}"',
            content,
            flags=re.MULTILINE,
        )
    else:
        # sisipkan baris solc tepat setelah header [profile.default]
        new_content = re.sub(
            r'(\[profile\.default\]\s*\n)',
            rf'\g<1>solc = "{version}"\n',
            content,
            count=1,
        )
    toml_path.write_text(new_content)
    print(f"[UPDATED] {toml_path} -> solc = \"{version}\"")


# ---------- REMAPPINGS FOUNDRY ----------
def ensure_foundry_remappings():
    """Generate/update remappings.txt biar forge tau cara nyambungin
    import (mis. '@openzeppelin/contracts/...') ke lokasi fisiknya
    di node_modules/ atau lib/. Tanpa ini, forge build bisa gagal
    'source not found' walaupun file-nya secara fisik ada."""
    print("\n=== Cek remapping Foundry ===")

    if not Path("foundry.toml").exists():
        print("[INFO] foundry.toml tidak ditemukan, skip remappings (bukan project Foundry).")
        return

    remap_path = Path("remappings.txt")
    existing = set()
    if remap_path.exists():
        existing = {line.strip() for line in remap_path.read_text().splitlines() if line.strip()}

    new_mappings = set(existing)

    # --- dari node_modules (npm packages, misal @openzeppelin/contracts) ---
    node_modules = Path("node_modules")
    if node_modules.exists():
        for entry in node_modules.iterdir():
            if entry.name.startswith("@") and entry.is_dir():
                for sub in entry.iterdir():
                    if sub.is_dir():
                        pkg = f"{entry.name}/{sub.name}"
                        new_mappings.add(f"{pkg}/=node_modules/{pkg}/")
            elif entry.is_dir():
                new_mappings.add(f"{entry.name}/=node_modules/{entry.name}/")

    # --- dari lib/ (forge dependencies, misal forge-std) ---
    lib_dir = Path("lib")
    if lib_dir.exists():
        for entry in lib_dir.iterdir():
            if entry.is_dir():
                src_dir = entry / "src"
                target = f"lib/{entry.name}/src/" if src_dir.exists() else f"lib/{entry.name}/"
                new_mappings.add(f"{entry.name}/={target}")

    if not new_mappings:
        print("[INFO] Tidak ada package di node_modules/ atau lib/ buat di-remap.")
        return

    if new_mappings != existing:
        remap_path.write_text("\n".join(sorted(new_mappings)) + "\n")
        print(f"[UPDATED] remappings.txt -> {len(new_mappings)} remapping:")
        for m in sorted(new_mappings):
            print(f"  - {m}")
    else:
        print("remappings.txt sudah lengkap & sesuai, tidak ada perubahan.")


# ---------- CEK IMPORT ----------
def extract_imports(sol_file):
    text = sol_file.read_text()
    pattern = re.compile(r'import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']')
    return pattern.findall(text)


def npm_package_name(import_path):
    parts = import_path.split("/")
    if import_path.startswith("@"):
        return "/".join(parts[:2])  # @scope/name
    return parts[0]


def check_imports(sol_files):
    print("\n=== Cek import di setiap contract ===")
    missing_local = []       # (file, import_path) - punya user sendiri, harus ditambahin manual
    found_local = []         # (file, import_path) - sudah ada
    failed_packages = set()  # package yang gak bisa di-install otomatis
    ok_packages = set()      # package yang sudah ada / berhasil di-install
    checked_packages = {}    # cache: package -> True/False (berhasil/gagal)

    for sol_file in sol_files:
        for imp in extract_imports(sol_file):
            if imp.startswith(".") or imp.startswith("/"):
                # import relative -> punya user sendiri (interface/lib custom)
                resolved = (sol_file.parent / imp).resolve()
                if resolved.exists():
                    found_local.append((sol_file.name, imp))
                else:
                    missing_local.append((sol_file.name, imp))
            else:
                pkg = npm_package_name(imp)
                if pkg in checked_packages:
                    if checked_packages[pkg]:
                        ok_packages.add(pkg)
                    else:
                        failed_packages.add(pkg)
                    continue

                if Path("node_modules", pkg).exists():
                    checked_packages[pkg] = True
                    ok_packages.add(pkg)
                    continue

                print(f"[INFO] Package '{pkg}' belum ada, coba install...")
                result = run(f"npm install {pkg}", check=False)
                ok = result.returncode == 0
                checked_packages[pkg] = ok
                if ok:
                    ok_packages.add(pkg)
                else:
                    failed_packages.add(pkg)

    if ok_packages:
        print("\n[OK] Package sudah tersedia:")
        for pkg in sorted(ok_packages):
            print(f"  - {pkg}")

    if found_local:
        print("\n[OK] File lokal sudah tersedia:")
        for fname, imp in found_local:
            print(f"  - {fname} -> {imp}")

    if missing_local:
        print("\n[STOP] Ada file lokal (interface/lib custom milik kamu sendiri) yang belum ada:")
        for fname, imp in missing_local:
            print(f"  - {fname} butuh '{imp}'")
        print("File-file ini bukan package open-source, jadi agent tidak bisa nge-download-in.")
        print("Silakan tambahin file-file tersebut secara manual, lalu jalankan ulang agent.")
        sys.exit(1)

    if failed_packages:
        print("\n[STOP] Ada package yang gagal di-install otomatis (kemungkinan bukan package publik di npm):")
        for pkg in sorted(failed_packages):
            print(f"  - {pkg}")
        print("Silakan cek/instal manual library ini, lalu jalankan ulang agent.")
        sys.exit(1)

    print("\nSemua import (local file & package) sudah lengkap.")


# ---------- DETEKSI "KEPALA" KONTRAK ----------
# Pendekatan: reverse-import-graph + filter tipe deklarasi.
# 1) Bangun graph siapa-ngeimport-siapa (local import doang, antar file
#    yang sejajar langsung di dalam contracts/).
# 2) File yang MUNCUL sebagai target import file lain -> otomatis bukan
#    kepala (dia "badan/buntut", contoh: Kantor.sol & Departemen.sol yang
#    diimport oleh Perusahaan.sol).
# 3) Dari sisa file yang gak pernah diimport siapa-siapa, buang juga yang
#    isinya cuma "abstract contract" / "interface" / "library" doang -
#    karena itu bukan kontrak yang bisa langsung di-deploy.
# 4) Sisanya = kepala. Bisa lebih dari 1 kepala (mis. Perusahaan.sol dan
#    Customer.sol yang independen tapi nanti saling berhubungan) - itu normal.
CONTRACT_DECL_RE = re.compile(r'\b(abstract\s+contract|contract|interface|library)\s+(\w+)')


def _extract_local_import_stems(sol_file):
    """Ambil stem (nama file tanpa .sol) dari import LOKAL (relative) di sol_file."""
    text = sol_file.read_text()
    pattern = re.compile(r'import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']')
    stems = set()
    for imp in pattern.findall(text):
        if imp.startswith(".") or imp.startswith("/"):
            resolved = (sol_file.parent / imp).resolve()
            if resolved.exists():
                stems.add(resolved.stem)
    return stems


def _get_concrete_contract_names(sol_file):
    """Nama 'contract X' KONKRET di file ini (bukan abstract/interface/library)."""
    text = sol_file.read_text()
    names = set()
    for kind, name in CONTRACT_DECL_RE.findall(text):
        if kind == "contract":
            names.add(name)
    return names


def detect_head_contracts(sol_files):
    """Return list of (head_file, [dependency_file, ...]).
    dependency_file = file lokal yang diimport LANGSUNG oleh head_file
    (dan sama-sama ada di top-level contracts/)."""
    by_stem = {f.stem: f for f in sol_files}

    file_deps = {}          # stem -> set(stem dependency)
    imported_by_someone = set()
    for f in sol_files:
        deps = {d for d in _extract_local_import_stems(f) if d in by_stem}
        file_deps[f.stem] = deps
        imported_by_someone.update(deps)

    heads = []
    skipped_non_concrete = []
    skipped_as_dependency = []
    for f in sol_files:
        if not _get_concrete_contract_names(f):
            skipped_non_concrete.append(f.name)
            continue
        if f.stem in imported_by_someone:
            skipped_as_dependency.append(f.name)
            continue
        dep_files = [by_stem[d] for d in sorted(file_deps[f.stem])]
        heads.append((f, dep_files))

    print("\n=== Deteksi kepala kontrak ===")
    if heads:
        print("[HEAD] File yang akan digenerate test-nya:")
        for f, deps in heads:
            dep_str = f" (butuh: {', '.join(d.name for d in deps)})" if deps else ""
            print(f"  - {f.name}{dep_str}")
    if skipped_as_dependency:
        print("[SKIP - dependency] Diimport oleh kontrak lain, gak digenerate standalone:")
        for name in skipped_as_dependency:
            print(f"  - {name}")
    if skipped_non_concrete:
        print("[SKIP - bukan contract konkret] abstract/interface/library:")
        for name in skipped_non_concrete:
            print(f"  - {name}")
    if not heads:
        print("[WARNING] Gak ada kepala yang kedeteksi (semua saling import atau semua "
              "abstract/interface/library). Fallback: generate semua file konkret sebagai kepala.")
        heads = [(f, []) for f in sol_files if _get_concrete_contract_names(f)]

    return heads


def extract_constructor_params(sol_file):
    """Return list of (type, name) dari constructor(...) kalau ada. Best-effort,
    parsing regex sederhana - gak nangani struct/nested generic yang aneh-aneh."""
    text = sol_file.read_text()
    m = re.search(r'constructor\s*\(([^)]*)\)', text, re.DOTALL)
    if not m:
        return []
    raw = m.group(1).strip()
    if not raw:
        return []
    params = []
    for part in raw.split(","):
        tokens = part.strip().split()
        if len(tokens) >= 2:
            ptype, pname = tokens[0], tokens[-1]
            params.append((ptype, pname))
    return params




def setup_environment_only():
    """Prepare the repository for the audit-agent pipeline.

    This script deliberately does NOT generate tests, exploits, PoCs, or
    vulnerability findings. Those are responsibilities of later agents.
    """
    print("=== SECURITY AUDIT PROJECT SETUP ===")
    print("Environment setup only: no exploit/PoC generation.\n")

    CONTRACTS_DIR.mkdir(exist_ok=True)
    sol_files = sorted(CONTRACTS_DIR.glob("*.sol"))
    if not sol_files:
        print(f"[STOP] Folder '{CONTRACTS_DIR}' kosong (tidak ada file .sol).")
        print("Masukkan source Solidity ke folder contracts/ terlebih dahulu.")
        sys.exit(1)

    print(f"[INFO] Ditemukan {len(sol_files)} file .sol.")

    setup_hardhat()
    setup_foundry()

    # Analyze imports/dependencies, but do not generate security tests.
    check_imports(sol_files)
    ensure_foundry_remappings()
    sync_solidity_version(sol_files)

    print("\n=== SETUP SELESAI ===")
    print("Repository siap dipakai oleh:")
    print("  1. Recon Agent")
    print("  2. Threat Model Agent")
    print("  3. Attack Chain Agent")
    print("  4. Exploit Validator Agent")
    print("  5. Finding/Report Agent")


if __name__ == "__main__":
    setup_environment_only()
