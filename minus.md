# Minus — Recon

## Recon Gate: Code4rena Jackpot

Status gate: **PASS**

Recon berhasil menganalisis repo Jackpot secara penuh:
- 61 files analyzed
- 0 files failed
- 10,189 facts
- 1,214 graph nodes
- 2,079 graph edges
- compiler resolved/invoked: 0.8.28
- `JackpotBridgeManager`, `Jackpot`, dan `JackpotTicketNFT` terdeteksi
- `_bridgeFunds` berhasil diekstrak beserta dynamic low-level call, approval, dataflow, dan post-call balance check

## Kekurangan yang masih terlihat

### 1. Callback capability belum terdeteksi pada benchmark Jackpot

**Evidence:** `summary.json` menghasilkan `callback_capable_call_count: 0`, walaupun target finding warden bergantung pada jalur `safeTransferFrom -> IERC721Receiver.onERC721Received`.

**Dampak:** Recon sudah menyediakan primitive yang diperlukan Threat (dynamic call, approval, asset operation, graph, dan post-call balance check), tetapi belum memberikan primitive callback yang eksplisit untuk jalur exploit tersebut.

**Kepemilikan perbaikan:** Belum tentu bug Recon. Ini harus diuji di Threat terlebih dahulu. Bila Threat gagal hanya karena callback primitive tidak tersedia, baru evaluasi apakah Recon perlu memperkaya callback analysis.

### 2. Banyak call-argument dataflow masih unresolved

**Evidence:** `summary.json` menunjukkan `analysis_coverage.unresolved.call_argument_dataflows: 237` dan terdapat `call_unresolved: 73`.

**Dampak:** Sebagian hubungan parameter -> argument -> sink belum dapat dibuktikan secara penuh. Ini dapat membatasi reasoning Threat/Attack pada kontrak yang memiliki ekspresi argument kompleks.

**Kepemilikan perbaikan:** Rekan ini tetap menjadi limitation Recon dan dapat diprioritaskan setelah benchmark Threat/Attack menunjukkan bahwa unresolved dataflow tersebut benar-benar memblokir finding.

### 3. Beberapa origin/dataflow pada `_bridgeFunds` masih berstatus unknown/heuristic

**Evidence:** untuk `_bridgeFunds`, beberapa fact seperti origin `_bridgeDetails.to`, `_bridgeDetails.data`, dan `balanceOf(address(this))` masih memiliki `root_kind: unresolved` atau catatan `unsupported_expression_shape`.

**Dampak:** Recon dapat mengetahui bahwa field tersebut dipakai, tetapi belum selalu dapat membuktikan asal nilai secara granular sampai root caller/field source.

**Kepemilikan perbaikan:** Jangan patch sekarang. Catat sebagai limitation yang akan dipakai untuk menentukan apakah Threat membutuhkan dataflow yang lebih dalam.

## Gate decision

Recon **cukup kuat untuk diteruskan ke Threat**. Kekurangan di atas dicatat sebagai backlog dan **tidak menjadi alasan untuk memblokir Threat**, kecuali benchmark Threat membuktikan bahwa salah satu limitation tersebut mencegah rekonstruksi root cause.

## Next gate

Lanjutkan ke **Threat Agent** menggunakan artifact:

`/tmp/recon-jackpot-v1a`
