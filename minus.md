RECON

Gate status

Recon sudah menghasilkan protocol model / security-relevant artifacts yang cukup untuk diteruskan ke Threat.

Kekurangan Recon yang perlu dicatat

Coverage belum identik dengan semantic completeness. Recon kuat di AST, inventory, call graph, state read/write, external interaction, dataflow, capability, dan provenance, tetapi hasil statis belum otomatis memahami apakah sebuah hubungan benar-benar security-relevant pada runtime.

Dynamic behavior masih punya batas static analysis. Callback, hook, runtime dispatch, delegatecall/call target resolution, dan perilaku kontrak eksternal belum selalu bisa dipastikan hanya dari fakta statis.

Authorization semantics belum sepenuhnya diputuskan oleh Recon. Recon dapat menunjukkan caller/input provenance, tetapi siapa yang secara semantik berhak melakukan aksi tertentu tetap perlu interpretasi Threat/Attack/Validator.

Business/economic meaning belum lengkap. Asset movement dan state mutation bisa ditemukan, tetapi hubungan akhirnya dengan economic loss, unfair allocation, insolvency, griefing, atau broken protocol invariant membutuhkan reasoning lanjutan.

Invariant masih berupa kandidat bila tidak benar-benar diturunkan dari protocol semantics. Jangan menganggap invariant candidate sebagai invariant yang sudah terbukti.

Tidak semua target yang tampak dinamis adalah attacker-controlled. Provenance terhadap parameter/argument perlu dibedakan dari sekadar adanya external call atau dynamic-looking expression.

Dependencies eksternal / library / mocks dapat memperbesar noise. Model perlu membedakan production code, test/mock code, dependency/library code, dan helper code agar Threat tidak menganggap semuanya sebagai attack surface yang setara.

Recon bukan attack proof. Output Recon adalah evidence/model untuk agent berikutnya, bukan konfirmasi vulnerability.

THREAT

Gate status

Threat sekarang mampu menyusun hypothesis dari kombinasi:
untrusted influence -> argument propagation -> external execution -> downstream opportunity -> asset/state effect -> invariant concern

Threat juga sudah memiliki grading seperti:

STRUCTURAL

SECURITY_RELEVANT

STRONG_SECURITY_CHAIN

Kekurangan Threat yang masih perlu dibawa ke gate berikutnya

Threat masih menghasilkan hypothesis, bukan confirmed finding.

Banyak hypothesis masih berhenti pada POSSIBLE / STRUCTURALLY_INDICATED karena runtime callback/target behavior belum bisa dibuktikan static.

Dynamic target tidak selalu terbukti benar-benar attacker-controlled.

Adjacency atau post-call-derived effect tidak boleh dianggap sebagai causal exploit proof.

INV-* masih candidate invariant, bukan invariant yang confirmed.

Banyak duplicate / overlapping hypotheses dapat menunjuk ke akar masalah yang sama.

Mock, tester, helper, dan dependency code masih dapat menghasilkan noise; production relevance harus diverifikasi.

Threat belum membuktikan exploitability, exact loss, privilege boundary bypass, griefing feasibility, atau economic consequence.

Threat belum menghasilkan PoC, trace runtime, fork reproduction, atau test result.

Threat belum melakukan final deduplication berdasarkan root cause / exploit path.

Output Threat harus diperlakukan sebagai input Attack Agent, bukan langsung sebagai finding.

Rule gate

Threat lolos untuk diteruskan ketika:

provenance cukup jelas untuk dianalisis,

security chain dapat dibentuk,

asset/state/invariant relationship dapat ditunjukkan,

uncertainty diberi label eksplisit,

dan hypothesis memiliki evidence/fact IDs yang dapat ditelusuri.

Threat belum dianggap confirmed vulnerability sampai Attack + Validator membuktikannya.
