# Synapse Mind

**Türkçe** · [English](#english)

**Bilgisayarının yerel hafızası.** Ne yapıyordun, hangi hatayı aradın, neyi nereye yapıştırdın: `Alt+Space`'e bas, yaz, bul.
Her şey cihazında kalır. Parolalar, API anahtarları ve kişisel bilgiler diske ulaşmadan bellekte maskelenir.

`v0.1.0` · Windows 11 (x64) · Rust 2024 + Tauri 2 · [FSL-1.1-MIT](LICENSE)

![Alt+Space ile arama: "derleme hatası" yazılıyor, nedensellik bağlarıyla sonuçlar geliyor](docs/media/arama.gif)

> Görüntüler sentetik veriyle alınmıştır. Synapse Mind'ın pencereleri gerçek ekran kayıtlarında görünmez (`WDA_EXCLUDEFROMCAPTURE`); bu yüzden arayüz kayıt için tarayıcıda örnek veriyle çalıştırıldı. Betik: [docs/media/capture.mjs](docs/media/capture.mjs).

## Ne yapar

- **Hatırlar.** Odaktaki pencerenin metnini (UI Automation), panoyu ve pencere geçişlerini olay olarak yakalar. Periyodik ekran görüntüsü almaz.
- **Bağlar.** Olaylar arasında nedensellik kurar: hata → arama → panoya kopyalama → yapıştırma. Arama sonucunda yalnızca anı değil, o anın zincirini de görürsün.
- **Bulur.** BM25 tam metin + vektör benzerliği + zaman ile hibrit arama. Tekil sorgu gömme p95 **18,06 ms**.
- **Korur.** Kara listedeki uygulamalar (parola yöneticileri, gizli sekmeler, `.env` / `.pem` / `id_rsa` pencereleri) hiç işlenmez. Diğer her şey maskeleyiciden geçer: `STRIPE_SECRET=[REDACTED_API_KEY]`.
- **Gizlenir.** Arama penceresi ve panel ekran kaydında ve ekran paylaşımında görünmez. Tam ekran oyunda kendini askıya alır.

## Hafıza Paneli

Bugün ne kadar şey hatırlandı, ne yapmaya çalışıyordun, hangi sırlar diske hiç ulaşmadı; duraklat, engelle, sil.

![Hafıza Paneli: bugünkü hafıza, nedensellik zinciri, saatlik grafik ve bölümler arası gezinme](docs/media/hafiza-paneli.gif)

<table>
<tr>
<td><img src="docs/media/hafiza-paneli-koyu.png" alt="Hafıza Paneli koyu tema"></td>
<td><img src="docs/media/hafiza-paneli-duraklatildi.png" alt="Yakalama duraklatılmış"></td>
</tr>
<tr>
<td align="center">Koyu tema</td>
<td align="center">Yakalama duraklatıldığında</td>
</tr>
</table>

## Kullanım

| Ne | Nasıl |
|---|---|
| Ara | `Alt+Space` → yaz → `↑` `↓` ile gez → `Esc` gizler |
| Hafıza Paneli | Arama açıkken `Ctrl+M`, ya da tepsi simgesi → **Hafıza Paneli** |
| Duraklat / devam | Tepsi simgesi → **1 saat duraklat** / **Devam et** (simge grileşir) |
| Bir uygulamayı hiç kaydetme | Panel → Kontrol sende → **Bir uygulamayı hiç kaydetme** |
| Sil | Panel → **Son 15 dakikayı sil** ya da iki adımlı onayla **Tüm hafızayı sil** |
| Kapat | Tepsi simgesi → **Synapse Mind'dan çık** (pencereyi kapatmak uygulamayı kapatmaz) |

Tepsi simgesinin ipucu durumu gösterir: `kaydediyor`, `duraklatıldı (N dk)`, `askıda (oyun modu)`.

## Güvenlik

| Kapı | Sonuç |
|---|---|
| **Gate 1**: PII sızma testi (Core 60, Evasion 40, Blacklist 26, r1/r2 108 vektör, zorunlu kontroller 38/38) | PASS, [kabul edilen risklerle](SECURITY.md) |
| **Gate 2**: bellek dökümü; nihai ikili, 41 döküm (uygulama, UIA işçisi, panel dahil WebView2) | PASS, sıfır tolerans sınıflarının hepsi 0 |

- **Şifreli depo:** SQLCipher, AES-256 (CBC + HMAC-SHA512). Anahtar rastgele üretilir ve Windows DPAPI ile korunur; düz anahtar diske yazılmaz.
- **Bellek hijyeni:** ham tamponlar işlem biter bitmez `zeroize` ile silinir. Guard her paketten sonra yığını temizler.
- **UI Automation ayrı süreçte:** Windows'un UIA kitaplığı okuduğu metni kendi tamponlarında sıfırlamadan bırakır. Synapse Mind bu okumayı tek kullanımlık, önceden ısıtılmış bir yardımcı süreçte yapar; süreç öldürülünce Windows belleği geri alır. Ana süreç bu kitaplığı hiç yüklemez.
- **Kendini kaydetmez:** Synapse Mind'ın kendi pencereleri ve süreçleri sensörde en başta dışlanır; yazdığın aramalar hafızaya girmez.
- **Ağ yok:** kullanıcı verisi cihazdan çıkmaz. Tek ağ kullanımı, `fastembed` özelliği açıksa modelin bir kez indirilmesidir.

Sınırlar (aynı oturumdaki kötü amaçlı yazılım, pagefile ve hibernasyon, Windows masaüstü yığını) ve kabul edilen riskler: [SECURITY.md](SECURITY.md) · [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Ölçümler

Makine boştayken, release derlemesi; AMD Ryzen 7 8845HS, Windows 11. Tam tablo: [benchmark.md](benchmark.md).

| Ölçüm | p50 | p95 | Hedef |
|---|---:|---:|---|
| Tekil sorgu gömme, FP32, ≈200 B | 16,25 ms | 18,06 ms | < 20 ms ✅ |
| Uçtan uca arama (1000 olay, şifreli, k=10) | 34,99 ms | 39,94 ms | |
| Hibrit arama, 10k vektör | 8,00 ms | 9,65 ms | |
| Guard, ≈200 B | 67,7 µs | 131,6 µs | |
| Rust daemon belleği (panel açıkken) | 43,5 MB | | < 50 MB ✅ |

Bilinen: 4 KB'lık tek metin gömme p95 88 ms (arama sorgusu boyutunun çok üstü; v0.1.1'de sorgu uzunluğu sınırı değerlendirilecek).

## Kurulum ve derleme

**Gereksinimler:** Rust 1.95+, MSVC derleme araçları, [Strawberry Perl](https://strawberryperl.com/) (SQLCipher için OpenSSL derlemesi; `winget install StrawberryPerl.StrawberryPerl`), Node.js ve npm, WebView2 Runtime (Windows 11'de yüklü gelir).

```powershell
npm --prefix ui install
npm --prefix ui run build
cargo build --manifest-path src-tauri/Cargo.toml --release
.\src-tauri\target\release\synapse-mind.exe
```

- Arayüz ikilinin içine gömülür (`custom-protocol` varsayılan). İlk release derlemesi OpenSSL ve SQLCipher yüzünden uzun sürer.
- **Anlamsal arama için** `--features fastembed` ekleyin. Varsayılan derleme gerçek model yerine deterministik bir test gömücüsü kullanır; kelime eşleşmesi çalışır, anlam benzerliği çalışmaz.
- Veriler: `%LOCALAPPDATA%\SynapseMind\memory.db` (şifreli) ve `key.bin` (DPAPI ile korunan anahtar). `key.bin` silinirse veritabanı açılamaz.
- Görev Yöneticisi'nde ikinci bir `synapse-mind.exe` görmen normal: bu, UI Automation yardımcı işçisidir.

Geliştirme komutlarının tamamı: [komutlar.txt](komutlar.txt).

## Henüz yok (v0.1.1+)

- OCR görsel yedek (UI Automation ağacı boş pencerelerde metin yakalanmaz)
- Uzun sorgular (4 KB+) için uzunluk sınırı
- Windows dışı platformlar, bulut eşitleme (kapsam dışı)

## Belgeler

[Mimari](ARCHITECTURE.md) · [Vizyon](SYNAPSE_MIND.md) · [Güvenlik](SECURITY.md) · [Tehdit modeli](docs/THREAT_MODEL.md) · [Sürüm notları](docs/CHANGELOG.md) · [Ölçümler](benchmark.md) · [Arayüz tasarımı](ui/DESIGN.md)

Belgelerin çoğu Türkçedir.

## Lisans

[Functional Source License 1.1, MIT Future License (FSL-1.1-MIT)](LICENSE).

- Kaynak kodu açıktır: okuyabilir, denetleyebilir, kendi kullanımın, eğitim ve araştırma için değiştirebilir ve dağıtabilirsin.
- Yasak olan tek şey **rakip kullanım**: Synapse Mind'ı ya da aynı işlevi sunan bir ürünü ticari olarak başkalarına sunmak.
- Her sürüm, yayımlandığı tarihten **2 yıl sonra** otomatik olarak MIT lisansına geçer.

Ayrıntı için [LICENSE](LICENSE) dosyasının kendisi geçerlidir; bu özet bilgilendirme amaçlıdır.

---

<a id="english"></a>

# Synapse Mind (English)

[Türkçe](#synapse-mind) · **English**

**Your computer's local memory.** What were you doing, which error did you search for, what did you paste where: press `Alt+Space`, type, find it.
Everything stays on your device. Passwords, API keys and personal data are masked in memory before anything reaches the disk.

`v0.1.0` · Windows 11 (x64) · Rust 2024 + Tauri 2 · [FSL-1.1-MIT](LICENSE)

> The demo above uses synthetic data. Synapse Mind's windows are hidden from real screen recordings (`WDA_EXCLUDEFROMCAPTURE`), so the UI was recorded in a browser with sample data. Script: [docs/media/capture.mjs](docs/media/capture.mjs). The UI itself is in Turkish.

## What it does

- **Remembers.** Captures the focused window's text (UI Automation), the clipboard and window switches as events. No periodic screenshots.
- **Connects.** Links events causally: error → search → copy → paste. A search result shows not just a moment but the chain around it.
- **Finds.** Hybrid search: BM25 full text + vector similarity + time. Single-query embedding p95 **18.06 ms**.
- **Protects.** Blocklisted apps (password managers, private browsing, `.env` / `.pem` / `id_rsa` windows) are never processed. Everything else goes through the masker: `STRIPE_SECRET=[REDACTED_API_KEY]`.
- **Hides.** The search window and the panel are invisible to screen recording and screen sharing. It suspends itself during fullscreen games.

## Memory Panel

How much was remembered today, what you were trying to do, which secrets never reached the disk; pause, block, delete.

![Memory Panel: today's memory, causality chain, hourly chart and navigation](docs/media/hafiza-paneli.gif)

## Usage

| What | How |
|---|---|
| Search | `Alt+Space` → type → move with `↑` `↓` → `Esc` hides |
| Memory Panel | `Ctrl+M` while search is open, or tray icon → **Hafıza Paneli** |
| Pause / resume | Tray icon → **1 saat duraklat** (pause 1 hour) / **Devam et** (resume); the icon turns grey |
| Never record an app | Panel → Kontrol sende → **Bir uygulamayı hiç kaydetme** |
| Delete | Panel → **Son 15 dakikayı sil** (last 15 minutes) or, with two-step confirmation, **Tüm hafızayı sil** (everything) |
| Quit | Tray icon → **Synapse Mind'dan çık** (closing a window does not quit the app) |

The tray tooltip shows the live state: recording, paused (N min), suspended (game mode).

## Security

| Gate | Result |
|---|---|
| **Gate 1**: PII leak test (Core 60, Evasion 40, Blacklist 26, r1/r2 108 vectors, mandatory controls 38/38) | PASS, [with accepted risks](SECURITY.md) |
| **Gate 2**: memory dump; final binary, 41 dumps (app, UIA worker, WebView2 including the panel) | PASS, every zero-tolerance class at 0 |

- **Encrypted store:** SQLCipher, AES-256 (CBC + HMAC-SHA512). The key is random and protected with Windows DPAPI; the plain key is never written to disk.
- **Memory hygiene:** raw buffers are wiped with `zeroize` as soon as they are processed. The guard clears its stack after every packet.
- **UI Automation in a separate process:** Windows' UIA library leaves the text it reads in its own buffers without wiping them. Synapse Mind performs this read in a single-use, pre-warmed helper process; when the process is killed, Windows reclaims its memory. The main process never loads that library.
- **Does not record itself:** Synapse Mind's own windows and processes are excluded at the very start of the sensor; your searches never enter the memory.
- **No network:** user data never leaves the device. The only network use is a one-time model download when the `fastembed` feature is enabled.

Limits (malware in the same session, pagefile and hibernation, the Windows desktop heap) and accepted risks: [SECURITY.md](SECURITY.md) · [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (in Turkish).

## Measurements

Idle machine, release build; AMD Ryzen 7 8845HS, Windows 11. Full table: [benchmark.md](benchmark.md).

| Measurement | p50 | p95 | Target |
|---|---:|---:|---|
| Single-query embedding, FP32, ≈200 B | 16.25 ms | 18.06 ms | < 20 ms ✅ |
| End-to-end search (1000 events, encrypted, k=10) | 34.99 ms | 39.94 ms | |
| Hybrid search, 10k vectors | 8.00 ms | 9.65 ms | |
| Guard, ≈200 B | 67.7 µs | 131.6 µs | |
| Rust daemon memory (panel open) | 43.5 MB | | < 50 MB ✅ |

Known: embedding a single 4 KB text has p95 88 ms (far above search-query size; a query length limit is planned for v0.1.1).

## Build

**Requirements:** Rust 1.95+, MSVC build tools, [Strawberry Perl](https://strawberryperl.com/) (OpenSSL build for SQLCipher; `winget install StrawberryPerl.StrawberryPerl`), Node.js and npm, WebView2 Runtime (preinstalled on Windows 11).

```powershell
npm --prefix ui install
npm --prefix ui run build
cargo build --manifest-path src-tauri/Cargo.toml --release
.\src-tauri\target\release\synapse-mind.exe
```

- The UI is embedded in the binary (`custom-protocol` by default). The first release build takes a while because of OpenSSL and SQLCipher.
- **For semantic search** add `--features fastembed`. The default build uses a deterministic test embedder instead of a real model: keyword matching works, semantic similarity does not.
- Data: `%LOCALAPPDATA%\SynapseMind\memory.db` (encrypted) and `key.bin` (DPAPI-protected key). If `key.bin` is deleted, the database cannot be opened.
- A second `synapse-mind.exe` in Task Manager is expected: it is the UI Automation helper.

All development commands: [komutlar.txt](komutlar.txt).

## Not yet (v0.1.1+)

- OCR visual fallback (no text is captured from windows with an empty UI Automation tree)
- A length limit for long queries (4 KB+)
- Non-Windows platforms, cloud sync (out of scope)

## License

[Functional Source License 1.1, MIT Future License (FSL-1.1-MIT)](LICENSE).

- The source is available: you may read, audit, modify and redistribute it for your own use, education and research.
- The only thing not allowed is a **competing use**: offering Synapse Mind, or a product with the same functionality, commercially to others.
- Each version automatically becomes MIT-licensed **two years** after its release.

The [LICENSE](LICENSE) file itself governs; this summary is for information only.
