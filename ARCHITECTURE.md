# Synapse Mind Mimarisi

Tip kontratı: `crates/s-types/src/lib.rs`.

## Veri hattı
```
s-sensor ──RawCapturePacket──▶ s-guard ──MaskedMemoryBlock──▶ s-core ──CausalityQueryHit──▶ src-tauri / ui
(Katman 1)    mpsc(128)       (Katman 2)        mpsc          (Katman 3)     Tauri IPC        (Katman 4)
```

## Crate'ler
| Crate | Katman | Sorumluluk |
|---|---|---|
| `s-types` | – | Kilitli kontrat tipleri. `RawCapturePacket` Debug/Serialize türetmez, Drop'ta zeroize eder. |
| `s-sensor` | 1 | Win32 olay kancaları, UI Automation, pano, xcap fallback, yük/oyun algılayıcı. |
| `s-guard` | 2 | Kara liste, PII/Secret scrubber, zeroize, DPAPI anahtar türetimi. |
| `s-core` | 3 | fastembed-rs, sqlite-vec, nedensellik kenarları, hibrit arama. |
| `src-tauri` + `ui` | 4 | Tauri 2.0 overlay (Faz 4'te eklenecek). |

## Bağımlılık yönü
`s-sensor`, `s-guard`, `s-core` yalnızca `s-types`'a bağımlıdır; birbirlerine doğrudan bağımlı değildir. Kablolama nihai binary'de (Faz 4) yapılır.

## `s-types` kontratı: Faz 0 donduruldu (2026-11-18, v0.2-ContractSpec)
Bu tiplerdeki değişiklikler bir ADR ile yapılır.

| Tip | Türetilen traitler | Bellek güvencesi |
|---|---|---|
| `RawCapturePacket` | yok (`Debug`/`Serialize`/`Clone` YOK) | `Zeroize` + `ZeroizeOnDrop`: drop'ta `timestamp_ms`, `process_id`, `process_name`, `window_title`, `raw_payload` silinir |
| `RawPayload` | yok (`Debug`/`Serialize`/`Clone` YOK) | Kendi `Drop`'u var: paketten bağımsız ömürde de silinir; `ScreenFrame` boyutları da sıfırlanır |
| `EventKind`, `ClipboardFormat` | `Debug, Clone, PartialEq, Eq` | Yalnızca metadata, loglanabilir, zeroize edilmez |
| `EventSource` (Sprint 3, ADR-003) | `Debug, Clone, Copy, PartialEq, Eq, Hash` | Alansız, 1 bayt (testle doğrulanır); DB kodu `as_str`/`parse`: `focus`, `clipboard`, `accessibility`, `visual` |
| `MaskedMemoryBlock`, `AppContext`, `CausalityQueryHit`, `CausalityEdge` | `Debug, Clone` | Temizlenmiş veri. `MaskedMemoryBlock.source: EventSource` (Sprint 3) |

Derleme zamanı güvenceleri (compile_fail doctest): ham tipler `{:?}` ile basılamaz, `Clone` edilemez, alanlar paketten taşınarak (move, E0509) çıkarılamaz.

Tüketici kuralları (tip seviyesinde kapatılamaz):
1. Ham alanları yalnızca `&` ile ödünç alın. `.clone()`/`.to_owned()`/`mem::take`/`mem::replace` ile kopyalamayın; kaçınılmazsa `zeroize::Zeroizing` ile sarın.
2. Sensör ham `String`/`Vec`'i `push` ile büyütmesin (realloc eski tamponu silmeden bırakır); `with_capacity` ya da tek seferde oluşturma kullanın.
3. Loglamaya yalnızca `EventKind`, `process_id`, `timestamp_ms` gibi metadata girer.

Açıklama (Sprint 2): `mem::take`/`mem::replace` tamponu kopyalamaz, taşır. Alınan değer hemen Drop'ta zeroize eden bir sarmalayıcıya konuyorsa kabul edilir (ör. s-guard `Held`, `Zeroizing<String>`). Yasak olan, alınan değerin zeroize edilmeyen bir yerde yaşamaya devam etmesidir.

## Karar kayıtları (ADR)
Tarih: 2026-11-18 (Sprint 2, temel commit 63be9f1). Sprint 2'de `s-types` donuk; aşağıdaki kod değişiklikleri yalnızca belirtilen sprintte uygulanır.

### ADR-001 `event_id` ataması: **ONAY (koşullu)**
Karar: s-guard `run_with_start_id(rx, tx, start_id)`, `run` = `run_with_start_id(.., 0)`; s-core `MemoryStore::next_event_id() -> u64` = `MAX(event_id)+1`; kablolama `start_id = store.next_event_id()`.

- **Tek süreç, tek yazar:** Doğru varsayım. Kimlik ataması tek bir guard görevinde, kalıcılık tek bir ingestion görevinde yapılıyor. Ancak s-core `ingest_block` `ON CONFLICT(event_id) DO UPDATE` kullanıyor; bu yüzden bir çakışma hata vermez, **eski olayın üzerine sessizce yazar** (eski kenarlar yeni içeriğe bağlanır). Bu yüzden aşağıdaki koşullar bağlayıcıdır.
- **Çökme sonrası boşluklar:** Sorun değil. `Dropped` kararları zaten kimlik tüketiyor, bu yüzden boşluk normal. Kanalda bekleyen ve kaybolan bloklar DB'ye hiç yazılmadığı için yeniden başlatmada `MAX+1` aynı numaraları güvenle yeniden kullanır. `event_id` yalnızca kimlik ve eşitlik bozucu olarak kullanılır; sayaç veya yoğunluk anlamı taşımaz.
- **Çok örnekli çalışma:** Desteklenmez. İki örnek aynı `MAX+1` değerini okur ve birbirinin olaylarını ezer.

Koşullar:
1. Faz 4 binary'si tek örnek kilidi alır (Windows adlandırılmış mutex, ör. `Local\SynapseMind-Singleton`). Kilit alınamazsa ikinci örnek DB açmadan çıkar.
2. `next_event_id()` DB açıldıktan sonra ve guard ile ingestion başlamadan önce **bir kez** çağrılır. Boş DB'de `0` döner (`COALESCE(MAX(event_id), -1) + 1`).
3. s-core üretim yolunda çakışmayı görünür kılar: ya düz `INSERT` (çakışmada hata verir) ya da upsert öncesi var olan satırı reddetme. Upsert yalnızca açık yeniden indeksleme API'sinde kalabilir.
4. guard sayaçta `wrapping_add` yerine taşmada duran `checked_add` kullanır. s-core `row_to_masked_block` negatif `event_id` değerini sessizce `0`'a çevirmek (`unwrap_or(0)`) yerine hata döndürür. Pratikte erişilemeyen sınırlar, ama sessiz çakışma üretmemeleri gerekir.
5. Çok örnek ya da çok yazar ileride gerekirse kimlik ataması DB'ye taşınır (s-core atar, guard'dan `event_id` kalkar). Bu bir kontrat değişikliğidir ve ayrı bir ADR gerektirir.

### ADR-002 IPC serileştirme: **ONAY**
`s-types`'a `serde` (opsiyonel feature dahil) eklenmez; `src-tauri` kendi DTO'larını tanımlar. Gerekçe: (a) kontrat crate'inde `Serialize` bulunması, `RawCapturePacket`/`RawPayload`'a yanlışlıkla türetme riskini ve inceleme yükünü artırır; (b) IPC şeması iç kontrattan ayrılır, böylece UI'ın görmemesi gereken alanlar tip seviyesinde dışarıda kalır.

DTO'lar (`src-tauri`, yalnızca `Serialize`; giden yönde `Deserialize` yok):
```rust
#[derive(serde::Serialize)]
struct HitDto { event_id: u64, timestamp_ms: u64, score: f32, summary_snippet: String,
                matched_app: String, causality_chain: Vec<EdgeDto> }
#[derive(serde::Serialize)]
struct EdgeDto { source_event_id: u64, target_event_id: u64, relationship: String,
                 time_delta_seconds: u32 }
#[derive(serde::Deserialize)]
struct SearchRequest { query: String, k: u32 } // sunucu tarafında k 1..=50'ye sıkıştırılır
```
- **UI'a GİTMEZ:** `text_hash` (tuzsuz SHA-256; kısa metinlerde sözlük doğrulamasına izin verir, UI'da kullanımı yok), `clean_text`'in tamamı (UI yalnızca ≤200 karakterlik `summary_snippet` alır), `redactions_count`, `has_embedding_payload`, `sanitized_title`. `CausalityQueryHit` bunları zaten taşımıyor; DTO da store'dan ek sorguyla bunları **eklememeli**.
- `score` NaN/Inf ise DTO'ya dönüştürülmeden önce sonuç atılır (serde_json NaN'ı `null` yapar).
- `event_id` JSON'da sayı olarak gider; 2^53 sınırı pratikte erişilemez, kabul edildi.
- `query` hiçbir zaman loglanmaz (kullanıcının yazdığı arama metni de hassas veridir).

### ADR-003 Kaynak olay türü metadata alanı: **UYGULANDI (Sprint 3 Aşama A, temel 52126bb)**
Uygulama notu: kapsam "mantık değişikliği yok" ile sınırlandığı için `is_clipboard_context` sezgisi **kaldırılmadı**. Pano olayı tespiti artık `source == Clipboard || is_clipboard_context(..)` ile yapılıyor; ≥16 karakterlik içerik eşleşmesi ve `text_hash` eşitliği yedek olarak duruyor. Sezginin kaldırılması (aşağıdaki tablodaki hedef) graph-vector-core'a ayrı bir iş olarak bırakıldı. Testlerdeki varsayılan `source` değeri `Accessibility`.
Gerekçe: s-core şu anda `pasted_from_clipboard` kenarını süreç adı ve başlıktaki `"clipboard"` sezgisinden ve ≥16 karakterlik metin eşleşmesinden çıkarıyor. Sezgi pano olaylarında neredeyse hiç tetiklenmiyor (pano olayının `process_name` değeri odaktaki süreç) ve kullanıcı kontrolündeki bir başlıkla tetiklenebiliyor. Kısa kopyala-yapıştır işlemleri de kaçıyor.

**`EventKind` aynen taşınmaz.** Bunun yerine **alansız (fieldless), kaba taneli** bir enum eklenir. Gerekçe: alansız enum yapısı gereği hiçbir içerik taşıyamaz; `node_count`, `phash_distance` ve pano biçimi s-core'un ihtiyacı değil (en az metadata ilkesi); çıktı kontratı da sensörün iç tipine bağlanmamış olur.
```rust
// crates/s-types/src/lib.rs (Sprint 3)
/// Kaynak olay türü. Alansız: içerik taşıyamaz (testte boyut 1 bayt olarak doğrulanır).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSource { Focus, Clipboard, Accessibility, Visual }

impl EventSource {
    /// Kalıcı ve kararlı DB kodu. Discriminant sırasına güvenilmez.
    pub const fn as_str(self) -> &'static str { /* "focus" | "clipboard" | "accessibility" | "visual" */ }
    pub fn parse(s: &str) -> Option<Self> { /* as_str'ın tersi */ }
}
impl From<&EventKind> for EventSource { /* total eşleme; tüm ClipboardCopied{..} → Clipboard */ }

pub struct MaskedMemoryBlock { /* mevcut alanlar */ pub source: EventSource }
```
`#[non_exhaustive]` bilerek kullanılmaz: workspace içinde yeni bir varyant eklendiğinde tüm `match` noktalarının derleme hatasıyla ortaya çıkması istenir. s-types testleri: `size_of::<EventSource>() == 1`, `parse(as_str(x)) == Some(x)` gidiş-dönüşü ve `From<&EventKind>` için tam kapsama.

Değişecek yerler (63be9f1 satırları):
| Crate | Yer | Değişiklik |
|---|---|---|
| s-types | `lib.rs` `MaskedMemoryBlock` (L175) | `EventSource` + `source` alanı + testler |
| s-guard | `lib.rs` `process` L64-84 | `drop(packet)`'tan önce `let source = EventSource::from(&packet.event_kind);` |
| s-guard | `lib.rs` L118-128 yapıcı | `source,` |
| s-core | `store.rs` L413-423 şema | `source TEXT NOT NULL CHECK (source IN ('focus','clipboard','accessibility','visual'))` |
| s-core | `store.rs` L141-165 `INSERT`/upsert | sütun, `?10` ve `source = excluded.source` |
| s-core | `causality.rs` L155-158 `SELECT` | `source` sütunu (ve `row_to_masked_block` kullanan tüm SELECT'ler) |
| s-core | `causality.rs` L297-330 `row_to_masked_block` | `EventSource::parse`; bilinmeyen değerde `FromSqlConversionFailure` |
| s-core | `causality.rs` L116-137 | `is_clipboard_context` sezgisi kaldırılır; kural `prev.source == Clipboard && curr.source != Clipboard`. Metin eşleşmesi yalnızca `prev.source == Clipboard` iken ikincil sinyal olarak kalır |
| s-core | test yardımcıları `causality.rs` L342-360, `store.rs` L554-571 | `source` parametresi; kısa (<16 karakter) yapıştırma testi eklenir |
| tests/redteam | `src/harness.rs` L164-176 `block()` | `source: EventSource::Accessibility` |
| src-tauri | DTO | Değişmez (`CausalityQueryHit` etkilenmez) |

Geçiş sırası (Sprint 3, 1. gün):
1. s-types/s-guard/s-core/redteam değişiklikleri kısa süreliğine dondurulur; Sprint 2 işlerinin birleştirildiği doğrulanır.
2. `s-types` değişikliği yapılır (`cargo test -p s-types`). Workspace bu noktada bilerek kırık.
3. Aynı dalda sırasıyla s-guard, s-core ve redteam harness'i düzeltilir.
4. Kapanış: `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo test -p s-redteam` (Gate 1 koşul 3) ve ayrı workspace'lerde (`src-tauri`, `benchmarks`) `cargo check`. Tek commit olarak birleştirilir.
5. **Bu iş kalıcı DB'den (DPAPI/SQLCipher) önce yapılmalı.** Şu an tüm DB'ler bellek içi olduğu için veri göçü (`ALTER TABLE`) gerekmiyor; kalıcı DB açıldıktan sonra bu değişiklik bir migrasyon gerektirir.

### ADR-004 Ayrı workspace'ler (`src-tauri`, `benchmarks`, `tests/security`): **ONAY (koşullu)**
- **Gerekçe:** Tauri'nin bağımlılık ağacı ve build script'i (frontend dist, `tauri.conf.json`) kök workspace'te `cargo test --workspace`'i yavaşlatır ve ön yüz derlemesine bağımlı kılar. Gate 2 bellek dökümü harness'i de kendi profilini ister (release + debug sembolleri, gerekirse ayrı `panic` stratejisi); profil yalnızca workspace kökünde tanımlanabildiği için ayrı workspace haklı.
- **Çift derleme maliyeti:** Her workspace'in kendi `target/` dizini var; s-types/s-guard/s-core ve ağır bağımlılıklar (rusqlite bundled, sqlite-vec, tokio, fastembed/ort) her workspace'te yeniden derlenir. Azaltım: her workspace'te `CARGO_TARGET_DIR` değişkeni ya da `.cargo/config.toml` `build.target-dir` ile ortak bir hedef dizin kullanmak. Sürüm ve özellik kümesi aynıysa artefaktlar yeniden kullanılır; bunun bedeli kilit beklemesidir.
- **Cargo.lock sürüm kayması (asıl risk):** Her workspace bağımlılıkları kendi başına çözer. Gate 1 kanıtı kök `Cargo.lock` ile üretiliyor; dağıtılan binary ise `src-tauri/Cargo.lock` ile derleniyor. `regex`, `sha2`, `zeroize` ve `rusqlite` sürümleri ayrışırsa güvenlik kanıtı dağıtılan binary'yi kapsamaz. Benchmark ölçümleri de dağıtılan sürümleri ölçmemiş olur.
- Koşullar:
  1. Ayrı workspace'ler kök `Cargo.lock`'tan tohumlanır (`cp Cargo.lock <ws>/Cargo.lock`, ardından `cargo build`), kök kilit dosyasında bir paket güncellendiğinde yeniden senkronlanır.
  2. Gate 1/Gate 2 öncesinde ortak paketlerin sürümleri karşılaştırılır (`cargo tree -p s-guard` çıktısının kök ve `src-tauri` arasındaki farkı boş olmalı). Fark varsa Gate kanıtı geçersizdir.
  3. Kök `[profile.release]` ayarları (`lto = "thin"`, `codegen-units = 1`) `src-tauri` ve `benchmarks` workspace'lerine aynen kopyalanır; aksi halde benchmark dağıtılan profili ölçmez.
  4. Sprint 3 önerisi: `benchmarks` ağır bağımlılık getirmiyorsa (criterion yalnızca dev-dependency) kök workspace'e üye yapılabilir; böylece kilit ve profil sorunları kendiliğinden kalkar. Karar orkestratörde.
