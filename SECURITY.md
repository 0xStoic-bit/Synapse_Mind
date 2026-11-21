# Güvenlik Politikası

Kapsam: Synapse Mind v0.1.x.

> **Sürüm durumu:** Aşağıdaki "doğrulandı" ifadeleri yalnızca belirtilen testler ve kapsam için geçerlidir. Resmi Gate 2 sonucu "Doğrulama durumu" bölümündeki yer tutucuya yazılır.

## Desteklenen sürümler

| Sürüm | Destek |
|---|---|
| 0.1.x (v0.1.0 yayınlandığında) | Güvenlik düzeltmeleri alır |
| 0.1.0 öncesi geliştirme dalları (`master`) | Desteklenmez, yalnızca geliştirme amaçlıdır |

Platform: Windows 11 (x64). Diğer platformlar desteklenmez (DPAPI ve Win32 API'lerine bağlıdır).

## Güvenlik bildirimi

Bir açık buldunuz mu, lütfen **herkese açık issue açmayın**.

- İletişim: **[YER TUTUCU: iletişim adresi]**
- Raporda şunları belirtin: etkilenen sürüm/commit, yeniden üretme adımları, etkinin tanımı (hangi veri nereye sızıyor).
- Gerçek parola, kart numarası, anahtar veya kişisel veri göndermeyin; sentetik örnek kullanın.
- Yanıt süresi ve koordineli ifşa takvimi: [YER TUTUCU: süreç henüz tanımlanmadı].

Kapsam dahilindeki örnekler: maskeleyiciyi atlayan girdi (ham sırrın diske, embedding'e, loga veya UI'a ulaşması), kara listeyi atlatma, ham sırrın Synapse Mind süreçlerinde bellekte `zeroize` sonrası kalması, veritabanının düz metin yazılması, anahtarın diske düz yazılması, IPC üzerinden hassas alan sızması, pencere bazlı IPC yetkilerinin aşılması.

Kapsam dışı: yönetici/SYSTEM yetkisine sahip saldırgan, çekirdek seviyesi saldırgan, aynı kullanıcı oturumunda zaten kod çalıştıran saldırganın yaptıkları (aşağıdaki "Sınırlar" bölümüne bakın), fiziksel olarak açık ve kilidi açılmış makine, Windows masaüstü yığınının (aşağıya bakın) ve okunan uygulamaların kendi belleği.

## Güvenlik garantileri

Aşağıdakiler tasarım ilkeleridir ve yanlarında belirtilen kanıtla desteklenir.

1. **Maskeleyiciden geçmemiş veri diske veya embedding'e gitmez.** `s-core` yalnızca `MaskedMemoryBlock` tüketir. Kanıt: Gate 1; Gate 2 ön koşusunda şifreli veritabanı gerçek anahtarla açıldığında olaylar maskeli ve diskte ham sır 0; guard'ı atlayan kontrol modunda 153/153 yakalama (dedektör kör değil).
2. **Kara liste.** Parola yöneticileri, gizli pencereler ve hassas dosya pencereleri işlenmeden düşürülür. Görünmez karakter, tam genişlik ve Kiril/Yunan homoglif kaçırmaları normalizasyonla yakalanır. Pencere başlığı eşleşmesi alt dizgedir ve bilinçli fail-closed çalışır (ör. "1Password nasıl kullanılır" başlıklı alakasız bir pencere de düşer). Kullanıcı Hafıza Paneli'nden ek uygulama engelleyebilir.
3. **Ham veri tiplerinin sızması engellenir.** `RawCapturePacket` ve `RawPayload` `Debug`, `Serialize`, `Clone` türetmez; ham alanlar paketten taşınarak çıkarılamaz. Kanıt: `s-types` derleme zamanı (`compile_fail`) doctest'leri.
4. **Bellek hijyeni.** Ham tamponlar `Drop`'ta `zeroize` edilir. Sensör tarafında pencere başlığı, süreç adı, UIA `BSTR` ve pano `HGLOBAL` tamponları sıfırlanır; guard her paket çıkışında 192 KiB'lık yığın silme yapar ve regex önbelleklerini ham metin görmeden önce ısıtır (aşağıdaki "Yığın silme ve regex önbellek ısıtması"). UI Automation okuması ana süreçten ayrı, tek kullanımlık bir yardımcı süreçte yapılır (aşağıdaki "UI Automation yardımcı süreci"). Veritabanı anahtarı `s_guard::DbKey` içinde (`Box<Zeroizing<[u8; 32]>>`, sabit heap adresi) tutulur, değerle taşınmaz, loglanmaz.
5. **Şifreli kalıcı depo.** Veritabanı yalnızca `MemoryStore::open_encrypted` ile açılır: SQLCipher 4.20.0 community, 32 baytlık ham anahtar, `PRAGMA cipher_memory_security = ON` (çalışma anında doğrulanır). Yanlış anahtar, düz SQLite dosyası veya bozuk dosya açık hata verir. Kanıt: s-core testleri (disk baytlarında `SQLite format 3` başlığı ve düz metin işaretçileri yok). Şifreleme SQLCipher 4 varsayılanıdır: sayfa başına AES-256-CBC ve HMAC-SHA512 (encrypt-then-MAC). Iron Rule 7 kullanıcı kararıyla (2026-11-19) buna göre güncellendi; önceki "AES-256-GCM" ifadesi SQLCipher ile uyumlu değildi.
6. **Anahtar koruması.** Anahtar işletim sistemi CSPRNG'sinden üretilir ve Windows DPAPI ile korunmuş halde `%LOCALAPPDATA%\SynapseMind\key.bin` içinde saklanır (atomik yazım). Bozuk blob üzerine yazılmaz.
7. **Tek örnek.** `Local\SynapseMind-Singleton` adlandırılmış mutex'i ikinci örneğin veritabanını açmasını (ve `event_id` çakışmasını) engeller. UIA işçi süreci bu kilidi almaz, veritabanını ve anahtar deposunu açmaz.
8. **Dar ve pencere bazlı IPC yüzeyi.** Webview'de `shell`, `fs`, `http`, `dialog` kapalıdır. Yetkiler pencere bazlıdır: arama (overlay) penceresi yalnızca `search`, `hide_overlay`, `is_demo_mode`, `open_memory_panel` ve olay dinlemeyi çağırabilir; Hafıza Paneli penceresi yalnızca panel komutlarını (duraklat/devam, uygulama engelle, son N dakikayı sil, tümünü sil, benzer anları ara, panel verisi) ve olay dinlemeyi çağırabilir. Sınır üç katmanda zorlanır: capability dosyaları, komut başına derleme zamanı izinleri ve çalışma zamanında pencere etiketi kontrolü (çapraz pencere çağrısı reddedilir, testli). "Tümünü sil" açık onay (`confirm == true`) gerektirir. UI'a yalnızca ≤200 karakterlik maskelenmiş özet, nedensellik kenarları ve sayaçlar gider; `text_hash`, tam metin ve `sanitized_title` gitmez. Arama sorguları loglanmaz.
9. **Ekran gizleme.** Overlay ve Hafıza Paneli `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` ile ekran kaydı ve paylaşımında görünmez olacak şekilde ayarlanır (eski Windows sürümlerinde `WDA_MONITOR` yedeği). Bu API çağrısı uygulanır; gerçek bir ekran kaydı/paylaşım aracıyla görsel doğrulama yapılmadı [DOĞRULANACAK].
10. **Yerel çalışma.** Kullanıcı verisini ağa gönderen kod yoktur. Tek bilinen ağ kullanımı, `fastembed` özelliğinde model/çalışma zamanı dosyası indirmesidir. Bağımsız ağ trafiği denetimi yapılmadı [DOĞRULANACAK].
11. **Kaynak farkındalığı.** Tam ekran oyun veya GPU %80+ iken sensörler durur ve boştaki UIA işçisi öldürülür (birim testli; canlı oyun elle doğrulanmadı).

## UI Automation yardımcı süreci

**Sorun.** Windows `UIAutomationCore.dll`, başka bir uygulamanın penceresinden okuduğu metni kendi iç NT heap tamponlarına kopyalar ve bunları sıfırlamadan serbest bırakır. Bu tamponlar Synapse Mind kodundan silinemez. Sensör tarafındaki tüm Rust ve `BSTR` tamponları sıfırlandıktan sonra bile, ana süreçte bu kalıntı görülüyordu (Gate 2 ön koşusunda son ölçüm: S1 25, S2 47, S3 3 eşleşme; hepsi UTF-16).

**Çözüm.** Synapse Mind her UI Automation okumasını, ana süreçten ayrı ve yalnızca o okuma için kullanılan bir yardımcı süreçte yapar (`UiaIsolation::Worker`, varsayılan):

- **Önceden ısıtılmış, tek kullanımlık işçi.** En fazla bir boşta yedek işçi hazır bekler (COM ve UIA kurulu, henüz hiçbir pencere okumamış). Okuma isteği gelince işçi tek bir pencereyi okur, sonucu verir ve hemen öldürülür; arka planda yenisi ısıtılır. Windows sonlanan sürecin belleğini geri alır, böylece UIA'nın kalıntısı işçiyle birlikte yok olur.
- **İşçi yalnızca bir pencere okur.** İstek, pencere tutacağı ve sınırları taşıyan 32 baytlık sayısal bir çerçevedir; komut satırında ham içerik veya pencere tutacağı bulunmaz. İşçide guard çalışmaz ve veritabanı, anahtar deposu, log veya dosya yazma yoktur; tek güven kapısı ana süreçteki guard olarak kalır.
- **Ana süreç `UIAutomationCore.dll` yüklemez.** UIA kitaplığı yalnızca işçide yüklenir.
- **IPC doğrudan `Zeroizing` tampona.** İstek ve sonuç, ana süreçle işçi arasındaki anonim `stdin`/`stdout` boruları üzerinden taşınır (adlı boru veya dosya yok; başka bir süreç bağlanamaz); işçinin `stderr` çıktısı atılır. Ana süreç çerçeve gövdesini tam kapasiteli bir `Zeroizing` tampona doğrudan okur (yeniden ayırma yok, testle doğrulandı), kopyasız olarak `RawCapturePacket`'e taşır ve guard paketi ham alanları aldıktan hemen sonra düşürür (`ZeroizeOnDrop`). Ham metnin ana süreçteki tek kopyası maskeleme biter bitmez sıfırlanır.
- **Job Object.** Tüm işçiler ana sürecin Job Object'ine (`KILL_ON_JOB_CLOSE`) atanır; ana süreç ölürse işçiler de ölür. Zaman aşımında bekçi işçiyi öldürür, işçi kendi zaman aşımını da uygular. `Suspended` / `Batching` girişinde boşta yedek öldürülür.
- **Odak bekletmesi.** 250 ms içinde değişen Alt+Tab ara pencereleri elenir; aynı pencere ve başlık için 2 s soğuma uygulanır. Bu, işçi süreç sayısını sınırlar.
- **Hata yolu.** İşçi başlamazsa süreç içi UIA'ya sessiz geri dönüş yoktur; okuma boş metin ve sabit bir sebep koduyla biter.

**Kanıt.**

| Ölçüm | Sonuç |
|---|---|
| Arena prototipi, `gate2-attrib --only S`, 7 koşu | 35/35 senaryo APP_OWNED 0. Aynı makinede değişiklik öncesi ikili: S1 3-26, S2 1-4 |
| Ana ağaca aktarım sonrası toplu doğrulama, `gate2-attrib --only S` | 3/3 koşuda S1-S5 APP_OWNED 0; UIA işçi alt süreçlerinde (boşta ve besleme sonrası) bulgu 0 |
| Canlılık (0 sonucu "sensör hiç okumadı" anlamına gelmesin diye) | `GATE2_SENSOR_TRACE` ile işçi yolunun gerçekten metin okuduğu (ör. 830 baytlık pencere metni) ve değişiklik öncesi ikilinin aynı makinede kalıntı bulduğu doğrulandı |
| Odak başına gecikme, önceden ısıtılmış işçi (60 örnek) | p50 33.40 ms, p95 44.31 ms. Önceden ısıtmasız soğuk başlatma: p50 91.25 ms, p95 115.66 ms |
| `stop()` | 5.23 ms |

İşçi arka plan iş parçacığında çalışır ve arama yolunu (p95 < 20 ms SLA) etkilemez.

**Sınır.** İşçi canlıyken (okuma başına yaklaşık 30-45 ms, önceden ısıtılmış işçi) ham metin o işçi süreçte bulunur. Aynı kullanıcı haklarıyla tam o anda süreç belleğini okuyabilen veya döküm alabilen bir saldırgan bunu görebilir. Önceden bu pencere ana sürecin ömrü kadardı. Ayrıca: `synapse-mind.exe` işçi olarak başladığında başlatma süresinin resmi ölçümü ayrıdır, bazı antivirüs/EDR ürünleri odak değişimi başına süreç oluşturulmasına uyarı verebilir. Sayfa dosyası/hibernasyon ve okunan uygulamanın kendi belleği kapsam dışıdır (aşağıya bakın). Süreç içi alternatiflerin neden elendiği: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) §6.4.

## Windows masaüstü yığını (Synapse Mind dışı)

Pencere başlıkları ve kontrol (EDIT vb.) metinleri, Windows masaüstü yığını tarafından oturum genelinde paylaşılan bellekte tutulur ve **tüm GUI süreçlerinde eşlenik (`mapped`) bölgelerde okunabilir**. Bu, işletim sisteminin davranışıdır; Synapse Mind bunu silemez ve Synapse Mind'a özgü değildir.

- **Negatif kontrol:** Gate 2 ön koşusunda Synapse Mind ile ilgisiz `explorer.exe` sürecinin dökümünde, Synapse Mind'ın okuduğu aynı sentetik pencere gövdesi sırları `mapped/image` bölgesinde görüldü. Bu yüzden Gate 2, yalnızca süreç sahipli bölgeleri (`private`, `stack`) Synapse Mind sorumluluğunda sayar ve `mapped` bulgularını `OS_SHARED` olarak karardan ayırır.
- **Anlamı:** ekranda görünen bir pencere başlığı veya kontrol metni, Synapse Mind hiç çalışmasa da, masaüstü yığınında bulunur. Synapse Mind'ın verdiği garanti, kendi süreç belleğinde ve diskte ham sır bırakmamasıdır; işletim sisteminin bu paylaşımlı belleği bu garantinin kapsamında değildir.

## Doğrulama durumu

### Gate 1 (PII/sır sızma testi): PASS, kabul edilen risklerle

Kaynak: bağımsız redteam test paketi (`tests/redteam`, `s-redteam`), hepsi sentetik veri. Yazılı onay: 19.11.2026.

- Sözleşme vektör seti: Core 60, Evasion 40, Blacklist 26, Control 31. Pencere=6'da maskelenmemiş karakter yok.
- **R1, R2, R3 kapandı:** `r1-*` 54/54, `r2-*` 54/54, stretch 16 ve stretch2 28 temiz; zorunlu kontroller 38/38.
- **R4 kapandı:** Gate 2 bellek gerilemesi (PEM / 64-hex kalıntısı) ve iki ek kalıntı (aşağıda) düzeltildi.
- **R5:** yeni `r3-*` sondaları (59 vektör): 29 PASS, 30 sızıntı; guard'ın ucuz düzeltmelerinden sonra 22 sızıntı (R5-b 7, R5-a 6, R5-c 9). Yüksek gerçekçilikte engel yok. Hepsi aşağıdaki kabul edilen risklerin kapsamındadır; kabul edilmemiş sızıntı 0.
- FP tarafı: zorunlu kontroller 38/38; bilinçli fail-closed maskelemeler "R5-d" altındadır.
- `s-guard`: 116 birim testi + 1 doctest.

### Gate 2 (RAM dökümü testi)

Yöntem: hedef süreçten (uygulama ve 6 WebView2 alt süreci dahil, UIA işçi süreçleri ve boşta yedek işçi dahil) `MiniDumpWriteDump` ile tam bellek dökümü, UTF-8 ve UTF-16LE tarama, sentetik sırlar ve DbKey (ham, hex, UTF-16, `x'hex'`) ile SQLCipher HMAC anahtarı. Kontroller (dedektörün kör olmadığı kanıtı): denetçinin kendi süreci 16/16, WebView'e yazılan işaret, `leaky-*` modları, HMAC türetiminin doğrulanması, şifreli veritabanının gerçek anahtarla açılıp olayların maskeli görülmesi.

Karar ölçütü **sıfır toleranstır**; "kabul edilen riskle PASS" yoktur. Sıfır olması gereken sınıflar: APP_OWNED UTF-8 ham sır, sensör UTF-16 tamponları (S1-S5), UIA işçi süreçleri (boşta yedek dahil), WebView2, tam DbKey, diskteki `memory.db`. Tek ayrık kabul sınıfı K1'dir (aşağıda).

**Ön koşu (panel öncesi `synapse-mind.exe`): VETO.** Düzeltmeleri:

| Kaynak | Bulgu | Durum |
|---|---|---|
| Sensör: pano | Ham UTF-16 kopyalar (HGLOBAL) | Kapandı (6 -> 0) |
| Sensör: başlık + UIA | Kalıntı `UIAutomationCore.dll`'in iç NT heap tamponlarında | UIA yardımcı süreciyle çözüldü (yukarıya bakın) |
| Guard | Düşük trafikte son paketin ham metni (G1-G3) | Kapandı: G1-G3 0 (öncesi 8-9, 6, 28) |
| Guard | R4b (geniş fixture, UTF-16 data URI blob kuyruğu) | Kapandı: release 10/10 koşuda temiz |
| DbKey | Son 12/32 bayt OS RNG tamponunda | K1 olarak kabul edildi |
| WebView2 | Önceki e-posta bulgusu | Sahte pozitif (parça `example.test` Chromium belleğinde zaten var); benzersiz e-postayla 6 süreçte 0 |

**Nihai ikili üzerinde resmi koşu sonucu:**

**Resmi Gate 2: PASS** (20.11.2026; nihai `synapse-mind.exe`, izole `LOCALAPPDATA`, gerçek sensör yolu: sentetik pencere + UIA gövdesi + 3 pano).

| Sıfır tolerans sınıfı | Sonuç |
|---|---|
| UTF-8 ham sır | 0 |
| BSTR / s-sensor `Vec<u16>` | 0 |
| UIA işçi süreçleri (boşta yedek dahil) | 0 |
| WebView2 (6 süreç × 5 evre) | 0 |
| Tam DbKey ve SQLCipher HMAC anahtarı | 0 |
| Disk (`memory.db`) | 0 |

- 40 döküm, döküm hatası 0. Evreler: başlangıçta boşta yedek, boşta, pencere kapalı, arama sonrası.
- K1 (DbKey'in son 12/32 baytı, OS RNG tamponu; kullanıcı kabulü) ayrık sınıftır; nihai koşuda 0.
- Pozitif kontroller geçti: denetçinin kendi süreci 16/16, WebView'e yazılan işaret görüldü, SQLCipher HMAC türetimi doğrulandı, şifreli DB gerçek anahtarla açıldığında olaylar maskeli.
- `gate2-audit` (release, 10'ar koşu, `process` / `run` / `core` / `encrypted-closed`): süreç sahipli bulgu 0/10.
- UIA işçi yaşam döngüsü (gerçek uygulama): eşzamanlı en çok 1 işçi, yetim işçi 0.
- **Yeniden koşu (20.11.2026 09:20, gömülü arayüzlü nihai ikili):** ilk resmi koşu, arayüzü gömülü olmayan (hata sayfası yükleyen) ikili üzerinde yapılmıştı; WebView ve panel kısmı bu yüzden geçersizdi. Düzeltilmiş ikiliyle tam koşu: **PASS**. 41 döküm (APP 5, UIA işçisi 5, WebView2 31; panel WebView'i dahil), döküm hatası 0. Evreler: başlangıçta boşta yedek, boşta, pencere kapalı, arama sonrası, **Hafıza Paneli açık**. Gerçek arayüz kanıtı: overlay ve panele özgü metinler ilgili evrelerde WebView belleğinde bulundu; panel penceresi gerçekten oluştu. Yeni sınıf **OZ_KAYIT** (Synapse Mind'ın kendi süreçlerinden gelen olay ve overlay'e yazılan arama işareti DB'de): 0. `gate2-audit` 10'ar koşu 0/10; Gate 2 testleri 16/16.

## Yığın silme ve regex önbellek ısıtması

Guard'ın ham metni işlerken bıraktığı kalıntının iki ayrı kaynağı vardı ve ikisi de Rust tamponu değildi, bu yüzden `zeroize` ile silinemiyordu:

- **Yığın kalıntısı.** `Regex::find/captures` çağrıları, ham metnin 16/32 baytlık parçalarını SIMD yazmaç dökümleri olarak yığına bırakıyordu. Çözüm: her `evaluate` (dolayısıyla `process` ve `run*`) çıkışında 192 KiB'lık bir yığın çerçevesi sabit bir desenle doldurulup sıfırlanır (`wipe_stack`). Maliyet paket başına yaklaşık bir `memset`'tir; bu ek `benchmark.md`'de ayrıca ölçülmedi.
- **Regex önbelleği.** Regex havuzu her desen için `Cache`'i ilk aramada çağıranın yığınında kurup heap'e taşır; bu sırada yığındaki önceki taramanın ham metin parçaları uzun ömürlü önbelleğe kopyalanabiliyordu. Çözüm: iş parçacığı başına bir kez, hiçbir ham metin işlenmeden önce 24 desenin tamamı zararsız bir dizgede çalıştırılarak önbellekler kurulur (`warm_up_thread`), öncesinde ve sonrasında yığın silinir.
- **R4b:** belirteç değerlendirmesinde harf kopyasını sıfırlamadan serbest bırakan ara `Vec` kaldırıldı.

Sınır: yığın silme, `evaluate`'i çağıran iş parçacığı için geçerlidir; guard'ı kendi iş parçacığından senkron `process` ile çağıran uygulama aynı garantiyi alır.

## Kabul edilen riskler

Yazılı onay: **19.11.2026**. Her satır redteam test sonuçlarından ve guard raporlarından alınmıştır. Kabul edilmeyen madde sürümü bloke eder (VETO).

| # | Madde | Örnek / kapsam | Neden kapatılamıyor | Gerçekçilik |
|---|---|---|---|---|
| A1 | Etiketsiz 64 hane hex (256-bit) | `value 3f2a...(64 hex) end` | SHA-256 özetleri ve commit hash'leriyle aynı biçim; maskelemek geliştirici içeriğini bozar (aranabilirlik kararı) | Orta |
| A2 | Etiketsiz 40 hane hex | `ref 9fceb02d...(40 hex)` | git SHA-1 ile aynı | Orta-düşük |
| A3 | `0x` önekli etiketsiz 64-hex | `0x<64 hex>` | Ethereum özel anahtarı ile işlem/blok özeti ayırt edilemez | Orta; cüzdan kullanıcısı için yüksek |
| A4 | Uzak etiketli hex | Etiket aynı satırda hex'ten >120 bayt önce, iki satır yukarıda veya >80 bayt sonra | Pencere genişledikçe yanlış pozitif artar | Düşük-orta |
| A5 | `password: String` | Değer gerçekten "String" | Tip adı; gerçek parola "String" olamaz | Çok düşük |
| A6 | Soneksiz 4-5 sözcüklü diceware | `correct_horse_battery_staple` | Düz İngilizce cümle veya slug'dan ayırt edilemez | Orta |
| R5-a | Kuyruk biçimleri | 4 sözcüklü satır, 9 satır, 2 harfli sözcükler, `ab=qwertzuiop`, `qwert:zuiop`, `return qwertzuiop` | Satır sonu sezgisi sıradan metni de yakalar (yanlış pozitif riski) | Orta |
| R5-b | Kasıtlı bölünmüş / çok katlı kodlanmış sabitler | `"Hunter".to_owned() + "2x.."`, `.concat()`, 7+ kat base64, base64(hex), `Option <X>`, `HunterTwoX9<T>` | Ters mühendislik gerektiren kodlama; saldırgan zaten yerel yetkili | Düşük |
| R5-c | Diceware bağlam muafiyetleri | `.txt`/`let`/`=` bağlamı, CamelCase 3 sözcük, 2 ve 11 harfli sözcük, leet rakam, `.`/`+` ayraç | Dosya adı ve kod tanımlayıcısı yanlış pozitifi | Düşük-orta |
| R5-d | Gereksiz maskeleme (fail-closed) | `password is changeable`, git özeti + yakın `key` sözcüğü, uzantısız `Word_Word_v3` | Aranabilirlik kaybı; güvenlik riski değil | (yanlış pozitif) |
| K1 | OS rastgele sayı üretecinin tamponunda DbKey'in son 12/32 baytı | Gate 2 ayrık sınıfı `K1_KABUL` | Kalıntı OS CSPRNG / `getrandom` iç durumundandır; `s-guard`, `s-core`, SQLCipher veya anahtar deposundan değil. 32 baytın yalnızca son 12 baytı (96/256 bit; kalan 160 bit bilinmiyor); açık veritabanında SQLCipher ek kopya tutmuyor | Düşük |

Bu tablonun dışında kalan, ilgili raporlarda belgelenmiş ek maskeleyici sınırları:

- Anahtar satırı sonunda bitiyorsa sonraki satırın ilk 6+ harfli sözcüğü anahtarla birlikte maskelenebilir (fail-closed, kullanılabilirlik kaybı).
- Sınırlı Kiril/Yunan homoglif tablosu (tam Unicode confusables yok).

## Sınırlar

Bunlar bilinen ve belgelenmiş sınırlardır.

- **Aynı kullanıcı oturumunda çalışan kötü amaçlı yazılım** DPAPI anahtarını açabilir (DPAPI kullanıcı kapsamlıdır), çalışan sürecin belleğini okuyabilir, açık veritabanını okuyabilir. Synapse Mind bu saldırgana karşı koruma sağlamaz.
- **Pagefile, hibernasyon dosyası ve çekirdek tamponları** Gate 2 kapsamı dışındadır (MiniDump yalnızca kullanıcı kipi belleği görür). `zeroize` sayfa dosyasına yazılmış sayfaları geri alamaz. Tam disk şifrelemesi (BitLocker) önerilir.
- **Okunan uygulamanın kendi belleği ve Windows masaüstü yığını** Synapse Mind'ın silebileceği bir şey değildir (yukarıya bakın).
- **Maskeleyici sezgiseldir** ve %100 yakalama garantisi vermez; açık kalan yüzey yukarıdaki kabul edilen riskler tablosudur.
- **Yanlış pozitifler bilinçli kabul edilir (fail-closed):** bazı kod/dosya adları ve hex özetleri gereksiz maskelenebilir; bu bir güvenlik değil, aranabilirlik kaybıdır.
- **Gizlilik anonimlik değildir.** Maskeleme yalnızca tanınan PII/sır kalıplarını siler. Maskelenmeyen sıradan metin (ne yaptığınız, hangi uygulamada olduğunuz) şifreli veritabanında saklanır.
- **Anahtar kaybı veri kaybıdır.** `key.bin` silinir veya farklı kullanıcı/makineye taşınırsa veritabanı açılamaz.
- **Canlı doğrulanmayanlar:** exclusive fullscreen oyun senaryosu, `Alt+Space` etkileşimi, ekran gizlemenin gerçek bir kayıt aracıyla görsel teyidi elle denenmedi.

## Güvenlik doğrulama komutları

```
cargo test -p s-guard
cargo test -p s-redteam -- --include-ignored
cargo test -p s-types
cd tests/security && cargo test
```

Gate 1: `cargo test -p s-redteam -- --include-ignored`. Gate 2: `tests/security` (`gate2-app`, `--features gate2-hooks` ile derlenmiş ikili).
