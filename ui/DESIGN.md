# Synapse Mind Hafıza Paneli — Görsel Sistem (`DESIGN.md`)

## 1. Görsel Dünya ve Yön

- **Kimlik:** *Quiet Fluent Vault* (Sakin Yerel Kasa) — Windows 11'de yerli hissettiren, gösterişsiz ama yüksek zanaatlı yerel güvenlik ve hafıza aracı.
- **Mod:** `Operate` (kullanıcı mevcut durumu doğrular, nedensellik zincirini okur ve yakalama/silme denetimlerini uygular).
- **Bilgi Mimarisi:** Windows 11 `NavigationView` sol gezinti şeridi (`Genel Bakış`, `Zaman ve Uygulamalar`, `Gizlilik ve Kalkan`, `Kontrol ve Sistem`) + ana çalışma alanı.
  - `Genel Bakış` en üstte tek, öne çıkan **"Bugünkü hafıza"** kahraman alanıyla açılır: büyük tipografiyle bugünkü olay sayısı, tek cümlelik gerçek özet (olay + maskelenen sır), sensör durumu, gün çizgisi (sparkline) ve tekrar etmeyen 3 destekleyici ölçüm (`Atılan pencere`, `Hafıza boyutu`, `Son arama`). Altında nedensellik zinciri, erişilebilir saatlik grafik, uygulamalar, okunur Türkçe adlarla `"Diske hiç ulaşmayanlar"` listesi, `"Kontrol sende"` ve `"Sistem"` yer alır.

## 2. Pencere Malzemesi (Mica / Acrylic / Düz Yedek)

- **Windows 11 Mica:** `src-tauri/src/lib.rs` içinde `panel` penceresi `.transparent(true)` ve `tauri::window::Effect::Mica` ile başlatılır; `apply_panel_backdrop` `DWMSBT_MAINWINDOW` (Mica) → `DWMSBT_TRANSIENTWINDOW` (Acrylic) → opak CSS tuvali sırasıyla geri düşer ve yalnızca durumu loglar.
- **Yarı Saydam Yüzeyler ve Kontrast:** `html, body { background: transparent; }` üzerinde `--bg-canvas`, `--bg-rail` ve `--bg-surface` yüksek opaklıklı yarı saydam RGBA katmanları (`0.66–0.88`) kullanır. En kötü durum (saf siyah veya saf beyaz masaüstü duvar kağıdı) üzerinde bile gövde metinleri `≥ 4.5:1` kontrastı korur.

## 3. Renk Token'ları (WCAG AA ≥ 4.5:1 Doğrulanmış)

### Açık Tema (`:root`)

| Token | Değer | Kullanım |
|---|---|---|
| `--bg-canvas` | `rgba(243, 245, 248, 0.78)` | Pencere tuvali (Mica üzeri yarı saydam örtü) |
| `--bg-rail` | `rgba(234, 239, 246, 0.66)` | Sol `NavigationView` şeridi |
| `--bg-surface` | `rgba(255, 255, 255, 0.88)` | Birincil çalışma katmanı |
| `--bg-subtle` | `rgba(247, 249, 252, 0.86)` | İkincil satır ve liste katmanı |
| `--fg-primary` | `#111827` | Ana metin ve sayısal değerler |
| `--fg-secondary` | `#475569` | Yardımcı açıklamalar |
| `--fg-muted` | `#576071` | Eksen, zaman damgası, alt etiketler |
| `--border-subtle` | `rgba(17, 24, 39, 0.10)` | İnce katman ayraçları |
| `--border-strong` | `rgba(17, 24, 39, 0.18)` | Girdi ve düğme kenarlıkları |
| `--accent` | `#005FB8` | Windows 11 Fluent birincil vurgu |
| `--accent-hover` | `#004C97` | Vurgu üzerine gelme durumu |
| `--on-accent` | `#FFFFFF` | Vurgu üzeri metin |
| `--accent-soft` | `rgba(0, 95, 184, 0.10)` | Seçili sekme/eleman arka planı |
| `--state-active-fg` / `-bg` / `-bd` | `#146C43` / `#E8F5EE` / `#A3D9BE` | Aktif yakalama durumu |
| `--state-batch-fg` / `-bg` / `-bd` | `#8A4B08` / `#FEF3E2` / `#F2CC8F` | Pil modu (biriktirme) |
| `--state-pause-fg` / `-bg` / `-bd` | `#475569` / `#EEF2F6` / `#CBD5E1` | Askıda / duraklatıldı |
| `--danger-fg` / `-bg` / `-bd` | `#B42318` / `#FEF2F2` / `#F5B7B1` | Kalıcı silme ve hata durumu |

### Koyu Tema (`:root[data-theme="dark"]`)

| Token | Değer | Kullanım |
|---|---|---|
| `--bg-canvas` | `rgba(22, 25, 31, 0.78)` | Pencere tuvali (Mica üzeri yarı saydam örtü) |
| `--bg-rail` | `rgba(16, 18, 24, 0.68)` | Sol gezinti şeridi |
| `--bg-surface` | `rgba(32, 35, 43, 0.88)` | Birincil çalışma katmanı |
| `--bg-subtle` | `rgba(38, 42, 52, 0.88)` | İkincil satır/liste katmanı |
| `--fg-primary` | `#F1F5F9` | Ana metin |
| `--fg-secondary` | `#C7D0DD` | İkincil metin |
| `--fg-muted` | `#B0BACB` | Eksen ve etiket metni (Mica üzerinde ≥ 4.6:1) |
| `--border-subtle` | `rgba(241, 245, 249, 0.10)` | İnce katman ayraçları |
| `--border-strong` | `rgba(241, 245, 249, 0.18)` | Girdi ve düğme kenarlıkları |
| `--accent` | `#60CDFF` | Windows 11 koyu Fluent vurgu |
| `--accent-hover` | `#7AD6FF` | Vurgu hover |
| `--on-accent` | `#09131C` | Vurgu üzeri koyu metin |
| `--accent-soft` | `rgba(96, 205, 255, 0.14)` | Seçili öğe arka planı |
| `--state-active-fg` / `-bg` / `-bd` | `#6EE7B7` / `rgba(16, 185, 129, 0.14)` / `rgba(110, 231, 183, 0.36)` | Aktif yakalama |
| `--state-batch-fg` / `-bg` / `-bd` | `#FCD34D` / `rgba(245, 158, 11, 0.14)` / `rgba(252, 211, 77, 0.36)` | Pil modu |
| `--state-pause-fg` / `-bg` / `-bd` | `#CBD5E1` / `rgba(148, 163, 184, 0.14)` / `rgba(203, 213, 225, 0.32)` | Askıda / duraklatıldı |
| `--danger-fg` / `-bg` / `-bd` | `#FCA5A5` / `rgba(239, 68, 68, 0.14)` / `rgba(252, 165, 165, 0.38)` | Silme / hata |

## 4. Tipografi

- **Ana arayüz ailesi:** `"Segoe UI Variable Display", "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, sans-serif` (harici font yok).
- **Ölçüm / etiket / kod ailesi:** `"Cascadia Mono", "Cascadia Code", Consolas, ui-monospace, monospace` (zaman damgası, olay kimliği, teknik maske ipucu ve süreç adlarında).
- **Ölçek (`rem`):**
  - Kahraman olay sayısı: `2.75rem` (`44px`), `600`, `tabular-nums`, `-0.025em`
  - Sayfa başlığı (`h1`): `1.5rem` (`24px`), `600`, satır yüksekliği `1.2`
  - Bölüm başlığı (`h2`): `1.0625rem` (`17px`), `600`
  - Alt başlık (`h3`): `0.875rem` (`14px`), `600`
  - Destekleyici ölçüm değeri: `1.25rem` (`20px`), `600`, `tabular-nums`
  - Gövde metni: `0.875rem` (`14px`), `1.5` satır yüksekliği (`65–75ch` azami genişlik)
  - Mikro veri / eksen: `0.75rem` (`12px`), `tabular-nums`

## 5. Boşluk, Köşe, Gölge ve Hareket

- **Boşluk ritmi:** `4px` taban birimi (`--space-1: 4px` … `--space-6: 24px`).
- **Köşeler:** `--radius-sm: 6px`, `--radius-md: 8px`, `--radius-lg: 12px`.
- **Gölgeler:**
  - Açık: `0 1px 3px rgba(15, 23, 42, 0.05)`
  - Koyu: `0 2px 10px rgba(0, 0, 0, 0.28)`
- **Hareket:** Durum geçişleri `150ms cubic-bezier(0.16, 1, 0.3, 1)`. `@media (prefers-reduced-motion: reduce)` altında tüm animasyon ve geçişler sıfırlanır.
