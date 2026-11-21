/// <reference types="vite/client" />
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { EmbedderStatusDto, HitDto } from "./main";

interface SensorStatusDto {
  state: "active" | "batching" | "suspended" | "unavailable";
  paused: boolean;
  pause_remaining_secs: number | null;
}

interface HourlyCountDto {
  hour: number;
  count: number;
}

interface AppCountDto {
  process_name: string;
  count: number;
}

interface TagCountDto {
  tag: string;
  label: string;
  count: number;
}

interface DropCountDto {
  reason: string;
  count: number;
}

interface MemoryPanelDto {
  sensor: SensorStatusDto;
  total_events: number;
  redactions_total: number;
  dropped_total: number;
  user_blocked_count: number;
  db_bytes: number | null;
  events_by_hour: HourlyCountDto[];
  top_apps: AppCountDto[];
  latest_chain: HitDto | null;
  redactions_by_kind: TagCountDto[];
  dropped_by_reason: DropCountDto[];
  user_blocklist: string[];
  last_search_ms: number | null;
  app_memory_bytes: number | null;
  embedder_label: string;
  embedder_status: EmbedderStatusDto;
  autostart_enabled: boolean;
  is_demo: boolean;
  version: string;
}

type ViewId = "overview" | "activity" | "privacy" | "controls";

const DROP_REASON_LABELS: Record<string, string> = {
  blacklisted_process: "Kara listedeki uygulama / süreç",
  private_window: "Gizli sekme (InPrivate / Incognito)",
  sensitive_file: "Hassas dosya / yol (.env, anahtar)",
  ignored_format: "Yok sayılan pano biçimi",
};

const workspaceEl = document.getElementById("workspace") as HTMLElement;
const loadingSkeletonEl = document.getElementById("loading-skeleton") as HTMLElement;
const memoryHeroEl = document.getElementById("memory-hero") as HTMLElement;
const contentGridEl = document.getElementById("content-grid") as HTMLElement;
const errorBannerEl = document.getElementById("error-banner") as HTMLElement;
const errorMessageEl = document.getElementById("error-message") as HTMLElement;
const retryBtn = document.getElementById("retry-btn") as HTMLButtonElement;

const todayDateEl = document.getElementById("today-date") as HTMLElement;
const statePillEl = document.getElementById("state-pill") as HTMLElement;
const stateLabelEl = document.getElementById("state-label") as HTMLElement;
const demoPillEl = document.getElementById("demo-pill") as HTMLElement;
const themeToggleBtn = document.getElementById("theme-toggle-btn") as HTMLButtonElement;
const refreshBtn = document.getElementById("refresh-btn") as HTMLButtonElement;

const noticeBannerEl = document.getElementById("notice-banner") as HTMLElement;
const noticeMessageEl = document.getElementById("notice-message") as HTMLElement;
const noticeResumeBtn = document.getElementById("notice-resume-btn") as HTMLButtonElement;
const embedderBannerEl = document.getElementById("embedder-banner") as HTMLElement;
const embedderMessageEl = document.getElementById("embedder-message") as HTMLElement;
const embedderSubtextEl = document.getElementById("embedder-subtext") as HTMLElement;
const embedderProgressTrackEl = document.getElementById("embedder-progress-track") as HTMLElement;
const embedderProgressFillEl = document.getElementById("embedder-progress-fill") as HTMLElement;
const embedderRetryBtn = document.getElementById("embedder-retry-btn") as HTMLButtonElement;

const heroEventsEl = document.getElementById("hero-events") as HTMLElement;
const heroSummaryEl = document.getElementById("hero-summary") as HTMLElement;
const heroSensorBadgeEl = document.getElementById("hero-sensor-badge") as HTMLElement;
const heroSparkLabelEl = document.getElementById("hero-spark-label") as HTMLElement;
const heroSparklineEl = document.getElementById("hero-sparkline") as unknown as SVGSVGElement;

const kpiDroppedEl = document.getElementById("kpi-dropped") as HTMLElement;
const kpiDroppedNoteEl = document.getElementById("kpi-dropped-note") as HTMLElement;
const kpiDbSizeEl = document.getElementById("kpi-db-size") as HTMLElement;
const kpiLastSearchEl = document.getElementById("kpi-last-search") as HTMLElement;

const chainWindowEl = document.getElementById("chain-window") as HTMLElement;
const chainListEl = document.getElementById("chain-list") as HTMLOListElement;
const chainEmptyEl = document.getElementById("chain-empty") as HTMLElement;
const openChainBtn = document.getElementById("open-chain-btn") as HTMLButtonElement;
const searchSimilarBtn = document.getElementById("search-similar-btn") as HTMLButtonElement;
const chainDetailsEl = document.getElementById("chain-details") as HTMLElement;

const hourlySectionEl = document.getElementById("hourly-section") as HTMLElement;
const hourlyChartWrapEl = document.getElementById("hourly-chart-wrap") as HTMLElement;
const hourlyBarsEl = document.getElementById("hourly-bars") as HTMLElement;
const hourlyLabelsEl = document.getElementById("hourly-labels") as HTMLElement;
const hourlyMetaEl = document.getElementById("hourly-meta") as HTMLElement;
const hourlySummaryEl = document.getElementById("hourly-summary") as HTMLElement;
const hourlySrSummaryEl = document.getElementById("hourly-sr-summary") as HTMLElement;
const appsListEl = document.getElementById("apps-list") as HTMLElement;
const appsEmptyEl = document.getElementById("apps-empty") as HTMLElement;

const redactionsListEl = document.getElementById("redactions-list") as HTMLElement;
const droppedListEl = document.getElementById("dropped-list") as HTMLElement;
const systemListEl = document.getElementById("system-list") as HTMLElement;

const pauseToggleBtn = document.getElementById("pause-toggle-btn") as HTMLButtonElement;
const pauseBtnTitleEl = document.getElementById("pause-btn-title") as HTMLElement;
const pauseBtnHintEl = document.getElementById("pause-btn-hint") as HTMLElement;
const blocklistToggleBtn = document.getElementById("blocklist-toggle-btn") as HTMLButtonElement;
const blocklistDrawerEl = document.getElementById("blocklist-drawer") as HTMLElement;
const blocklistFormEl = document.getElementById("blocklist-form") as HTMLFormElement;
const blocklistInputEl = document.getElementById("blocklist-input") as HTMLInputElement;
const blocklistCancelBtn = document.getElementById("blocklist-cancel-btn") as HTMLButtonElement;
const blocklistChipsEl = document.getElementById("blocklist-chips") as HTMLElement;
const deleteRecentBtn = document.getElementById("delete-recent-btn") as HTMLButtonElement;
const deleteAllOpenBtn = document.getElementById("delete-all-open-btn") as HTMLButtonElement;
const deleteAllConfirmEl = document.getElementById("delete-all-confirm") as HTMLElement;
const deleteAllConfirmBtn = document.getElementById("delete-all-confirm-btn") as HTMLButtonElement;
const deleteAllCancelBtn = document.getElementById("delete-all-cancel-btn") as HTMLButtonElement;
const controlFeedbackEl = document.getElementById("control-feedback") as HTMLElement;
const autostartToggleBtn = document.getElementById("autostart-toggle-btn") as HTMLButtonElement;
const autostartStateTextEl = document.getElementById("autostart-state-text") as HTMLElement;
const autostartFeedbackEl = document.getElementById("autostart-feedback") as HTMLElement;

const navButtons = Array.from(document.querySelectorAll<HTMLButtonElement>(".nav-item[data-view]"));
const viewSections = Array.from(document.querySelectorAll<HTMLElement>("[data-views]"));

let latestChainHit: HitDto | null = null;
let chainExpanded = false;
let isSensorPaused = false;
let isAutostartEnabled = false;
let activeView: ViewId = "overview";
let loadedOnce = false;

function formatNumber(n: number): string {
  return n.toLocaleString("tr-TR");
}

function formatBytes(bytes: number | null): string {
  if (bytes === null) {
    return "Bellek içi";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const kb = bytes / 1024;
  if (kb < 1024) {
    return `${kb.toFixed(1)} KB`;
  }
  const mb = kb / 1024;
  return `${mb.toFixed(mb >= 10 ? 0 : 1)} MB`;
}

function formatClock(tsMs: number): string {
  const d = new Date(tsMs);
  if (Number.isNaN(d.getTime())) {
    return "—";
  }
  return d.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
}

function formatDurationMinutes(secs: number | null): string {
  if (secs === null) {
    return "";
  }
  const mins = Math.max(1, Math.ceil(secs / 60));
  return `${mins} dk kaldı`;
}

function showFeedback(message: string): void {
  controlFeedbackEl.textContent = message;
  controlFeedbackEl.classList.remove("hidden");
}

function isDevBrowserPreview(): boolean {
  if (!import.meta.env.DEV) {
    return false;
  }
  const tauriPresent =
    typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !==
    "undefined";
  return !tauriPresent && Boolean(new URLSearchParams(window.location.search).get("preview"));
}

function setTheme(dark: boolean): void {
  if (dark) {
    document.documentElement.setAttribute("data-theme", "dark");
    themeToggleBtn.textContent = "Açık görünüm";
  } else {
    document.documentElement.removeAttribute("data-theme");
    themeToggleBtn.textContent = "Koyu görünüm";
  }
  if (isDevBrowserPreview()) {
    document.documentElement.style.background = dark ? "#12151B" : "#E5EBF3";
  }
}

function applyView(view: ViewId): void {
  activeView = view;
  for (const btn of navButtons) {
    const selected = btn.dataset.view === view;
    btn.classList.toggle("active", selected);
    btn.setAttribute("aria-selected", String(selected));
  }

  for (const section of viewSections) {
    const targets = (section.dataset.views ?? "").split(/\s+/);
    section.classList.toggle("hidden", !targets.includes(view));
  }

  contentGridEl.classList.toggle("single-column", view !== "overview");
}

function renderSensorState(sensor: SensorStatusDto): void {
  isSensorPaused = sensor.paused;

  if (sensor.paused) {
    statePillEl.setAttribute("data-state", "paused");
    const remaining = formatDurationMinutes(sensor.pause_remaining_secs);
    stateLabelEl.textContent = remaining
      ? `Duraklatıldı · ${remaining}`
      : "Duraklatıldı · kullanıcı kararı";
    noticeBannerEl.setAttribute("data-state", "paused");
    noticeMessageEl.textContent =
      "Yakalama kullanıcı tarafından geçici olarak duraklatıldı. Süre dolduğunda ya da devam ettirdiğinizde kendiliğinden sürer.";
    noticeResumeBtn.classList.remove("hidden");
    noticeBannerEl.classList.remove("hidden");
    pauseBtnTitleEl.textContent = "Yakalamayı şimdi devam ettir";
    pauseBtnHintEl.textContent = remaining
      ? `Kalan duraklatma süresi: ${remaining}`
      : "Sensör yakalamasını anında başlatır";
    return;
  }

  statePillEl.setAttribute("data-state", sensor.state);
  noticeResumeBtn.classList.add("hidden");
  pauseBtnTitleEl.textContent = "Yakalamayı 1 saat duraklat";
  pauseBtnHintEl.textContent = "Süre dolunca otomatik devam eder";

  if (sensor.state === "suspended") {
    stateLabelEl.textContent = "Askıda · tam ekran / yüksek GPU";
    noticeBannerEl.setAttribute("data-state", "suspended");
    noticeMessageEl.textContent =
      "Tam ekran uygulama veya yüksek GPU yükü algılandı. Sensörler ve indeksleme duraklatıldı; çıkışta kendiliğinden devam eder.";
    noticeBannerEl.classList.remove("hidden");
  } else if (sensor.state === "batching") {
    stateLabelEl.textContent = "Biriktiriyor · pil modu";
    noticeBannerEl.setAttribute("data-state", "batching");
    noticeMessageEl.textContent =
      "Pil modundasınız. Olaylar bellekte bekletiliyor ve AC gücüne dönünce işlenecek.";
    noticeBannerEl.classList.remove("hidden");
  } else if (sensor.state === "unavailable") {
    stateLabelEl.textContent = "Sensör kapalı";
    noticeBannerEl.setAttribute("data-state", "suspended");
    noticeMessageEl.textContent =
      "Sensör hattı bu oturumda başlatılamadı; kayıtlı hafıza salt okunur aranabilir durumda.";
    noticeBannerEl.classList.remove("hidden");
  } else {
    stateLabelEl.textContent = "Aktif · olaylar yakalanıyor";
    noticeBannerEl.classList.add("hidden");
  }
}

function renderHeroSparkline(buckets: HourlyCountDto[], isEmpty: boolean): void {
  heroSparklineEl.replaceChildren();
  const ns = "http://www.w3.org/2000/svg";

  if (isEmpty) {
    const line = document.createElementNS(ns, "line");
    line.setAttribute("x1", "2");
    line.setAttribute("y1", "34");
    line.setAttribute("x2", "198");
    line.setAttribute("y2", "34");
    line.setAttribute("stroke", "var(--border-strong)");
    line.setAttribute("stroke-width", "1.5");
    line.setAttribute("stroke-dasharray", "4 4");
    heroSparklineEl.appendChild(line);
    return;
  }

  const map = new Map<number, number>();
  for (const b of buckets) {
    map.set(b.hour, b.count);
  }
  const currentHour = new Date().getHours();
  let minHour = 8;
  let maxHour = Math.max(18, currentHour);
  for (const h of map.keys()) {
    minHour = Math.min(minHour, h);
    maxHour = Math.max(maxHour, h);
  }

  const counts: number[] = [];
  for (let h = minHour; h <= maxHour; h += 1) {
    counts.push(map.get(h) ?? 0);
  }
  const peak = Math.max(1, ...counts);
  const w = 196;
  const h = 34;
  const stepX = counts.length > 1 ? w / (counts.length - 1) : w;

  const points: [number, number][] = counts.map((val, idx) => {
    const x = 2 + idx * stepX;
    const y = 4 + (1 - val / peak) * (h - 2);
    return [Number(x.toFixed(1)), Number(y.toFixed(1))];
  });

  const area = document.createElementNS(ns, "polygon");
  const areaPoints = [
    `${points[0][0]},40`,
    ...points.map(([x, y]) => `${x},${y}`),
    `${points[points.length - 1][0]},40`,
  ].join(" ");
  area.setAttribute("points", areaPoints);
  area.setAttribute("fill", "var(--accent)");
  area.setAttribute("fill-opacity", "0.14");

  const polyline = document.createElementNS(ns, "polyline");
  polyline.setAttribute("points", points.map(([x, y]) => `${x},${y}`).join(" "));
  polyline.setAttribute("fill", "none");
  polyline.setAttribute("stroke", "var(--accent)");
  polyline.setAttribute("stroke-width", "2");
  polyline.setAttribute("stroke-linecap", "round");
  polyline.setAttribute("stroke-linejoin", "round");

  heroSparklineEl.append(area, polyline);
}

function renderHero(data: MemoryPanelDto): void {
  heroEventsEl.textContent = formatNumber(data.total_events);

  if (data.sensor.paused) {
    memoryHeroEl.setAttribute("data-hero-state", "paused");
    const remaining = formatDurationMinutes(data.sensor.pause_remaining_secs);
    heroSensorBadgeEl.textContent = remaining ? `Duraklatıldı · ${remaining}` : "Duraklatıldı";
    heroSummaryEl.textContent =
      data.total_events === 0
        ? "Yakalama kullanıcı tarafından duraklatıldı; devam ettirildiğinde odak, pano ve metin değişimleri kaydedilir."
        : `Yakalama duraklatıldı; bugün ${formatNumber(
            data.total_events
          )} olay kaydedildi ve ${formatNumber(
            data.redactions_total
          )} gizli bilgi diske ulaşmadan maskelendi.`;
  } else if (data.total_events === 0) {
    memoryHeroEl.setAttribute("data-hero-state", "empty");
    heroSensorBadgeEl.textContent =
      data.sensor.state === "suspended"
        ? "Askıda"
        : data.sensor.state === "batching"
          ? "Biriktiriyor"
          : "Aktif · izleniyor";
    heroSummaryEl.textContent =
      "Bugün henüz olay kaydedilmedi; pencere odağı, pano ve metin değişimleri yakalandıkça burada görünür.";
  } else if (data.sensor.state === "suspended") {
    memoryHeroEl.setAttribute("data-hero-state", "paused");
    heroSensorBadgeEl.textContent = "Askıda · tam ekran / GPU";
    heroSummaryEl.textContent = `Bugün ${formatNumber(
      data.total_events
    )} olay kaydedildi; ${formatNumber(
      data.redactions_total
    )} gizli bilgi diske ulaşmadan maskelendi.`;
  } else if (data.sensor.state === "batching") {
    memoryHeroEl.setAttribute("data-hero-state", "batching");
    heroSensorBadgeEl.textContent = "Biriktiriyor · pil modu";
    heroSummaryEl.textContent = `Bugün ${formatNumber(
      data.total_events
    )} olay kaydedildi; ${formatNumber(
      data.redactions_total
    )} gizli bilgi diske ulaşmadan maskelendi.`;
  } else {
    memoryHeroEl.setAttribute("data-hero-state", "active");
    heroSensorBadgeEl.textContent = "Aktif · yakalanıyor";
    heroSummaryEl.textContent = `Bugün ${formatNumber(
      data.total_events
    )} olay kaydedildi; ${formatNumber(
      data.redactions_total
    )} gizli bilgi diske ulaşmadan maskelendi.`;
  }

  heroSparkLabelEl.textContent = data.total_events === 0 ? "Kayıt bekleniyor" : "Gün çizgisi";
  renderHeroSparkline(data.events_by_hour, data.total_events === 0);

  kpiDroppedEl.textContent = formatNumber(data.dropped_total);
  kpiDroppedNoteEl.textContent =
    data.user_blocklist.length > 0
      ? `Parola yöneticisi, gizli sekme · +${data.user_blocklist.length} engel`
      : "Parola yöneticisi, gizli sekme, .env";
  kpiDbSizeEl.textContent = formatBytes(data.db_bytes);
  kpiLastSearchEl.textContent =
    data.last_search_ms === null ? "Henüz yok" : `${data.last_search_ms.toFixed(1)} ms`;
}

function renderChain(hit: HitDto | null): void {
  latestChainHit = hit;
  chainExpanded = false;
  chainDetailsEl.classList.add("hidden");
  chainDetailsEl.replaceChildren();
  chainListEl.replaceChildren();

  if (!hit) {
    chainWindowEl.textContent = "Son nedensellik zinciri · yok";
    chainEmptyEl.classList.remove("hidden");
    openChainBtn.disabled = true;
    searchSimilarBtn.disabled = true;
    return;
  }

  chainEmptyEl.classList.add("hidden");
  openChainBtn.disabled = false;
  searchSimilarBtn.disabled = false;
  openChainBtn.textContent = "Zinciri aç";
  chainWindowEl.textContent = `Son nedensellik zinciri · ${formatClock(hit.timestamp_ms)}`;

  interface ChainStep {
    time: string;
    app: string;
    kind: string;
    text: string;
    edge: string;
  }

  const steps: ChainStep[] = [
    {
      time: formatClock(hit.timestamp_ms),
      app: hit.matched_app,
      kind: `olay #${hit.event_id}`,
      text: hit.summary_snippet,
      edge: "",
    },
    ...hit.causality_chain.map((edge) => ({
      time: `+${edge.time_delta_seconds}s`,
      app: `Olay #${edge.source_event_id} → #${edge.target_event_id}`,
      kind: "nedensellik bağı",
      text: edge.relationship,
      edge: `${edge.time_delta_seconds} sn aralığında bağlandı`,
    })),
  ];

  const fragment = document.createDocumentFragment();
  steps.forEach((step, idx) => {
    const li = document.createElement("li");
    li.className = "chain-item";

    const timeEl = document.createElement("span");
    timeEl.className = "chain-time";
    timeEl.textContent = step.time;

    const railCol = document.createElement("span");
    railCol.className = "chain-rail-col";

    const dot = document.createElement("span");
    dot.className = "chain-dot";
    dot.setAttribute("aria-hidden", "true");

    const rail = document.createElement("span");
    rail.className = idx === steps.length - 1 ? "chain-rail chain-rail-end" : "chain-rail";
    rail.setAttribute("aria-hidden", "true");
    railCol.append(dot, rail);

    const body = document.createElement("span");
    body.className = "chain-body";

    const appLine = document.createElement("span");
    appLine.className = "chain-app";
    appLine.textContent = `${step.app} `;
    const kindSpan = document.createElement("span");
    kindSpan.className = "chain-kind";
    kindSpan.textContent = `· ${step.kind}`;
    appLine.appendChild(kindSpan);

    const textEl = document.createElement("span");
    textEl.className = "chain-text";
    textEl.textContent = step.text;

    body.append(appLine, textEl);
    if (step.edge) {
      const edgeEl = document.createElement("span");
      edgeEl.className = "chain-edge";
      edgeEl.textContent = step.edge;
      body.appendChild(edgeEl);
    }

    li.append(timeEl, railCol, body);
    fragment.appendChild(li);
  });

  chainListEl.appendChild(fragment);
}

function renderHourlyChart(buckets: HourlyCountDto[], sensor: SensorStatusDto): void {
  hourlyBarsEl.replaceChildren();
  hourlyLabelsEl.replaceChildren();

  const totalToday = buckets.reduce((acc, b) => acc + b.count, 0);
  if (totalToday === 0) {
    hourlyChartWrapEl.classList.add("hidden");
    hourlyMetaEl.textContent = "Saat başına olay";
    hourlySummaryEl.textContent = "Bugün henüz saatlik olay kaydedilmedi.";
    hourlySrSummaryEl.textContent = "Bugün kayıt yok";
    hourlySectionEl.setAttribute("aria-label", "Gün boyu yakalanan olaylar: Bugün kayıt yok");
    return;
  }

  hourlyChartWrapEl.classList.remove("hidden");

  const map = new Map<number, number>();
  for (const b of buckets) {
    map.set(b.hour, b.count);
  }

  const currentHour = new Date().getHours();
  let minHour = 8;
  let maxHour = Math.max(18, currentHour);
  for (const h of map.keys()) {
    minHour = Math.min(minHour, h);
    maxHour = Math.max(maxHour, h);
  }

  const hours: number[] = [];
  for (let h = minHour; h <= maxHour; h += 1) {
    hours.push(h);
  }

  const colsTemplate = `repeat(${hours.length}, minmax(0, 1fr))`;
  hourlyBarsEl.style.gridTemplateColumns = colsTemplate;
  hourlyLabelsEl.style.gridTemplateColumns = colsTemplate;

  const peak = Math.max(1, ...hours.map((h) => map.get(h) ?? 0));
  let peakHour = hours[0];
  for (const h of hours) {
    if ((map.get(h) ?? 0) > (map.get(peakHour) ?? 0)) {
      peakHour = h;
    }
  }

  const barsFrag = document.createDocumentFragment();
  const labelsFrag = document.createDocumentFragment();

  for (const h of hours) {
    const count = map.get(h) ?? 0;
    const isPausedNow = h === currentHour && (sensor.paused || sensor.state === "suspended");
    const hourStr = `${String(h).padStart(2, "0")}:00`;

    const col = document.createElement("div");
    col.className = "hourly-bar-col";
    col.setAttribute("role", "listitem");
    col.setAttribute("tabindex", "0");
    col.setAttribute(
      "aria-label",
      isPausedNow && count === 0
        ? `Saat ${hourStr}, yakalama askıda veya duraklatıldı`
        : `Saat ${hourStr}, ${formatNumber(count)} olay`
    );

    const bar = document.createElement("span");
    if (count > 0) {
      const countSpan = document.createElement("span");
      countSpan.className = "hourly-count";
      countSpan.textContent = String(count);
      col.appendChild(countSpan);

      bar.className = "hourly-fill";
      const px = Math.max(8, Math.round((count / peak) * 108));
      bar.style.height = `${px}px`;
    } else if (isPausedNow) {
      bar.className = "hourly-fill-paused";
    } else {
      bar.className = "hourly-fill-zero";
    }

    col.appendChild(bar);
    barsFrag.appendChild(col);

    const lbl = document.createElement("span");
    lbl.className = "hourly-label";
    lbl.textContent = String(h).padStart(2, "0");
    labelsFrag.appendChild(lbl);
  }

  hourlyBarsEl.appendChild(barsFrag);
  hourlyLabelsEl.appendChild(labelsFrag);

  const summaryText = `En yoğun saat ${String(peakHour).padStart(2, "0")}:00, ${formatNumber(
    map.get(peakHour) ?? 0
  )} olay.`;
  hourlyMetaEl.textContent = "Saat başına olay";
  hourlySummaryEl.textContent = summaryText;
  hourlySrSummaryEl.textContent = summaryText;
  hourlySectionEl.setAttribute("aria-label", `Gün boyu yakalanan olaylar: ${summaryText}`);
}

function renderApps(apps: AppCountDto[]): void {
  appsListEl.replaceChildren();
  if (apps.length === 0) {
    appsEmptyEl.classList.remove("hidden");
    return;
  }
  appsEmptyEl.classList.add("hidden");

  const maxCount = Math.max(1, apps[0].count);
  const frag = document.createDocumentFragment();

  for (const app of apps) {
    const row = document.createElement("div");
    row.className = "app-row";

    const nameEl = document.createElement("span");
    nameEl.className = "app-name";
    nameEl.textContent = app.process_name;

    const track = document.createElement("span");
    track.className = "app-track";
    const bar = document.createElement("span");
    bar.className = "app-bar";
    bar.style.width = `${Math.max(4, Math.round((app.count / maxCount) * 100))}%`;
    track.appendChild(bar);

    const countEl = document.createElement("span");
    countEl.className = "app-count";
    countEl.textContent = formatNumber(app.count);

    row.append(nameEl, track, countEl);
    frag.appendChild(row);
  }

  appsListEl.appendChild(frag);
}

function renderPrivacy(data: MemoryPanelDto): void {
  redactionsListEl.replaceChildren();
  const redFrag = document.createDocumentFragment();
  for (const item of data.redactions_by_kind) {
    const row = document.createElement("div");
    row.className = "ledger-row";
    row.title = item.tag;

    const titleGroup = document.createElement("div");
    titleGroup.className = "redaction-title-group";

    const labelEl = document.createElement("span");
    labelEl.className = "redaction-label";
    labelEl.textContent = item.label;

    const tagHint = document.createElement("span");
    tagHint.className = "redaction-tag-hint";
    tagHint.textContent = item.tag;

    titleGroup.append(labelEl, tagHint);

    const v = document.createElement("span");
    v.className = "redaction-count";
    v.textContent = formatNumber(item.count);

    row.append(titleGroup, v);
    redFrag.appendChild(row);
  }
  redactionsListEl.appendChild(redFrag);

  droppedListEl.replaceChildren();
  const dropFrag = document.createDocumentFragment();
  for (const item of data.dropped_by_reason) {
    const row = document.createElement("div");
    row.className = "kv-row";
    const k = document.createElement("span");
    k.className = "kv-key";
    k.textContent = DROP_REASON_LABELS[item.reason] ?? item.reason;
    const v = document.createElement("span");
    v.className = "kv-val";
    v.textContent = formatNumber(item.count);
    row.append(k, v);
    dropFrag.appendChild(row);
  }
  if (data.user_blocked_count > 0 || data.user_blocklist.length > 0) {
    const row = document.createElement("div");
    row.className = "kv-row";
    const k = document.createElement("span");
    k.className = "kv-key";
    k.textContent = "Kullanıcı engeli";
    const v = document.createElement("span");
    v.className = "kv-val";
    v.textContent = formatNumber(data.user_blocked_count);
    row.append(k, v);
    dropFrag.appendChild(row);
  }
  droppedListEl.appendChild(dropFrag);
}

function renderBlocklist(items: string[]): void {
  blocklistChipsEl.replaceChildren();
  if (items.length === 0) {
    const note = document.createElement("span");
    note.className = "panel-meta";
    note.textContent = "Ekli kullanıcı engeli yok.";
    blocklistChipsEl.appendChild(note);
    return;
  }

  const frag = document.createDocumentFragment();
  for (const name of items) {
    const chip = document.createElement("span");
    chip.className = "block-chip";

    const label = document.createElement("span");
    label.textContent = name;

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "block-chip-remove";
    removeBtn.setAttribute("aria-label", `${name} engelini kaldır`);
    removeBtn.textContent = "×";
    removeBtn.addEventListener("click", () => {
      void removeBlockedApp(name);
    });

    chip.append(label, removeBtn);
    frag.appendChild(chip);
  }
  blocklistChipsEl.appendChild(frag);
}

function renderSystem(data: MemoryPanelDto): void {
  systemListEl.replaceChildren();
  const rows: [string, string][] = [
    ["Embedding modeli", data.embedder_label],
    ["Bellek (daemon)", formatBytes(data.app_memory_bytes)],
    ["Ağ bağlantısı", "Yok · tamamen yerel"],
    ["Sürüm", `v${data.version}`],
  ];

  const frag = document.createDocumentFragment();
  for (const [key, value] of rows) {
    const row = document.createElement("div");
    row.className = "kv-row";

    const kEl = document.createElement("span");
    kEl.className = "kv-key";
    kEl.textContent = key;

    const vEl = document.createElement("span");
    vEl.className = "kv-val";
    vEl.textContent = value;

    row.append(kEl, vEl);
    frag.appendChild(row);
  }
  systemListEl.appendChild(frag);
}

function renderAutostart(enabled: boolean): void {
  isAutostartEnabled = enabled;
  autostartToggleBtn.setAttribute("aria-checked", String(enabled));
  autostartStateTextEl.textContent = enabled ? "Açık" : "Kapalı";
}

function renderEmbedderStatus(status: EmbedderStatusDto): void {
  if (status.state === "ready") {
    embedderBannerEl.classList.add("hidden");
    embedderBannerEl.removeAttribute("data-state");
    embedderRetryBtn.classList.add("hidden");
    return;
  }

  embedderBannerEl.classList.remove("hidden");
  embedderBannerEl.setAttribute("data-state", status.state);

  if (status.state === "failed") {
    embedderMessageEl.textContent =
      status.message ?? "Anlamsal arama kapalı, kelime araması çalışıyor";
    embedderSubtextEl.textContent = "BM25 tam metin ve nedensellik araması normal şekilde çalışır.";
    embedderProgressTrackEl.classList.add("hidden");
    embedderProgressTrackEl.classList.remove("indeterminate");
    embedderProgressTrackEl.removeAttribute("aria-valuenow");
    embedderRetryBtn.classList.remove("hidden");
    embedderRetryBtn.disabled = false;
    return;
  }

  embedderRetryBtn.classList.add("hidden");
  embedderProgressTrackEl.classList.remove("hidden");
  embedderMessageEl.textContent =
    status.state === "downloading"
      ? "Anlamsal arama modeli indiriliyor…"
      : "Anlamsal arama modeli hazırlanıyor…";

  if (status.progress_pct !== null && status.total !== null) {
    const clamped = Math.max(0, Math.min(100, status.progress_pct));
    embedderProgressTrackEl.classList.remove("indeterminate");
    embedderProgressTrackEl.setAttribute("aria-valuenow", String(clamped));
    embedderProgressFillEl.style.width = `${clamped}%`;
    const downloaded = formatBytes(status.bytes ?? 0);
    const total = formatBytes(status.total);
    embedderSubtextEl.textContent = `%${clamped} (${downloaded} / ${total}) · kelime araması bu sırada kullanılabilir`;
  } else {
    embedderProgressTrackEl.classList.add("indeterminate");
    embedderProgressTrackEl.removeAttribute("aria-valuenow");
    embedderProgressFillEl.style.width = "";
    embedderSubtextEl.textContent = "İlk kurulum dosyaları indiriliyor · kelime araması bu sırada kullanılabilir";
  }
}

function renderPanel(data: MemoryPanelDto): void {
  loadedOnce = true;
  workspaceEl.setAttribute("aria-busy", "false");
  loadingSkeletonEl.classList.add("hidden");
  errorBannerEl.classList.add("hidden");
  memoryHeroEl.classList.remove("hidden");
  contentGridEl.classList.remove("hidden");

  const formattedDay = new Date().toLocaleDateString("tr-TR", {
    day: "numeric",
    month: "long",
  });
  todayDateEl.textContent = `Bugün, ${formattedDay}`;
  demoPillEl.classList.toggle("hidden", !data.is_demo);

  renderEmbedderStatus(data.embedder_status);
  renderSensorState(data.sensor);
  renderHero(data);
  renderChain(data.latest_chain);
  renderHourlyChart(data.events_by_hour, data.sensor);
  renderApps(data.top_apps);
  renderPrivacy(data);
  renderBlocklist(data.user_blocklist);
  renderSystem(data);
  renderAutostart(data.autostart_enabled);
  applyView(activeView);
}

function buildDevPreviewFixture(mode: string, embedMode: string | null): MemoryPanelDto {
  const readyEmbed: EmbedderStatusDto = {
    state: "ready",
    bytes: null,
    total: null,
    progress_pct: 100,
    message: null,
  };
  const previewEmbed: EmbedderStatusDto =
    embedMode === "downloading" || mode === "downloading"
      ? {
          state: "downloading",
          bytes: 41_600_000,
          total: 67_100_000,
          progress_pct: 62,
          message: null,
        }
      : embedMode === "failed" || mode === "embed-error"
        ? {
            state: "failed",
            bytes: null,
            total: null,
            progress_pct: null,
            message: "Anlamsal arama kapalı, kelime araması çalışıyor",
          }
        : readyEmbed;

  const now = Date.now();
  if (mode === "empty") {
    return {
      sensor: { state: "active", paused: false, pause_remaining_secs: null },
      total_events: 0,
      redactions_total: 0,
      dropped_total: 0,
      user_blocked_count: 0,
      db_bytes: 86_016,
      events_by_hour: [],
      top_apps: [],
      latest_chain: null,
      redactions_by_kind: [
        { tag: "[REDACTED_API_KEY]", label: "API anahtarı", count: 0 },
        { tag: "[REDACTED_PASSWORD]", label: "Parola", count: 0 },
        { tag: "[REDACTED_EMAIL]", label: "E-posta", count: 0 },
        { tag: "[REDACTED_JWT]", label: "JWT / oturum belirteci", count: 0 },
        { tag: "[REDACTED_CREDIT_CARD]", label: "Kredi kartı", count: 0 },
        { tag: "[REDACTED_TC_KIMLIK]", label: "TC kimlik no", count: 0 },
        { tag: "[REDACTED_SSN]", label: "Kimlik / SSN numarası", count: 0 },
        { tag: "[REDACTED_PRIVATE_KEY]", label: "Özel anahtar (PEM)", count: 0 },
      ],
      dropped_by_reason: [
        { reason: "blacklisted_process", count: 0 },
        { reason: "private_window", count: 0 },
        { reason: "sensitive_file", count: 0 },
        { reason: "ignored_format", count: 0 },
      ],
      user_blocklist: [],
      last_search_ms: null,
      app_memory_bytes: 36_850_000,
      embedder_label: "bge-small-en-v1.5 (FP32+INT8) · yerel",
      embedder_status: previewEmbed,
      autostart_enabled: false,
      is_demo: true,
      version: "0.1.0",
    };
  }

  return {
    sensor:
      mode === "paused"
        ? { state: "suspended", paused: true, pause_remaining_secs: 3420 }
        : { state: "active", paused: false, pause_remaining_secs: null },
    total_events: 1099,
    redactions_total: 37,
    dropped_total: 12,
    user_blocked_count: 2,
    db_bytes: 48 * 1024 * 1024,
    events_by_hour: [
      { hour: 8, count: 34 },
      { hour: 9, count: 121 },
      { hour: 10, count: 168 },
      { hour: 11, count: 182 },
      { hour: 12, count: 0 },
      { hour: 13, count: 0 },
      { hour: 14, count: 147 },
      { hour: 15, count: 156 },
      { hour: 16, count: 98 },
      { hour: 17, count: 132 },
      { hour: 18, count: 61 },
    ],
    top_apps: [
      { process_name: "Code.exe", count: 412 },
      { process_name: "brave.exe", count: 287 },
      { process_name: "WindowsTerminal.exe", count: 164 },
      { process_name: "Obsidian.exe", count: 98 },
      { process_name: "msedge.exe", count: 61 },
    ],
    latest_chain: {
      event_id: 1099,
      timestamp_ms: now - 120_000,
      score: 1.0,
      summary_snippet: "win32_hook.rs içinde TreeCoalesceState bağlandı",
      matched_app: "Code.exe",
      causality_chain: [
        {
          source_event_id: 1096,
          target_event_id: 1097,
          relationship: "searched_after_error",
          time_delta_seconds: 15,
        },
        {
          source_event_id: 1097,
          target_event_id: 1098,
          relationship: "pasted_from_clipboard",
          time_delta_seconds: 45,
        },
        {
          source_event_id: 1098,
          target_event_id: 1099,
          relationship: "switched_app_after",
          time_delta_seconds: 10,
        },
      ],
    },
    redactions_by_kind: [
      { tag: "[REDACTED_API_KEY]", label: "API anahtarı", count: 14 },
      { tag: "[REDACTED_PASSWORD]", label: "Parola", count: 9 },
      { tag: "[REDACTED_EMAIL]", label: "E-posta", count: 8 },
      { tag: "[REDACTED_JWT]", label: "JWT / oturum belirteci", count: 3 },
      { tag: "[REDACTED_CREDIT_CARD]", label: "Kredi kartı", count: 2 },
      { tag: "[REDACTED_TC_KIMLIK]", label: "TC kimlik no", count: 1 },
      { tag: "[REDACTED_SSN]", label: "Kimlik / SSN numarası", count: 0 },
      { tag: "[REDACTED_PRIVATE_KEY]", label: "Özel anahtar (PEM)", count: 0 },
    ],
    dropped_by_reason: [
      { reason: "blacklisted_process", count: 7 },
      { reason: "private_window", count: 4 },
      { reason: "sensitive_file", count: 1 },
      { reason: "ignored_format", count: 0 },
    ],
    user_blocklist: ["slack"],
    last_search_ms: 14.2,
    app_memory_bytes: 36_850_000,
    embedder_label: "bge-small-en-v1.5 (FP32+INT8) · yerel",
    embedder_status: previewEmbed,
    autostart_enabled: false,
    is_demo: true,
    version: "0.1.0",
  };
}

async function refreshPanel(): Promise<void> {
  if (import.meta.env.DEV) {
    const tauriPresent =
      typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !==
      "undefined";
    const params = new URLSearchParams(window.location.search);
    const previewMode = params.get("preview");
    const embedPreview = params.get("embed");
    if (!tauriPresent && previewMode) {
      if (previewMode === "dark") {
        setTheme(true);
      } else {
        setTheme(false);
      }
      renderPanel(buildDevPreviewFixture(previewMode, embedPreview));
      return;
    }
  }

  try {
    // JS getTimezoneOffset() is minutes behind UTC (e.g. -180 for UTC+3);
    // s-core expects positive minutes ahead of UTC (+180).
    const tzOffsetMinutes = -new Date().getTimezoneOffset();
    const data = await invoke<MemoryPanelDto>("get_memory_panel_data", {
      tzOffsetMinutes,
    });
    renderPanel(data);
  } catch (err) {
    workspaceEl.setAttribute("aria-busy", "false");
    loadingSkeletonEl.classList.add("hidden");
    errorMessageEl.textContent = `Panel verileri alınamadı: ${String(err)}`;
    errorBannerEl.classList.remove("hidden");
    if (!loadedOnce) {
      statePillEl.setAttribute("data-state", "unavailable");
      stateLabelEl.textContent = "Bağlantı hatası";
    }
  }
}

async function togglePause(): Promise<void> {
  try {
    if (isSensorPaused) {
      await invoke<SensorStatusDto>("resume_capture");
      showFeedback("Yakalama devam ettirildi.");
    } else {
      await invoke<SensorStatusDto>("pause_capture", { seconds: 3600 });
      showFeedback("Yakalama 1 saat süreyle duraklatıldı.");
    }
    await refreshPanel();
  } catch (err) {
    showFeedback(`Sensör durumu güncellenemedi: ${String(err)}`);
  }
}

async function addBlockedApp(processName: string): Promise<void> {
  const trimmed = processName.trim();
  if (!trimmed) {
    return;
  }
  try {
    const list = await invoke<string[]>("add_blocked_app", { processName: trimmed });
    blocklistInputEl.value = "";
    renderBlocklist(list);
    showFeedback("Uygulama engellendi.");
    await refreshPanel();
  } catch (err) {
    showFeedback(`Engelleme eklenemedi: ${String(err)}`);
  }
}

async function removeBlockedApp(processName: string): Promise<void> {
  try {
    const list = await invoke<string[]>("remove_blocked_app", { processName });
    renderBlocklist(list);
    showFeedback("Uygulama engeli kaldırıldı.");
    await refreshPanel();
  } catch (err) {
    showFeedback(`Engel kaldırılamadı: ${String(err)}`);
  }
}

async function deleteRecent(): Promise<void> {
  try {
    const deleted = await invoke<number>("delete_recent_memory", { minutes: 15 });
    showFeedback(`Son 15 dakikadan ${formatNumber(deleted)} olay silindi.`);
    await refreshPanel();
  } catch (err) {
    showFeedback(`Son 15 dakika silinemedi: ${String(err)}`);
  }
}

async function deleteAll(): Promise<void> {
  try {
    const deleted = await invoke<number>("delete_all_memory", { confirm: true });
    deleteAllConfirmEl.classList.add("hidden");
    deleteAllOpenBtn.setAttribute("aria-expanded", "false");
    showFeedback(`Tüm hafıza silindi (${formatNumber(deleted)} olay temizlendi).`);
    await refreshPanel();
  } catch (err) {
    showFeedback(`Hafıza silinemedi: ${String(err)}`);
  }
}

async function toggleAutostart(): Promise<void> {
  const next = !isAutostartEnabled;
  if (isDevBrowserPreview()) {
    renderAutostart(next);
    autostartFeedbackEl.textContent = next
      ? "Windows açılışında başlatma açıldı."
      : "Windows açılışında başlatma kapatıldı.";
    autostartFeedbackEl.classList.remove("hidden");
    return;
  }

  autostartToggleBtn.disabled = true;
  try {
    const actual = await invoke<boolean>("set_autostart", { enabled: next });
    renderAutostart(actual);
    autostartFeedbackEl.textContent = actual
      ? "Windows açılışında başlatma açıldı."
      : "Windows açılışında başlatma kapatıldı.";
    autostartFeedbackEl.classList.remove("hidden");
  } catch (err) {
    autostartFeedbackEl.textContent = `Başlangıç ayarı güncellenemedi: ${String(err)}`;
    autostartFeedbackEl.classList.remove("hidden");
  } finally {
    autostartToggleBtn.disabled = false;
  }
}

navButtons.forEach((btn, idx) => {
  btn.addEventListener("click", () => {
    const view = (btn.dataset.view as ViewId) ?? "overview";
    applyView(view);
  });

  btn.addEventListener("keydown", (event: KeyboardEvent) => {
    if (event.key === "ArrowDown" || event.key === "ArrowRight") {
      event.preventDefault();
      const next = navButtons[(idx + 1) % navButtons.length];
      next.focus();
      applyView((next.dataset.view as ViewId) ?? "overview");
    } else if (event.key === "ArrowUp" || event.key === "ArrowLeft") {
      event.preventDefault();
      const prev = navButtons[(idx - 1 + navButtons.length) % navButtons.length];
      prev.focus();
      applyView((prev.dataset.view as ViewId) ?? "overview");
    }
  });
});

themeToggleBtn.addEventListener("click", () => {
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  setTheme(!isDark);
});

refreshBtn.addEventListener("click", () => {
  void refreshPanel();
});

retryBtn.addEventListener("click", () => {
  errorBannerEl.classList.add("hidden");
  void refreshPanel();
});

pauseToggleBtn.addEventListener("click", () => {
  void togglePause();
});

noticeResumeBtn.addEventListener("click", () => {
  void (async () => {
    try {
      await invoke<SensorStatusDto>("resume_capture");
      showFeedback("Yakalama devam ettirildi.");
      await refreshPanel();
    } catch (err) {
      showFeedback(`Devam ettirilemedi: ${String(err)}`);
    }
  })();
});

blocklistToggleBtn.addEventListener("click", () => {
  const willShow = blocklistDrawerEl.classList.contains("hidden");
  blocklistDrawerEl.classList.toggle("hidden", !willShow);
  blocklistToggleBtn.setAttribute("aria-expanded", String(willShow));
  if (willShow) {
    blocklistInputEl.focus();
  }
});

blocklistCancelBtn.addEventListener("click", () => {
  blocklistDrawerEl.classList.add("hidden");
  blocklistToggleBtn.setAttribute("aria-expanded", "false");
});

blocklistFormEl.addEventListener("submit", (event) => {
  event.preventDefault();
  void addBlockedApp(blocklistInputEl.value);
});

deleteRecentBtn.addEventListener("click", () => {
  void deleteRecent();
});

deleteAllOpenBtn.addEventListener("click", () => {
  const willShow = deleteAllConfirmEl.classList.contains("hidden");
  deleteAllConfirmEl.classList.toggle("hidden", !willShow);
  deleteAllOpenBtn.setAttribute("aria-expanded", String(willShow));
});

deleteAllCancelBtn.addEventListener("click", () => {
  deleteAllConfirmEl.classList.add("hidden");
  deleteAllOpenBtn.setAttribute("aria-expanded", "false");
});

deleteAllConfirmBtn.addEventListener("click", () => {
  void deleteAll();
});

autostartToggleBtn.addEventListener("click", () => {
  void toggleAutostart();
});

openChainBtn.addEventListener("click", () => {
  if (!latestChainHit) {
    return;
  }
  chainExpanded = !chainExpanded;
  openChainBtn.textContent = chainExpanded ? "Zinciri gizle" : "Zinciri aç";
  chainDetailsEl.classList.toggle("hidden", !chainExpanded);

  if (chainExpanded) {
    chainDetailsEl.replaceChildren();
    const header = document.createElement("div");
    header.textContent = `Çapa olay #${latestChainHit.event_id} · ${latestChainHit.matched_app} · ${formatClock(latestChainHit.timestamp_ms)}`;
    chainDetailsEl.appendChild(header);
    for (const edge of latestChainHit.causality_chain) {
      const line = document.createElement("div");
      line.textContent = `#${edge.source_event_id} —[${edge.relationship}, +${edge.time_delta_seconds}s]→ #${edge.target_event_id}`;
      chainDetailsEl.appendChild(line);
    }
    if (latestChainHit.causality_chain.length === 0) {
      const empty = document.createElement("div");
      empty.textContent = "Ek kenar yok.";
      chainDetailsEl.appendChild(empty);
    }
  }
});

searchSimilarBtn.addEventListener("click", () => {
  if (!latestChainHit) {
    return;
  }
  const seed = latestChainHit.summary_snippet.replace(/\[DEMO\]/g, "").trim().slice(0, 64);
  void invoke("open_overlay_with_query", { query: seed });
});

embedderRetryBtn.addEventListener("click", () => {
  if (isDevBrowserPreview()) {
    renderEmbedderStatus({
      state: "downloading",
      bytes: 18_500_000,
      total: 67_100_000,
      progress_pct: 28,
      message: null,
    });
    return;
  }
  embedderRetryBtn.disabled = true;
  void (async () => {
    try {
      const next = await invoke<EmbedderStatusDto>("retry_embedder_download");
      renderEmbedderStatus(next);
    } catch (err) {
      showFeedback(`Model indirilemedi: ${String(err)}`);
      embedderRetryBtn.disabled = false;
    }
  })();
});

async function bootstrapPanel(): Promise<void> {
  const media =
    typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-color-scheme: dark)")
      : null;
  setTheme(media?.matches ?? false);
  media?.addEventListener("change", (ev) => {
    const previewMode = import.meta.env.DEV
      ? new URLSearchParams(window.location.search).get("preview")
      : null;
    if (!previewMode) {
      setTheme(ev.matches);
    }
  });

  if (import.meta.env.DEV) {
    const viewParam = new URLSearchParams(window.location.search).get("view") as ViewId | null;
    if (
      viewParam === "overview" ||
      viewParam === "activity" ||
      viewParam === "privacy" ||
      viewParam === "controls"
    ) {
      applyView(viewParam);
    }
  }

  await refreshPanel();

  try {
    await listen<EmbedderStatusDto>("embedder://status", (event) => {
      renderEmbedderStatus(event.payload);
    });
    await listen("panel://refresh", () => {
      void refreshPanel();
    });
  } catch {
    // Ignore outside Tauri runtime.
  }

  try {
    const currentEmbed = await invoke<EmbedderStatusDto>("get_embedder_status");
    renderEmbedderStatus(currentEmbed);
  } catch {
    // Ignore outside Tauri runtime.
  }

  const isPreview =
    import.meta.env.DEV &&
    Boolean(new URLSearchParams(window.location.search).get("preview"));
  if (!isPreview) {
    window.setInterval(() => {
      void refreshPanel();
    }, 5000);
  }
}

void bootstrapPanel();
