import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export interface EdgeDto {
  source_event_id: number;
  target_event_id: number;
  relationship: string;
  time_delta_seconds: number;
}

export interface HitDto {
  event_id: number;
  timestamp_ms: number;
  score: number;
  summary_snippet: string;
  matched_app: string;
  causality_chain: EdgeDto[];
}

const DEBOUNCE_MS = 150;
const SEARCH_LIMIT = 12;

const searchInput = document.getElementById("search-input") as HTMLInputElement;
const resultsContainer = document.getElementById("results-container") as HTMLElement;
const statusText = document.getElementById("status-text") as HTMLElement;
const demoBadge = document.getElementById("demo-badge") as HTMLElement;
const openPanelBtn = document.getElementById("open-panel-btn") as HTMLButtonElement;

let debounceTimer: number | undefined;
let activeRequestSeq = 0;
let selectedIndex = -1;
let currentHits: HitDto[] = [];

function formatTimestamp(tsMs: number): string {
  const date = new Date(tsMs);
  if (Number.isNaN(date.getTime())) {
    return String(tsMs);
  }
  const clock = date.toLocaleTimeString("tr-TR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const diffSec = Math.max(0, Math.floor((Date.now() - tsMs) / 1000));
  if (diffSec < 60) {
    return `${clock} · ${diffSec}sn önce`;
  }
  if (diffSec < 3600) {
    return `${clock} · ${Math.floor(diffSec / 60)}dk önce`;
  }
  if (diffSec < 86400) {
    return `${clock} · ${Math.floor(diffSec / 3600)}sa önce`;
  }
  const day = date.toLocaleDateString("tr-TR");
  return `${day} ${clock}`;
}

function renderEmpty(message: string): void {
  resultsContainer.replaceChildren();
  const empty = document.createElement("div");
  empty.className = "empty-state";
  empty.textContent = message;
  resultsContainer.appendChild(empty);
}

function updateSelectionVisuals(): void {
  const cards = resultsContainer.querySelectorAll<HTMLElement>(".hit-card");
  cards.forEach((card, index) => {
    const isSelected = index === selectedIndex;
    card.classList.toggle("selected", isSelected);
    card.setAttribute("aria-selected", String(isSelected));
    if (isSelected) {
      card.scrollIntoView({ block: "nearest" });
    }
  });
}

function renderHits(hits: HitDto[]): void {
  currentHits = hits;
  selectedIndex = hits.length > 0 ? 0 : -1;

  if (hits.length === 0) {
    renderEmpty("Eşleşen kayıt bulunamadı.");
    return;
  }

  const fragment = document.createDocumentFragment();
  hits.forEach((hit, index) => {
    const card = document.createElement("article");
    card.className = index === 0 ? "hit-card selected" : "hit-card";
    card.setAttribute("role", "option");
    card.setAttribute("aria-selected", String(index === 0));

    const meta = document.createElement("div");
    meta.className = "hit-meta";

    const app = document.createElement("span");
    app.className = "hit-app";
    app.textContent = hit.matched_app;

    const time = document.createElement("span");
    time.className = "hit-time";
    time.textContent = formatTimestamp(hit.timestamp_ms);

    const score = document.createElement("span");
    score.className = "hit-score";
    score.textContent = `#${hit.event_id} · ${hit.score.toFixed(2)}`;

    meta.append(app, time, score);

    const snippet = document.createElement("p");
    snippet.className = "hit-snippet";
    snippet.textContent = hit.summary_snippet;

    card.append(meta, snippet);

    if (hit.causality_chain.length > 0) {
      const chainRow = document.createElement("div");
      chainRow.className = "hit-chain";
      for (const edge of hit.causality_chain) {
        const chip = document.createElement("span");
        chip.className = "chain-chip";
        chip.textContent = `#${edge.source_event_id} → ${edge.relationship} (+${edge.time_delta_seconds}s) → #${edge.target_event_id}`;
        chainRow.appendChild(chip);
      }
      card.appendChild(chainRow);
    }

    card.addEventListener("mouseenter", () => {
      selectedIndex = index;
      updateSelectionVisuals();
    });

    fragment.appendChild(card);
  });

  resultsContainer.replaceChildren(fragment);
}

async function runSearch(rawQuery: string): Promise<void> {
  const query = rawQuery.trim();
  const requestSeq = ++activeRequestSeq;

  if (query.length === 0) {
    currentHits = [];
    selectedIndex = -1;
    renderEmpty("Aramak için yazmaya başlayın · Alt+Space ile aç/kapat");
    statusText.textContent = "Hazır";
    return;
  }

  statusText.textContent = "Aranıyor...";
  try {
    const hits = await invoke<HitDto[]>("search", {
      request: { query, k: SEARCH_LIMIT },
    });
    if (requestSeq !== activeRequestSeq) {
      return;
    }
    renderHits(hits);
    statusText.textContent = `${hits.length} sonuç`;
  } catch {
    if (requestSeq !== activeRequestSeq) {
      return;
    }
    currentHits = [];
    selectedIndex = -1;
    renderEmpty("Arama sırasında bir hata oluştu.");
    statusText.textContent = "Arama hatası";
  }
}

function scheduleSearch(): void {
  if (debounceTimer !== undefined) {
    window.clearTimeout(debounceTimer);
  }
  const snapshot = searchInput.value;
  debounceTimer = window.setTimeout(() => {
    debounceTimer = undefined;
    void runSearch(snapshot);
  }, DEBOUNCE_MS);
}

async function hideOverlay(): Promise<void> {
  try {
    await invoke("hide_overlay");
  } catch {
    // Ignore outside Tauri runtime.
  }
}

async function openMemoryPanel(): Promise<void> {
  try {
    await invoke("open_memory_panel");
  } catch {
    // Ignore outside Tauri runtime.
  }
}

openPanelBtn.addEventListener("click", () => {
  void openMemoryPanel();
});

searchInput.addEventListener("input", scheduleSearch);

window.addEventListener("keydown", (event: KeyboardEvent) => {
  if (event.ctrlKey && event.key.toLowerCase() === "m") {
    event.preventDefault();
    void openMemoryPanel();
    return;
  }

  if (event.key === "Escape") {
    event.preventDefault();
    void hideOverlay();
    return;
  }

  if (currentHits.length === 0) {
    return;
  }

  if (event.key === "ArrowDown") {
    event.preventDefault();
    selectedIndex = (selectedIndex + 1) % currentHits.length;
    updateSelectionVisuals();
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    selectedIndex = (selectedIndex - 1 + currentHits.length) % currentHits.length;
    updateSelectionVisuals();
  }
});

async function bootstrap(): Promise<void> {
  searchInput.focus();
  try {
    const demo = await invoke<boolean>("is_demo_mode");
    demoBadge.classList.toggle("hidden", !demo);
  } catch {
    // Ignore outside Tauri runtime.
  }

  try {
    await listen("overlay://focus", () => {
      searchInput.focus();
      searchInput.select();
    });
    await listen<string>("overlay://prefill", (event) => {
      const query = typeof event.payload === "string" ? event.payload.trim() : "";
      searchInput.value = query;
      searchInput.focus();
      searchInput.select();
      if (query.length > 0) {
        void runSearch(query);
      }
    });
  } catch {
    // Ignore outside Tauri runtime.
  }
}

void bootstrap();
