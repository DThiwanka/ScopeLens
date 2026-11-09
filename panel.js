const requestsEl = document.getElementById("requests");
const countEl = document.getElementById("count");
const originEl = document.getElementById("origin");
const filterInput = document.getElementById("filter-input");
const filterBtns = document.querySelectorAll(".filter-btn");
const exportBtn = document.getElementById("export-btn");
const clearBtn = document.getElementById("clear-btn");

let inspectedOrigin = null;
let recordedRequests = [];
let activeTypeFilter = "all";
let searchQuery = "";

const sensitiveName = /authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|api.?key|client.?secret|session/i;
const jwtPattern = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

function sanitizeUrl(raw) {
  try {
    const u = new URL(raw);
    for (const key of [...u.searchParams.keys()]) {
      if (sensitiveName.test(key)) u.searchParams.set(key, "[REDACTED]");
    }
    u.username = ""; u.password = "";
    return u.toString();
  } catch { return raw; }
}

function redactText(value) {
  let text = String(value ?? "");
  try {
    const parsed = JSON.parse(text);
    const scrub = obj => {
      if (Array.isArray(obj)) return obj.map(scrub);
      if (obj && typeof obj === "object") {
        const clean = {};
        for (const [key, val] of Object.entries(obj)) clean[key] = sensitiveName.test(key) ? "[REDACTED]" : scrub(val);
        return clean;
      }
      return typeof obj === "string" ? obj.replace(/\bBearer\s+\S+/gi, "Bearer [REDACTED]").replace(jwtPattern, "[JWT REDACTED]") : obj;
    };
    text = JSON.stringify(scrub(parsed), null, 2);
  } catch {
    text = text
      .replace(/(authorization|cookie|set-cookie|password|client_secret|access_token|refresh_token|api[_-]?key)(["'\s:=]+)([^"'\s,;&}]+)/gi, "$1$2[REDACTED]")
      .replace(/\bBearer\s+\S+/gi, "Bearer [REDACTED]")
      .replace(jwtPattern, "[JWT REDACTED]");
  }
  return text.slice(0, 10000);
}

function redactHeaders(headers = []) {
  return headers.map(({ name, value }) => ({
    name,
    value: sensitiveName.test(name) ? "[REDACTED]" : redactText(value)
  }));
}

function addText(parent, tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.textContent = text;
  parent.append(el);
  return el;
}

function addCode(parent, text) {
  const pre = document.createElement("pre");
  pre.className = "code-box";
  pre.textContent = text;
  parent.append(pre);
  return pre;
}

function getStatusClass(status) {
  if (status >= 200 && status < 300) return "status-2xx";
  if (status >= 300 && status < 400) return "status-3xx";
  if (status >= 400 && status < 500) return "status-4xx";
  if (status >= 500) return "status-5xx";
  return "status-other";
}

function matchesFilter(item) {
  const resourceType = (item._resourceType || "").toLowerCase();
  if (activeTypeFilter !== "all") {
    if (activeTypeFilter === "fetch" && !["fetch", "xhr"].includes(resourceType)) return false;
    if (activeTypeFilter === "script" && resourceType !== "script") return false;
    if (activeTypeFilter === "stylesheet" && resourceType !== "stylesheet") return false;
    if (activeTypeFilter === "document" && resourceType !== "document") return false;
    if (activeTypeFilter === "image" && !["image", "media", "font"].includes(resourceType)) return false;
  }

  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    const urlMatch = item.request.url.toLowerCase().includes(q);
    const methodMatch = item.request.method.toLowerCase().includes(q);
    const statusMatch = String(item.response.status).includes(q);
    const mimeMatch = (item.response.content.mimeType || "").toLowerCase().includes(q);
    return urlMatch || methodMatch || statusMatch || mimeMatch;
  }

  return true;
}

function renderRequests() {
  const visibleItems = recordedRequests.filter(matchesFilter);
  countEl.textContent = `${recordedRequests.length} requests (${visibleItems.length} shown)`;

  if (!visibleItems.length) {
    requestsEl.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = recordedRequests.length === 0
      ? "Reload the inspected page with DevTools open to capture same-origin network traffic."
      : "No requests match the active filter or search query.";
    requestsEl.append(empty);
    return;
  }

  requestsEl.replaceChildren();

  visibleItems.forEach(item => {
    const card = document.createElement("section");
    card.className = "panel request-card";

    const header = document.createElement("div");
    header.className = "request-summary";

    const badge = document.createElement("span");
    badge.className = `method-badge method-${item.request.method.toLowerCase()}`;
    badge.textContent = item.request.method;

    const statusPill = document.createElement("span");
    statusPill.className = `status-pill ${getStatusClass(item.response.status)}`;
    statusPill.textContent = item.response.status || "—";

    const urlSpan = document.createElement("span");
    urlSpan.className = "request-url";
    urlSpan.title = item.request.url;
    urlSpan.textContent = sanitizeUrl(item.request.url);

    const metaSpan = document.createElement("span");
    metaSpan.className = "request-meta muted";
    const time = Math.round(item.time || 0);
    const size = item.response.bodySize >= 0 ? `${Math.round(item.response.bodySize / 1024 * 10) / 10} KB` : "cached";
    metaSpan.textContent = `${item._resourceType || "xhr"} · ${size} · ${time}ms`;

    header.append(badge, statusPill, urlSpan, metaSpan);
    card.append(header);

    // Expandable details drawer
    const details = document.createElement("div");
    details.className = "request-details hidden";

    // Copy actions row
    const actionRow = document.createElement("div");
    actionRow.className = "action-mini-row";

    const copyUrlBtn = document.createElement("button");
    copyUrlBtn.className = "btn-xs";
    copyUrlBtn.textContent = "Copy URL";
    copyUrlBtn.addEventListener("click", e => {
      e.stopPropagation();
      navigator.clipboard.writeText(item.request.url);
      copyUrlBtn.textContent = "Copied!";
      setTimeout(() => copyUrlBtn.textContent = "Copy URL", 1500);
    });

    actionRow.append(copyUrlBtn);
    details.append(actionRow);

    // Headers
    const reqHeaders = redactHeaders(item.request.headers || []);
    addText(details, "div", "row-title", "Request Headers");
    addCode(details, reqHeaders.map(h => `${h.name}: ${h.value}`).join("\n") || "(none exposed)");

    const resHeaders = redactHeaders(item.response.headers || []);
    addText(details, "div", "row-title", "Response Headers");
    addCode(details, resHeaders.map(h => `${h.name}: ${h.value}`).join("\n") || "(none exposed)");

    // Request postData
    if (item.request.postData?.text) {
      addText(details, "div", "row-title", "Request Payload");
      addCode(details, redactText(item.request.postData.text));
    }

    // Response content preview
    if (item.getContent) {
      const respTitle = addText(details, "div", "row-title", "Response Body");
      const respBtn = document.createElement("button");
      respBtn.className = "text-button";
      respBtn.textContent = "Load response body preview";
      const respBox = document.createElement("div");
      respBox.className = "hidden";

      respBtn.addEventListener("click", e => {
        e.stopPropagation();
        if (respBox.classList.contains("hidden")) {
          if (item._cachedBody !== undefined) {
            respBox.replaceChildren();
            addCode(respBox, item._cachedBody);
            respBox.classList.remove("hidden");
            respBtn.textContent = "Hide response body";
            return;
          }
          respBtn.textContent = "Loading…";
          item.getContent((content, encoding) => {
            const decoded = encoding === "base64" ? "[Base64 binary response omitted]" : content;
            item._cachedBody = redactText(decoded || "(empty response body)");
            respBox.replaceChildren();
            addCode(respBox, item._cachedBody);
            respBox.classList.remove("hidden");
            respBtn.textContent = "Hide response body";
          });
        } else {
          respBox.classList.add("hidden");
          respBtn.textContent = "Show response body preview";
        }
      });

      details.append(respBtn, respBox);
    }

    header.addEventListener("click", () => {
      details.classList.toggle("hidden");
      card.classList.toggle("expanded");
    });

    card.append(details);
    requestsEl.append(card);
  });
}

function onRequestFinished(request) {
  let url;
  try { url = new URL(request.request.url); } catch { return; }
  if (inspectedOrigin && url.origin !== inspectedOrigin) return;

  recordedRequests.unshift(request);
  if (recordedRequests.length > 500) recordedRequests.pop();

  renderRequests();
}

// Search and filter listeners
filterInput?.addEventListener("input", e => {
  searchQuery = e.target.value.trim();
  renderRequests();
});

filterBtns.forEach(btn => {
  btn.addEventListener("click", () => {
    filterBtns.forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeTypeFilter = btn.dataset.filter;
    renderRequests();
  });
});

clearBtn?.addEventListener("click", () => {
  recordedRequests = [];
  renderRequests();
});

exportBtn?.addEventListener("click", () => {
  if (!recordedRequests.length) {
    alert("No network requests to export.");
    return;
  }
  const cleanData = recordedRequests.map(r => ({
    url: sanitizeUrl(r.request.url),
    method: r.request.method,
    status: r.response.status,
    statusText: r.response.statusText,
    resourceType: r._resourceType,
    timeMs: r.time,
    mimeType: r.response.content.mimeType,
    sizeBytes: r.response.bodySize,
    requestHeaders: redactHeaders(r.request.headers || []),
    responseHeaders: redactHeaders(r.response.headers || [])
  }));

  const blob = new Blob([JSON.stringify({
    inspectedOrigin,
    exportedAt: new Date().toISOString(),
    totalRequests: cleanData.length,
    requests: cleanData
  }, null, 2)], { type: "application/json" });

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `scopelens-network-${(inspectedOrigin || "capture").replace(/[^a-z0-9]/gi, "_")}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

chrome.devtools.inspectedWindow.eval("location.origin", (origin, exceptionInfo) => {
  if (exceptionInfo || typeof origin !== "string") {
    originEl.textContent = "Could not determine inspected origin.";
    return;
  }
  inspectedOrigin = origin;
  originEl.textContent = `Filtering to ${origin}`;
});

chrome.devtools.network.onRequestFinished.addListener(onRequestFinished);
