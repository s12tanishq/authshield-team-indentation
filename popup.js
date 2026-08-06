// popup.js — AuthShield Popup Logic

const STATUS_ICONS = {
  SAFE: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
  DANGER: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  UNKNOWN: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
};

let currentRecord = null;
let tickInterval  = null;

document.addEventListener("DOMContentLoaded", () => {
  loadStatusForActiveTab();

  const refreshButton = document.getElementById("refresh-button");
  refreshButton.addEventListener("click", () => {
    loadStatusForActiveTab();
  });

  tickInterval = setInterval(updateCheckedTime, 15000);
});

async function loadStatusForActiveTab() {
  const [activeTab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  if (!activeTab || !activeTab.id) {
    renderStatus({ status: "UNKNOWN", message: "No active tab detected.", domain: "—" });
    return;
  }

  const key = `tabStatus_${activeTab.id}`;
  const stored = await chrome.storage.session.get(key);
  const record = stored[key];

  if (!record) {
    renderStatus({ status: "UNKNOWN", message: "No verification data yet for this tab.", domain: "—" });
    return;
  }

  renderStatus(record);
}

function renderStatus(record) {
  currentRecord = record;

  const badge       = document.getElementById("status-badge");
  const statusIcon   = document.getElementById("status-icon");
  const statusText  = document.getElementById("status-text");
  const messageText = document.getElementById("status-message");
  const domainValue = document.getElementById("domain-value");

  statusIcon.innerHTML     = STATUS_ICONS[record.status] || STATUS_ICONS.UNKNOWN;
  statusText.textContent   = record.status;
  messageText.textContent  = record.message;
  domainValue.textContent  = record.domain || "—";

  badge.classList.remove("status-safe", "status-danger", "status-unknown");

  if (record.status === "SAFE") {
    badge.classList.add("status-safe");
  } else if (record.status === "DANGER") {
    badge.classList.add("status-danger");
  } else {
    badge.classList.add("status-unknown");
  }

  updateCheckedTime();
}

function updateCheckedTime() {
  const checkedValue = document.getElementById("checked-value");
  if (!currentRecord || !currentRecord.timestamp) {
    checkedValue.textContent = "—";
    return;
  }
  checkedValue.textContent = formatRelativeTime(currentRecord.timestamp);
}

function formatRelativeTime(timestamp) {
  const diffMs = Date.now() - timestamp;
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 10) return "just now";
  if (diffSec < 60) return `${diffSec}s ago`;

  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;

  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;

  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}
