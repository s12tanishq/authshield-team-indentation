// popup.js — AuthShield Popup Logic
// Role: Read the active tab's verification status from chrome.storage.session
// (written by background.js) and render it into popup.html's elements.

document.addEventListener("DOMContentLoaded", () => {
  loadStatusForActiveTab();

  const refreshButton = document.getElementById("refresh-button");
  refreshButton.addEventListener("click", () => {
    loadStatusForActiveTab();
  });
});

async function loadStatusForActiveTab() {
  const [activeTab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  if (!activeTab || !activeTab.id) {
    renderStatus({
      status: "UNKNOWN",
      message: "No active tab detected.",
      domain: "—"
    });
    return;
  }

  const key = `tabStatus_${activeTab.id}`;
  const stored = await chrome.storage.session.get(key);
  const record = stored[key];

  if (!record) {
    renderStatus({
      status: "UNKNOWN",
      message: "No verification data yet for this tab.",
      domain: "—"
    });
    return;
  }

  renderStatus(record);
}

function renderStatus(record) {
  const badge       = document.getElementById("status-badge");
  const statusText  = document.getElementById("status-text");
  const messageText = document.getElementById("status-message");
  const domainValue = document.getElementById("domain-value");

  statusText.textContent  = record.status;
  messageText.textContent = record.message;
  domainValue.textContent = record.domain || "—";

  badge.classList.remove("status-safe", "status-danger", "status-unknown");

  if (record.status === "SAFE") {
    badge.classList.add("status-safe");
  } else if (record.status === "DANGER") {
    badge.classList.add("status-danger");
  } else {
    badge.classList.add("status-unknown");
  }
}
