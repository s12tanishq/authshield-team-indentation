// background.js — AuthShield Service Worker
// Role: Bridge between content.js (DOM hash sender) and the FastAPI backend.
// Also maintains per-tab verification status for popup.js to read.

const BACKEND_URL = "http://localhost:8000/verify";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action !== "VERIFY_DOM_HASH") {
    return false;
  }

  const tabId = sender.tab?.id;

  if (!tabId) {
    sendResponse({ status: "UNKNOWN", message: "No tab context available." });
    return false;
  }

  verifyDomHash(message.domain, message.hash)
    .then((result) => {
      storeStatusForTab(tabId, message.domain, result);
      sendResponse(result);
    })
    .catch((err) => {
      const fallback = {
        status: "UNKNOWN",
        message: "Verification failed: backend unreachable."
      };
      storeStatusForTab(tabId, message.domain, fallback);
      sendResponse(fallback);
    });

  return true;
});

async function verifyDomHash(domain, hash) {
  const response = await fetch(BACKEND_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      domain: domain,
      dom_hash: hash
    })
  });

  if (!response.ok) {
    throw new Error(`Backend responded with status ${response.status}`);
  }

  const data = await response.json();
  return {
    status: data.status,
    message: data.message
  };
}

async function storeStatusForTab(tabId, domain, result) {
  const key = `tabStatus_${tabId}`;
  await chrome.storage.session.set({
    [key]: {
      domain: domain,
      status: result.status,
      message: result.message,
      timestamp: Date.now()
    }
  });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  const key = `tabStatus_${tabId}`;
  chrome.storage.session.remove(key);
});
