// background.js — AuthShield Service Worker
// Role: Bridge between content.js (DOM hash sender) and the FastAPI backend.
// Also maintains per-tab verification status for popup.js to read.

const BACKEND_URL = "http://localhost:8000";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "SUBMIT_REPORT") {
    submitReport(message.report)
      .then(sendResponse)
      .catch((err) => sendResponse({ status: "ERROR", message: err.message }));
    return true;
  }

  if (message.action !== "VERIFY_DOM_HASH") {
    return false;
  }

  const tabId = sender.tab?.id;

  if (!tabId) {
    sendResponse({ status: "UNKNOWN", message: "No tab context available." });
    return false;
  }

  verifyDomHash(message.domain, message.hash, message.featureSignature)
    .then(async (result) => {
      await storeStatusForTab(tabId, message.domain, result, message.hash, message.featureSignature);
      sendResponse(result);
    })
    .catch(async (err) => {
      const fallback = {
        status: "UNKNOWN",
        // Do not label every failure as an unreachable backend. A 422, for
        // example, means the API received the request but rejected its data.
        message: `Verification could not be completed: ${err.message}`
      };
      await storeStatusForTab(tabId, message.domain, fallback, message.hash, message.featureSignature);
      sendResponse(fallback);
    });

  return true;
});

async function postToBackend(path, body) {
  const response = await fetch(`${BACKEND_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    let detail = "";
    try {
      const errorBody = await response.json();
      detail = errorBody.detail
        ? ` — ${typeof errorBody.detail === "string" ? errorBody.detail : JSON.stringify(errorBody.detail)}`
        : "";
    } catch (_) {
      // Some proxies return non-JSON error responses. The HTTP status still
      // gives the user a useful diagnostic.
    }
    throw new Error(`Backend returned HTTP ${response.status}${detail}`);
  }

  return response.json();
}

async function verifyDomHash(domain, hash, featureSignature) {
  return postToBackend("/verify", {
    domain,
    dom_hash: hash,
    feature_signature: featureSignature || ""
  });
}

async function submitReport(report) {
  return postToBackend("/reports", report);
}

async function storeStatusForTab(tabId, domain, result, hash, featureSignature) {
  const key = `tabStatus_${tabId}`;
  await chrome.storage.session.set({
    [key]: {
      domain: domain,
      status: result.status,
      message: result.message,
      similarityScore: result.similarity_score,
      similarPortal: result.similar_portal,
      domainSimilarityScore: result.domain_similarity_score,
      similarDomain: result.similar_domain,
      // Tranco fallback context - only ever populated on the backend's
      // catch-all UNKNOWN verdict (see main.py). Both are undefined/null
      // for SAFE and DANGER results, and popup.js treats that as "no
      // popularity data to show" rather than an error.
      trancoRank: result.tranco_rank ?? null,
      trancoSource: result.tranco_source ?? null,
      domHash: hash,
      featureSignature: featureSignature || "",
      timestamp: Date.now()
    }
  });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  const key = `tabStatus_${tabId}`;
  chrome.storage.session.remove(key);
});
