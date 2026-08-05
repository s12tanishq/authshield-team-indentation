/**
 * AuthShield - content.js
 *
 * Responsibilities:
 *   1. Scan the page for login forms.
 *   2. Strip dynamic/volatile attributes (CSRF tokens, dynamic ids, values, etc.)
 *   3. Serialize the cleaned structural markup into a standardized string.
 *   4. Compute a SHA-256 hash of that string using the native Web Crypto API.
 *   5. Send { action: "VERIFY_DOM_HASH", domain, hash } to background.js.
 *   6. On response:
 *        - "DANGER"  -> Red banner + disable all form inputs.
 *        - "UNKNOWN" -> Yellow advisory banner, form remains enabled.
 *        - "SAFE"    -> No UI action (popup reflects status only).
 */

(() => {
  "use strict";

  // ------------------------------------------------------------------
  // Configuration
  // ------------------------------------------------------------------

  // Attributes considered "dynamic" / non-structural — stripped before hashing
  // so the same form structure always produces the same hash regardless of
  // CSRF tokens, session values, or auto-generated ids.
  const DYNAMIC_ATTRS = new Set([
    "value",
    "id",
    "name",
    "class",
    "style",
    "data-csrf",
    "data-csrf-token",
    "csrf-token",
    "data-token",
    "data-session",
    "data-nonce",
    "nonce",
    "autocomplete",
    "aria-describedby",
    "aria-labelledby",
    "tabindex",
    "data-reactid",
    "data-testid",
  ]);

  // Attribute name patterns that are auto-generated/dynamic even if not in the
  // explicit list above (e.g. Vue scoped ids, Angular bindings, etc.)
  const DYNAMIC_ATTR_PATTERNS = [
    /^data-v-/i,       // Vue scoped ids
    /^ng-/i,           // Angular bindings
    /^_ngcontent/i,    // Angular content attributes
    /^jsaction$/i,     // Google jsaction
    /^data-reactroot$/i,
  ];

  // ONLY these attributes are kept after cleaning — everything else is dropped.
  // This keeps the hash purely structural and stable across deployments.
  const STRUCTURAL_ATTRS_ALLOWLIST = new Set([
    "type",
    "action",
    "method",
    "for",
    "role",
    "placeholder",
    "required",
    "maxlength",
    "minlength",
  ]);

  const VERIFY_ENDPOINT_ACTION = "VERIFY_DOM_HASH";

  // Banner element IDs — used to avoid duplicate injection on re-runs.
  const DANGER_BANNER_ID  = "authshield-danger-banner";
  const UNKNOWN_BANNER_ID = "authshield-unknown-banner";


  // ------------------------------------------------------------------
  // 1. Form Discovery
  // ------------------------------------------------------------------

  function findLoginForms() {
    const forms = Array.from(document.querySelectorAll("form"));
    return forms.filter(isLikelyLoginForm);
  }

  function isLikelyLoginForm(form) {
    // Primary signal: any form with a password field is a login form.
    const passwordFields = form.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) return true;

    // Fallback heuristic: text/email input + login-related keywords.
    // Catches portals that lazy-reveal the password field after email entry.
    const hasCredentialField = form.querySelector(
      'input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i]'
    );
    const loginKeywords = /(log[\s-]?in|sign[\s-]?in|username|password)/i;
    return Boolean(hasCredentialField) && loginKeywords.test(
      form.innerText ? form.innerText.toLowerCase() : ""
    );
  }


  // ------------------------------------------------------------------
  // 2. Cleaning
  // ------------------------------------------------------------------

  /**
   * Deep-clones the form element and strips all dynamic/volatile attributes
   * so the structural fingerprint is stable across page loads.
   * The live DOM is NEVER mutated — always working on a clone.
   */
  function cleanElement(node) {
    const clone = node.cloneNode(true);
    stripDynamicAttributes(clone);
    return clone;
  }

  function stripDynamicAttributes(root) {
    const elements = [root, ...root.querySelectorAll("*")];

    for (const el of elements) {
      if (!(el instanceof Element)) continue;

      // Always remove current state/values regardless of allowlist.
      el.removeAttribute("value");
      el.removeAttribute("checked");
      el.removeAttribute("selected");

      const attrNames = Array.from(el.attributes).map((a) => a.name);

      for (const attrName of attrNames) {
        const lower = attrName.toLowerCase();

        const isExplicitlyDynamic  = DYNAMIC_ATTRS.has(lower);
        const matchesDynamicPattern = DYNAMIC_ATTR_PATTERNS.some((re) => re.test(lower));
        const isAllowlisted         = STRUCTURAL_ATTRS_ALLOWLIST.has(lower);

        // Drop the attribute if it is explicitly dynamic, matches a dynamic
        // pattern, OR is simply not in the structural allowlist.
        if (isExplicitlyDynamic || matchesDynamicPattern || !isAllowlisted) {
          el.removeAttribute(attrName);
        }
      }
    }
  }


  // ------------------------------------------------------------------
  // 3. Serialization
  // ------------------------------------------------------------------

  /**
   * Produces a whitespace-normalized, attribute-order-stable structural string.
   * Two structurally identical forms will always serialize identically,
   * giving the same SHA-256 hash regardless of server-side rendering differences.
   */
  function serializeStructure(cleanedEl) {
    normalizeAttributeOrder(cleanedEl);
    const raw = cleanedEl.outerHTML || "";
    return raw
      .replace(/\s+/g, " ")
      .replace(/>\s+</g, "><")
      .trim();
  }

  // Sort each element's attributes alphabetically so attribute insertion
  // order differences between page loads don't affect the final hash.
  function normalizeAttributeOrder(root) {
    const elements = [root, ...root.querySelectorAll("*")];
    for (const el of elements) {
      if (!(el instanceof Element)) continue;
      const attrs = Array.from(el.attributes).sort((a, b) =>
        a.name.localeCompare(b.name)
      );
      for (const attr of attrs) {
        const val = el.getAttribute(attr.name);
        el.removeAttribute(attr.name);
        el.setAttribute(attr.name, val);
      }
    }
  }


  // ------------------------------------------------------------------
  // 4. Hashing (Web Crypto API — no external libraries)
  // ------------------------------------------------------------------

  async function sha256Hex(message) {
    const encoder = new TextEncoder();
    const data    = encoder.encode(message);
    const digest  = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }


  // ------------------------------------------------------------------
  // 5. Messaging to background.js
  //
  // ⚠ CONFIRMATION NEEDED FROM PERSON A (background.js) — READ BEFORE MERGING
  // ------------------------------------------------------------------

  /**
   * Sends the domain + hash to background.js and waits for a response.
   *
   * This function covers BOTH possible implementations of background.js.
   * Read the two cases below and confirm with Person A which one applies.
   *
   * ─────────────────────────────────────────────────────────────────
   * CASE 1 — background.js responds ASYNCHRONOUSLY (fetch to backend)
   * ─────────────────────────────────────────────────────────────────
   * This is the EXPECTED case given the architecture (background.js
   * awaits a fetch to http://localhost:8000/verify before responding).
   *
   * For this to work, Person A's onMessage listener MUST include
   * "return true" to keep the message channel open while fetch completes.
   *
   * Expected background.js structure:
   *
   *   chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
   *     if (message.action === "VERIFY_DOM_HASH") {
   *       fetch("http://localhost:8000/verify", {
   *         method: "POST",
   *         headers: { "Content-Type": "application/json" },
   *         body: JSON.stringify({
   *           domain:   message.domain,
   *           dom_hash: message.hash
   *         })
   *       })
   *       .then(res => res.json())
   *       .then(data => sendResponse(data))
   *       .catch(()  => sendResponse({ status: "UNKNOWN", message: "Backend unreachable." }));
   *
   *       return true; // ← CRITICAL: without this line, the channel closes
   *     }               //   before fetch resolves and content.js gets undefined.
   *   });
   *
   * If "return true" is missing → response will be undefined here →
   * NO banner will ever appear, even on real phishing pages.
   *
   * ─────────────────────────────────────────────────────────────────
   * CASE 2 — background.js responds SYNCHRONOUSLY (no async fetch)
   * ─────────────────────────────────────────────────────────────────
   * If Person A's implementation is fully synchronous (e.g. using a
   * cached result or pre-fetched data), "return true" is not needed
   * and the current sendMessage callback below works as-is.
   *
   * No changes needed in content.js for Case 2.
   * ─────────────────────────────────────────────────────────────────
   *
   * ACTION FOR PERSON A:
   *   Confirm which case applies and ensure "return true" is present
   *   in the onMessage listener if Case 1 (async fetch) is used.
   */
  function verifyHash(domain, hash) {
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage(
          { action: VERIFY_ENDPOINT_ACTION, domain, hash },
          (response) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
              return;
            }
            // If response is undefined here, Person A's background.js is
            // likely missing "return true" in the onMessage listener (Case 1).
            resolve(response);
          }
        );
      } catch (err) {
        reject(err);
      }
    });
  }


  // ------------------------------------------------------------------
  // 6. Banner Injection & Form Lockdown
  // ------------------------------------------------------------------

  /**
   * DANGER — Red banner + form fully disabled.
   * Triggered when: status === "DANGER"
   * The cloned portal's DOM hash matches a known authentic portal's hash
   * but the domain does not — clear credential harvesting attempt.
   */
  function injectDangerBanner(message) {
    if (document.getElementById(DANGER_BANNER_ID)) return; // prevent duplicates

    const banner = document.createElement("div");
    banner.id = DANGER_BANNER_ID;
    banner.setAttribute("role", "alert");
    banner.style.cssText = [
      "position:fixed",
      "top:0",
      "left:0",
      "right:0",
      "z-index:2147483647",
      "background:#c0392b",
      "color:#ffffff",
      "font-family:Arial, sans-serif",
      "font-size:15px",
      "font-weight:bold",
      "text-align:center",
      "padding:12px 16px",
      "box-shadow:0 2px 6px rgba(0,0,0,0.5)",
    ].join(";");

    banner.textContent = `⛔ AuthShield Warning: ${message}`;
    document.documentElement.appendChild(banner);
    if (document.body) document.body.style.marginTop = "48px";
  }

  function disableForm(form) {
    const fields = form.querySelectorAll("input, button, select, textarea");
    fields.forEach((field) => {
      field.disabled = true;
      field.style.filter = "grayscale(60%)";
    });
    form.style.opacity      = "0.6";
    form.style.pointerEvents = "none";
  }

  /**
   * UNKNOWN — Yellow advisory banner, form remains fully enabled.
   * Triggered when: status === "UNKNOWN"
   *
   * CHANGE FROM ORIGINAL DESIGN (confirm with team if needed):
   * Originally, UNKNOWN status had no UI action (popup-only).
   * Updated to show a yellow advisory banner so users are warned about
   * portals not yet registered in the AuthShield database — these could
   * be new phishing sites not yet catalogued, or legitimate new portals.
   * The form is intentionally left enabled since this is advisory only.
   */
  function injectUnknownBanner(message) {
    if (document.getElementById(UNKNOWN_BANNER_ID)) return; // prevent duplicates

    const banner = document.createElement("div");
    banner.id = UNKNOWN_BANNER_ID;
    banner.setAttribute("role", "alert");
    banner.style.cssText = [
      "position:fixed",
      "top:0",
      "left:0",
      "right:0",
      "z-index:2147483647",
      "background:#f39c12",
      "color:#ffffff",
      "font-family:Arial, sans-serif",
      "font-size:15px",
      "font-weight:bold",
      "text-align:center",
      "padding:12px 16px",
      "box-shadow:0 2px 6px rgba(0,0,0,0.4)",
    ].join(";");

    banner.textContent = message;
    document.documentElement.appendChild(banner);
    if (document.body) document.body.style.marginTop = "48px";
  }


  // ------------------------------------------------------------------
  // Orchestration
  // ------------------------------------------------------------------

  async function scanAndVerify() {
    const domain = window.location.hostname;
    const forms  = findLoginForms();

    if (forms.length === 0) return;

    for (const form of forms) {
      try {
        const cleaned         = cleanElement(form);
        const structuralString = serializeStructure(cleaned);
        const hash            = await sha256Hex(structuralString);
        console.log("[AuthShield] Computed Hash:", hash);

        const response = await verifyHash(domain, hash);

        // Guard: if response is undefined, background.js messaging is broken.
        // Most likely cause: missing "return true" in background.js onMessage
        // listener (see Case 1 comment in verifyHash() above).
        if (!response) {
          console.warn(
            "[AuthShield] Received undefined response from background.js.",
            "Check: does background.js onMessage listener return true for async fetch?"
          );
          continue;
        }

        if (response.status === "DANGER") {
          // Confirmed phishing/cloned portal — lock down the form immediately.
          injectDangerBanner(
            response.message || "Cloned portal detected. Do not enter credentials."
          );
          disableForm(form);

        } else if (response.status === "UNKNOWN") {
          // Portal not found in registry — advisory warning only.
          // Form remains enabled (user can still proceed at their own risk).
          // See injectUnknownBanner() for reasoning behind this change.
          injectUnknownBanner(
            response.message || "⚠ AuthShield: Unrecognized portal detected. Avoid entering credentials."
          );

        }
        // "SAFE" -> No banner, no action. Popup reflects the SAFE status.

      } catch (err) {
        console.warn("[AuthShield] Verification error for form:", err);
      }
    }
  }


  // ------------------------------------------------------------------
  // Entry Point
  // ------------------------------------------------------------------

  function init() {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", scanAndVerify);
    } else {
      // DOM already ready (e.g. script injected after load).
      scanAndVerify();
    }
  }

  init();

})();
