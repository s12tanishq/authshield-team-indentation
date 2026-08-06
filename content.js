/**
 * AuthShield - content.js
 *
 * Responsibilities:
 *   1. Scan the page for login forms.
 *   2. Strip dynamic/volatile attributes (CSRF tokens, dynamic ids, values, etc.)
 *      and remove volatile third-party subtrees (captchas, iframes) entirely.
 *   3. Serialize the cleaned structural markup into a standardized string.
 *   4. Compute a SHA-256 hash of that string using the native Web Crypto API.
 *   5. Send { action: "VERIFY_DOM_HASH", domain, hash } to background.js.
 *   6. On response:
 *        - "DANGER"  -> Red banner + disable all form inputs.
 *        - "UNKNOWN" -> Amber advisory banner, form remains enabled.
 *        - "SAFE"    -> No UI action (popup reflects status only).
 */

(() => {
  "use strict";

  // ------------------------------------------------------------------
  // Configuration
  // ------------------------------------------------------------------

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

  const DYNAMIC_ATTR_PATTERNS = [
    /^data-v-/i,       // Vue scoped ids
    /^ng-/i,           // Angular bindings
    /^_ngcontent/i,    // Angular content attributes
    /^jsaction$/i,     // Google jsaction
    /^data-reactroot$/i,
  ];

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

  // Elements matching these selectors are removed ENTIRELY before hashing —
  // not just attribute-stripped. These are third-party widgets (captchas,
  // embedded iframes) that load asynchronously and may or may not have
  // finished injecting their own markup by the time we scan, making their
  // mere presence/absence a source of hash instability unrelated to the
  // actual login form's identity.
  const VOLATILE_SUBTREE_SELECTORS = [
    ".cf-turnstile",
    "iframe",
    "[data-sitekey]",
    "template",
  ];

  const VERIFY_ENDPOINT_ACTION = "VERIFY_DOM_HASH";

  const DANGER_BANNER_ID  = "authshield-danger-banner";
  const UNKNOWN_BANNER_ID = "authshield-unknown-banner";

  // ------------------------------------------------------------------
  // Inline icons (no external CDN dependency — content scripts run on
  // arbitrary third-party pages, so we never fetch external resources)
  // ------------------------------------------------------------------

  const ICON_SHIELD_X = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9.5" y1="9" x2="14.5" y2="14"/><line x1="14.5" y1="9" x2="9.5" y2="14"/></svg>`;

  const ICON_ALERT = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;

  const ICON_CLOSE = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;


  // ------------------------------------------------------------------
  // 1. Form Discovery
  // ------------------------------------------------------------------

  function findLoginForms() {
    const forms = Array.from(document.querySelectorAll("form"));
    return forms.filter(isLikelyLoginForm);
  }

  function isLikelyLoginForm(form) {
    const passwordFields = form.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) return true;

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
   * Deep-clones the form element, removes volatile third-party subtrees
   * (captchas, iframes), then strips all dynamic/volatile attributes so
   * the structural fingerprint is stable across page loads.
   * The live DOM is NEVER mutated — always working on a clone.
   */
  function cleanElement(node) {
    const clone = node.cloneNode(true);
    removeVolatileSubtrees(clone);
    stripDynamicAttributes(clone);
    return clone;
  }

  function removeVolatileSubtrees(root) {
    VOLATILE_SUBTREE_SELECTORS.forEach((selector) => {
      root.querySelectorAll(selector).forEach((el) => el.remove());
    });
  }

  function stripDynamicAttributes(root) {
    const elements = [root, ...root.querySelectorAll("*")];

    for (const el of elements) {
      if (!(el instanceof Element)) continue;

      el.removeAttribute("value");
      el.removeAttribute("checked");
      el.removeAttribute("selected");

      const attrNames = Array.from(el.attributes).map((a) => a.name);

      for (const attrName of attrNames) {
        const lower = attrName.toLowerCase();

        const isExplicitlyDynamic  = DYNAMIC_ATTRS.has(lower);
        const matchesDynamicPattern = DYNAMIC_ATTR_PATTERNS.some((re) => re.test(lower));
        const isAllowlisted         = STRUCTURAL_ATTRS_ALLOWLIST.has(lower);

        if (isExplicitlyDynamic || matchesDynamicPattern || !isAllowlisted) {
          el.removeAttribute(attrName);
        }
      }
    }
  }

  // ------------------------------------------------------------------
  // 3. Serialization
  // ------------------------------------------------------------------

  function serializeStructure(cleanedEl) {
    normalizeAttributeOrder(cleanedEl);
    const raw = cleanedEl.outerHTML || "";
    return raw
      .replace(/\s+/g, " ")
      .replace(/>\s+</g, "><")
      .trim();
  }

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
  // ------------------------------------------------------------------

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

  function buildBanner({ id, bg, fg, icon, title, message }) {
    const banner = document.createElement("div");
    banner.id = id;
    banner.setAttribute("role", "alert");
    banner.style.cssText = [
      "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
      `background:${bg}`, `color:${fg}`,
      "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif",
      "display:flex", "align-items:center", "gap:12px",
      "padding:12px 16px", "box-shadow:0 2px 6px rgba(0,0,0,0.4)",
    ].join(";");

    const iconWrap = document.createElement("span");
    iconWrap.style.cssText = "flex-shrink:0;display:flex;";
    iconWrap.innerHTML = icon;

    const textWrap = document.createElement("div");
    textWrap.style.cssText = "flex:1;text-align:left;";

    const titleEl = document.createElement("div");
    titleEl.style.cssText = "font-size:14px;font-weight:600;";
    titleEl.textContent = title;

    const msgEl = document.createElement("div");
    msgEl.style.cssText = "font-size:12px;opacity:0.9;margin-top:2px;";
    msgEl.textContent = message;

    textWrap.appendChild(titleEl);
    textWrap.appendChild(msgEl);

    const closeBtn = document.createElement("span");
    closeBtn.setAttribute("role", "button");
    closeBtn.setAttribute("aria-label", "Dismiss");
    closeBtn.style.cssText = "flex-shrink:0;cursor:pointer;display:flex;opacity:0.85;";
    closeBtn.innerHTML = ICON_CLOSE;
    closeBtn.addEventListener("click", () => {
      banner.remove();
      if (document.body) document.body.style.marginTop = "0";
    });

    banner.appendChild(iconWrap);
    banner.appendChild(textWrap);
    banner.appendChild(closeBtn);
    return banner;
  }

  function injectDangerBanner(message) {
    if (document.getElementById(DANGER_BANNER_ID)) return;

    const banner = buildBanner({
      id: DANGER_BANNER_ID,
      bg: "#7f1d1d",
      fg: "#ffffff",
      icon: ICON_SHIELD_X,
      title: "AuthShield: Cloned portal detected",
      message: message || "Do not enter your credentials on this page.",
    });

    document.documentElement.appendChild(banner);
    if (document.body) document.body.style.marginTop = banner.offsetHeight + "px";
  }

  function injectUnknownBanner(message) {
    if (document.getElementById(UNKNOWN_BANNER_ID)) return;

    const banner = buildBanner({
      id: UNKNOWN_BANNER_ID,
      bg: "#78350f",
      fg: "#ffffff",
      icon: ICON_ALERT,
      title: "AuthShield: Unrecognized portal",
      message: message || "We don't have a baseline for this site yet — proceed with caution.",
    });

    document.documentElement.appendChild(banner);
    if (document.body) document.body.style.marginTop = banner.offsetHeight + "px";
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

  // ------------------------------------------------------------------
  // Orchestration
  // ------------------------------------------------------------------

  async function scanAndVerify() {
    const domain = window.location.hostname;
    const forms  = findLoginForms();

    if (forms.length === 0) return;

    for (const form of forms) {
      try {
        const cleaned          = cleanElement(form);
        const structuralString = serializeStructure(cleaned);
        const hash              = await sha256Hex(structuralString);
        console.log("[AuthShield DEBUG]", domain, hash);

        const response = await verifyHash(domain, hash);

        if (!response) {
          console.warn(
            "[AuthShield] Received undefined response from background.js.",
            "Check: does background.js onMessage listener return true for async fetch?"
          );
          continue;
        }

        if (response.status === "DANGER") {
          injectDangerBanner(response.message);
          disableForm(form);
        } else if (response.status === "UNKNOWN") {
          injectUnknownBanner(response.message);
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
      scanAndVerify();
    }
  }

  init();

})();
