const FEED_URL = "https://openphish.com/feed.txt";
const MAX_RULES = 4000;
const PROTECTED_HOSTS = [
  "google.com",
  "paypal.com",
  "microsoft.com",
  "amazon.com",
  "apple.com",
  "github.com",
];

function isProtected(host) {
  return PROTECTED_HOSTS.some((d) => host === d || host.endsWith("." + d));
}

function buildRules(text) {
  const seen = new Set();
  const rules = [];

  for (const line of text.split("\n")) {
    if (rules.length >= MAX_RULES) break;

    let url;
    try {
      url = new URL(line.trim());
    } catch {
      continue; // not a valid URL
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") continue;

    const target = url.hostname + url.pathname;
    if (/[*|^]/.test(target)) continue; // would change how the filter behaves
    if (isProtected(url.hostname) && url.pathname === "/") continue;
    if (seen.has(target)) continue;
    seen.add(target);

    rules.push({
      id: rules.length + 1,
      priority: 1,
      action: {
        type: "redirect",
        redirect: {
          extensionPath: `/blocked/blocked.html?site=${encodeURIComponent(url.hostname)}`,
        },
      },
      condition: { urlFilter: `||${target}`, resourceTypes: ["main_frame"] },
    });
  }
  return rules;
}

async function refreshFeed() {
  try {
    const res = await fetch(FEED_URL, { cache: "no-store" });
    if (!res.ok) throw new Error(`Feed returned ${res.status}`);

    const rules = buildRules(await res.text());
    if (rules.length === 0) throw new Error("Feed produced no usable rules");

    const { settings } = await chrome.storage.local.get("settings");
    if (settings && settings.protectionEnabled === false) return; // turned off mid-download

    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((r) => r.id),
      addRules: rules,
    });

    await chrome.storage.local.set({
      feedStatus: { ok: true, updatedAt: Date.now(), count: rules.length },
    });
  } catch (err) {
    console.error("PhishShield: feed refresh failed, keeping old rules", err);
    const { feedStatus } = await chrome.storage.local.get("feedStatus");
    await chrome.storage.local.set({
      feedStatus: { ...feedStatus, ok: false },
    });
  }
}

async function clearFeedRules() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((r) => r.id),
  });
}
