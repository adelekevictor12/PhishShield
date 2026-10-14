// OpenPhish provides URL-level phishing indicators. CERT Polska provides
// active abusive domains. OpenPhish is processed first when the rule cap is hit.
const FEEDS = [
  {
    name: "OpenPhish",
    url: "https://openphish.com/feed.txt",
    parse: parseUrlFeed,
  },
  {
    name: "CERT Polska",
    url: "https://hole.cert.pl/domains/v2/domains.txt",
    parse: parseDomainFeed,
  },
];

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
  return PROTECTED_HOSTS.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function parseUrlFeed(text) {
  return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function parseDomainFeed(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((domain) => `https://${domain}/`);
}

function toRuleTarget(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.username || url.password) return null;

  const host = url.hostname.toLowerCase();
  const path = url.pathname || "/";
  if (!host || /[*|^]/.test(host + path)) return null;
  if (isProtected(host) && path === "/") return null;

  return { host, path };
}

function buildRules(urls) {
  const seen = new Set();
  const rules = [];

  for (const value of urls) {
    if (rules.length >= MAX_RULES) break;

    const target = toRuleTarget(value);
    if (!target) continue;

    const key = `${target.host}${target.path}`;
    if (seen.has(key)) continue;
    seen.add(key);

    rules.push({
      id: rules.length + 1,
      priority: 1,
      action: {
        type: "redirect",
        redirect: {
          extensionPath: `/blocked/blocked.html?site=${encodeURIComponent(target.host)}`,
        },
      },
      condition: { urlFilter: `||${key}`, resourceTypes: ["main_frame"] },
    });
  }

  return rules;
}

async function fetchFeed(feed) {
  const response = await fetch(feed.url, { cache: "no-store" });
  if (!response.ok) throw new Error(`${feed.name} returned HTTP ${response.status}`);

  const items = feed.parse(await response.text());
  if (items.length === 0) throw new Error(`${feed.name} returned an empty feed`);
  return items;
}

async function refreshFeed() {
  const results = await Promise.allSettled(FEEDS.map(fetchFeed));
  const urls = [];
  const sourceStatus = {};

  results.forEach((result, index) => {
    const feed = FEEDS[index];
    if (result.status === "fulfilled") {
      for (const value of result.value) urls.push(value);
      sourceStatus[feed.name] = { ok: true, count: result.value.length };
    } else {
      console.error(`PhishShield: ${feed.name} refresh failed`, result.reason);
      sourceStatus[feed.name] = { ok: false, error: String(result.reason) };
    }
  });

  const rules = buildRules(urls);
  if (rules.length === 0) {
    console.error("PhishShield: no usable feed rules; keeping existing rules");
    const { feedStatus } = await chrome.storage.local.get("feedStatus");
    await chrome.storage.local.set({
      feedStatus: { ...feedStatus, ok: false, sources: sourceStatus },
    });
    return;
  }

  const { settings } = await chrome.storage.local.get("settings");
  if (settings?.protectionEnabled === false) return;

  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((rule) => rule.id),
      addRules: rules,
    });

    await chrome.storage.local.set({
      feedStatus: {
        ok: results.some((result) => result.status === "fulfilled"),
        updatedAt: Date.now(),
        count: rules.length,
        limitReached: rules.length === MAX_RULES,
        sources: sourceStatus,
      },
    });
  } catch (err) {
    console.error("PhishShield: could not update dynamic rules; keeping existing rules", err);
    const { feedStatus } = await chrome.storage.local.get("feedStatus");
    await chrome.storage.local.set({ feedStatus: { ...feedStatus, ok: false } });
  }
}

async function clearFeedRules() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((rule) => rule.id),
  });
}
