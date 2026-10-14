chrome.runtime.onInstalled.addListener(async () => {
  const { settings } = await chrome.storage.local.get("settings");
  if (!settings) {
    await chrome.storage.local.set({
      settings: { protectionEnabled: true },
      events: [],
    });
  }
});

// Turn blocking on or off when the popup changes the setting
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local" || !changes.settings) return;

  const enabled = changes.settings.newValue?.protectionEnabled;

  await chrome.declarativeNetRequest.updateEnabledRulesets(
    enabled
      ? { enableRulesetIds: ["ruleset_1"] }
      : { disableRulesetIds: ["ruleset_1"] },
  );
});
