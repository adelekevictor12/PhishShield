const PhishStore = {
  async getSettings() {
    const { settings } = await chrome.storage.local.get("settings");
    return settings || { protectionEnabled: true };
  },

  async setProtection(enabled) {
    const settings = await this.getSettings();
    await chrome.storage.local.set({
      settings: { ...settings, protectionEnabled: enabled },
    });
  },

  async getEvents() {
    const { events } = await chrome.storage.local.get("events");
    return events || [];
  },

  async addEvent(domain) {
    const events = await this.getEvents();
    events.unshift({ domain, timestamp: Date.now() });
    await chrome.storage.local.set({ events: events.slice(0, 50) });
  },
};
