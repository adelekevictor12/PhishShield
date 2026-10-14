async function init() {
  const settings = await PhishStore.getSettings();
  document.getElementById("status").textContent = settings.protectionEnabled
    ? "Protection: ON"
    : "Protection: OFF";
}

init();
