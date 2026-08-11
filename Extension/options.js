/**
 * options.js
 * Loads and saves user-configurable extension settings.
 */

async function loadOptions() {
  const settings = await getSettings();
  document.getElementById("backendUrl").value = settings.backendUrl;
  document.getElementById("allowActiveScan").checked = !!settings.allowActiveScan;
}

document.getElementById("saveBtn").addEventListener("click", async () => {
  const backendUrl = document.getElementById("backendUrl").value.trim() || "http://127.0.0.1:5000";
  const allowActiveScan = document.getElementById("allowActiveScan").checked;

  await updateSettings({ backendUrl, allowActiveScan });

  const status = document.getElementById("statusMsg");
  status.textContent = "Settings saved.";
  setTimeout(() => (status.textContent = ""), 2000);
});

loadOptions();
