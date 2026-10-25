import init from "/pkg/admin.js";
try { await init(); } catch (error) {
  console.error(error);
  document.getElementById("app").textContent="The audit console could not start. Reload the page or contact your administrator.";
}
