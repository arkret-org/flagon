const startup = document.getElementById('arkret-startup');
const retry = document.getElementById('arkret-startup-retry');
retry?.addEventListener('click', () => window.location.reload());

try {
  // Dynamic import also catches module download failures before WASM initialization.
  const { default: init } = await import('/pkg/admin.js');
  await init();
  startup?.remove();
} catch (error) {
  console.error('Flagon Admin could not start', error);
  if (startup) {
    startup.setAttribute('role', 'alert');
    startup.setAttribute('aria-busy', 'false');
    document.getElementById('arkret-startup-message').textContent =
      'Flagon Admin could not start. Check your connection and reload to try again.';
    startup.querySelector('.startup-spinner').hidden = true;
    retry.hidden = false;
  }
}
