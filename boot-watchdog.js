window.setTimeout(() => {
  if (!window.__LPS_CONTROL_CENTER_BOOTED__) {
    const status = document.getElementById('bootStatus');
    if (status) {
      status.textContent = 'Falha ao carregar o módulo de autenticação. Atualize a página; se persistir, verifique o console do navegador.';
    }
  }
}, 8000);
