  // =================================================================
  // 24-init.js: Start-up: load products and restore what was open last time.
  // =================================================================

  // =================================================================
  // Load the product registry up front so product detection, feature gating
  // and the Explorer default work from the first render (it is tiny).
  loadProducts();

  // Put back what was open last time; an empty first tab if there was
  // nothing, or nothing readable.
  restoreState().then((restored) => {
    if (!restored) createSwitch();
    appLog('info', 'Page loaded', {
      librariesLoaded: librariesLoaded(), restored: !!restored
    });
  });
