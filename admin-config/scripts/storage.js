(function attachStorage(global) {
  "use strict";

  var STORAGE_KEY = "dobotshield.admin.config";

  function loadSavedConfig() {
    try {
      var savedValue = localStorage.getItem(STORAGE_KEY);
      return savedValue ? JSON.parse(savedValue) : null;
    } catch (error) {
      return null;
    }
  }

  function saveConfig(config) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
    } catch (error) {
      return false;
    }

    return true;
  }

  function clearSavedConfig() {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (error) {
      return false;
    }

    return true;
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    clearSavedConfig: clearSavedConfig,
    loadSavedConfig: loadSavedConfig,
    saveConfig: saveConfig
  });
})(window);
