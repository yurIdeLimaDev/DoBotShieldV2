(function attachClipboard(global) {
  "use strict";

  function copyText(text, sourceElement) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }

    return fallbackCopy(text, sourceElement);
  }

  function fallbackCopy(text, sourceElement) {
    sourceElement.focus();
    sourceElement.select();

    return new Promise(function resolveCopy(resolve, reject) {
      var copied = document.execCommand("copy");

      if (copied) {
        resolve();
      } else {
        reject(new Error("copy_failed"));
      }
    });
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    copyText: copyText
  });
})(window);
