(function attachDownload(global) {
  "use strict";

  function downloadText(filename, content) {
    var blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");

    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    downloadText: downloadText
  });
})(window);
