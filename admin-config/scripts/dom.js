(function attachDom(global) {
  "use strict";

  function getElement(selector, root) {
    return (root || document).querySelector(selector);
  }

  function getElements(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function setText(element, value) {
    element.textContent = value;
  }

  function setValue(fieldId, value) {
    var field = getElement("#" + fieldId);

    if (field.type === "checkbox") {
      field.checked = String(value) === "true";
      return;
    }

    field.value = value;
  }

  function getValue(fieldId) {
    var field = getElement("#" + fieldId);

    if (field.type === "checkbox") {
      return field.checked ? "true" : "false";
    }

    return field.value;
  }

  function setFieldError(fieldId, message) {
    var input = getElement("#" + fieldId);
    var error = getElement('[data-error-for="' + fieldId + '"]');

    if (input) { input.classList.toggle("invalid", Boolean(message)); }
    if (error) { error.textContent = message || ""; }
  }

  function clearFieldErrors() {
    global.DoBotAdmin.CONFIG_FIELDS.forEach(function clearField(field) {
      setFieldError(field.id, "");
    });
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    clearFieldErrors: clearFieldErrors,
    getElement: getElement,
    getElements: getElements,
    getValue: getValue,
    setFieldError: setFieldError,
    setText: setText,
    setValue: setValue
  });
})(window);
