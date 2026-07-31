(function attachRender(global) {
  "use strict";

  function readConfigFromForm() {
    var config = {};

    global.DoBotAdmin.CONFIG_FIELDS.forEach(function readField(field) {
      config[field.id] = global.DoBotAdmin.getValue(field.id);
    });

    return config;
  }

  function writeConfigToForm(config) {
    global.DoBotAdmin.CONFIG_FIELDS.forEach(function writeField(field) {
      global.DoBotAdmin.setValue(field.id, config[field.id] || field.defaultValue);
    });
  }

  function renderValidation(validation) {
    global.DoBotAdmin.clearFieldErrors();

    Object.keys(validation.errors).forEach(function showFieldError(fieldId) {
      global.DoBotAdmin.setFieldError(fieldId, validation.errors[fieldId]);
    });

    renderStatus(validation);
  }

  function renderStatus(validation) {
    var status = global.DoBotAdmin.getElement("#configStatus");
    var alert = global.DoBotAdmin.getElement("#setupAlert");
    var title = global.DoBotAdmin.getElement("#alertTitle");
    var message = global.DoBotAdmin.getElement("#alertMessage");
    var errorCount = Object.keys(validation.errors).length;

    status.classList.toggle("ready", validation.isValid);
    status.classList.toggle("needs-review", !validation.isValid);
    alert.classList.toggle("alert-success", validation.isValid);
    alert.classList.toggle("alert-warning", !validation.isValid);

    if (validation.isValid) {
      global.DoBotAdmin.setText(status, "Ready");
      global.DoBotAdmin.setText(title, "Configuration ready");
      global.DoBotAdmin.setText(message, "Use the generated command to start DoBot Shield with these values.");
      return;
    }

    global.DoBotAdmin.setText(status, "Review needed");
    global.DoBotAdmin.setText(title, "Review the configuration");
    global.DoBotAdmin.setText(message, errorCount + " field(s) need attention.");
  }

  function renderCommand(config, mode) {
    var output = global.DoBotAdmin.getElement("#commandOutput");
    output.value = global.DoBotAdmin.buildCommand(config, mode);
  }

  function renderActiveTab(mode) {
    global.DoBotAdmin.getElements("[data-command-tab]").forEach(function updateTab(tab) {
      var isActive = tab.dataset.commandTab === mode;
      tab.classList.toggle("active", isActive);
      tab.setAttribute("aria-selected", String(isActive));
    });
  }

  function focusFirstInvalid(validation) {
    var firstInvalidId = Object.keys(validation.errors)[0];

    if (firstInvalidId) {
      global.DoBotAdmin.getElement("#" + firstInvalidId).focus();
    }
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    focusFirstInvalid: focusFirstInvalid,
    readConfigFromForm: readConfigFromForm,
    renderActiveTab: renderActiveTab,
    renderCommand: renderCommand,
    renderValidation: renderValidation,
    writeConfigToForm: writeConfigToForm
  });
})(window);
