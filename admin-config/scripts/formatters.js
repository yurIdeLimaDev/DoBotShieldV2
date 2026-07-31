(function attachFormatters(global) {
  "use strict";

  var CSV_FIELDS = ["trustedProxies", "allowedHosts", "allowedMethods", "wafAllowlist", "blockedIps", "webSocketAllowedOrigins"];

  function normalizeConfig(config) {
    var normalized = {};
    global.DoBotAdmin.CONFIG_FIELDS.forEach(function normalizeField(field) {
      var value = trimValue(config[field.id]);
      normalized[field.id] = CSV_FIELDS.includes(field.id)
        ? global.DoBotAdmin.splitCsv(value).join(",")
        : value;
    });
    return normalized;
  }

  function trimValue(value) {
    return String(value || "").trim();
  }

  function toEnvPairs(config) {
    var normalizedConfig = normalizeConfig(config);
    return global.DoBotAdmin.CONFIG_FIELDS.map(function mapField(field) {
      return { key: field.env, value: normalizedConfig[field.id] };
    });
  }

  function buildAccessUrl(config) {
    var address = String(config.proxyPort || ":443").trim();
    var scheme = config.httpMode === "true" ? "http" : "https";
    if (address.charAt(0) === ":") {
      address = "localhost" + address;
    }
    return scheme + "://" + address;
  }

  function buildPowerShell(config) {
    var lines = toEnvPairs(config).map(function mapPair(pair) {
      return "$env:" + pair.key + " = " + quotePowerShell(pair.value);
    });
    lines.unshift("# Access URL: " + buildAccessUrl(config));
    lines.push("go build -o dobotshield.exe .");
    lines.push(".\\dobotshield.exe");
    return lines.join("\n");
  }

  function buildBash(config) {
    var lines = toEnvPairs(config).map(function mapPair(pair) {
      return "export " + pair.key + "=" + quoteBash(pair.value);
    });
    lines.unshift("# Access URL: " + buildAccessUrl(config));
    lines.push("go build -o dobotshield .");
    lines.push("./dobotshield");
    return lines.join("\n");
  }

  function buildDotEnv(config) {
    var header = "# Access URL: " + buildAccessUrl(config);
    var body = toEnvPairs(config).map(function mapPair(pair) {
      return pair.key + "=" + quoteDotEnv(pair.value);
    }).join("\n");
    return header + "\n" + body;
  }

  function buildCommand(config, mode) {
    return { powershell: buildPowerShell, bash: buildBash, dotenv: buildDotEnv }[mode](config);
  }

  function quotePowerShell(value) {
    return "'" + String(value).replace(/'/g, "''") + "'";
  }

  function quoteBash(value) {
    return "'" + String(value).replace(/'/g, "'\\''") + "'";
  }

  function quoteDotEnv(value) {
    return '"' + String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    buildCommand: buildCommand,
    buildDotEnv: buildDotEnv,
    normalizeConfig: normalizeConfig
  });
})(window);
