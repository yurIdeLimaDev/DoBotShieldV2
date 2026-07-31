(function attachValidators(global) {
  "use strict";

  function result(isValid, message) {
    return { isValid: isValid, message: message || "" };
  }

  function isBlank(value) {
    return String(value || "").trim() === "";
  }

  function splitCsv(value) {
    return String(value || "").split(",").map(function trim(item) {
      return item.trim();
    }).filter(Boolean);
  }

  function fieldMin(fieldId) {
    var field = global.DoBotAdmin.CONFIG_FIELDS.find(function find(candidate) {
      return candidate.id === fieldId;
    });
    return field && field.min;
  }

  function fieldMax(fieldId) {
    var field = global.DoBotAdmin.CONFIG_FIELDS.find(function find(candidate) {
      return candidate.id === fieldId;
    });
    return field && field.max;
  }

  function validateTargetUrl(value) {
    if (isBlank(value)) {
      return result(false, "Enter the protected application's URL.");
    }
    try {
      var parsed = new URL(String(value).trim());
      if (!["http:", "https:"].includes(parsed.protocol)) {
        return result(false, "Use an http:// or https:// URL.");
      }
      if (parsed.username || parsed.password || parsed.hash) {
        return result(false, "Do not include credentials or a fragment in the upstream URL.");
      }
      return result(true);
    } catch (error) {
      return result(false, "Enter a valid absolute URL.");
    }
  }

  function validateProxyPort(value) {
    var clean = String(value || "").trim();
    var match = clean.match(/^(?:(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]))?:([0-9]{1,5})$/);
    if (!match) {
      return result(false, "Use :443, host:port, or [ipv6]:port syntax.");
    }
    var port = Number(match[1]);
    return Number.isInteger(port) && port >= 1 && port <= 65535
      ? result(true)
      : result(false, "The port must be between 1 and 65535.");
  }

  function validateNumber(value, label, integer, min, max) {
    var number = Number(String(value || "").trim());
    if (!Number.isFinite(number) || (integer && !Number.isInteger(number)) || number < min) {
      return result(false, label + " must be " + (integer ? "an integer " : "") + "of at least " + min + ".");
    }
    if (typeof max === "number" && number > max) {
      return result(false, label + " must be at most " + max + ".");
    }
    return result(true);
  }

  function validateBoolean(value, label) {
    return value === "true" || value === "false"
      ? result(true)
      : result(false, label + " must be true or false.");
  }

  function validateWafMode(value) {
    return ["block", "monitor", "off"].includes(String(value || "").trim())
      ? result(true)
      : result(false, "WAF mode must be block, monitor, or off.");
  }

  function validateRequiredPath(value, label) {
    return isBlank(value) ? result(false, "Enter the " + label + ".") : result(true);
  }

  function isIPv4(value) {
    var parts = String(value || "").split(".");
    return parts.length === 4 && parts.every(function validPart(part) {
      return /^\d{1,3}$/.test(part) && !(part.length > 1 && part.charAt(0) === "0") && Number(part) <= 255;
    });
  }

  function isIPv6(value) {
    var clean = String(value || "").trim();
    if (!clean.includes(":") || clean.includes("%") || clean.length > 45) {
      return false;
    }
    try {
      return new URL("http://[" + clean + "]/" ).hostname.length > 0;
    } catch (error) {
      return false;
    }
  }

  function isIPOrCIDR(value) {
    var parts = String(value || "").split("/");
    if (parts.length === 1) {
      return isIPv4(parts[0]) || isIPv6(parts[0]);
    }
    if (parts.length !== 2 || !/^\d{1,3}$/.test(parts[1])) {
      return false;
    }
    var prefix = Number(parts[1]);
    return (isIPv4(parts[0]) && prefix <= 32) || (isIPv6(parts[0]) && prefix <= 128);
  }

  function validateOptionalIpCsv(value) {
    var invalid = splitCsv(value).filter(function invalidEntry(item) { return !isIPOrCIDR(item); });
    return invalid.length ? result(false, "Review these IP/CIDR entries: " + invalid.join(", ")) : result(true);
  }

  function validateAllowedHosts(value) {
    var hostPattern = /^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/;
    var invalid = splitCsv(value).filter(function invalidHost(item) {
      return !hostPattern.test(item) && !isIPv4(item) && !isIPv6(item);
    });
    return invalid.length ? result(false, "Review these host patterns: " + invalid.join(", ")) : result(true);
  }

  function validateAllowedMethods(value) {
    var methods = splitCsv(value).map(function upper(method) { return method.toUpperCase(); });
    if (!methods.length) {
      return result(false, "Enter at least one allowed HTTP method.");
    }
    var invalid = methods.filter(function invalidMethod(method) {
      return !/^[!#$%&'*+\-.^_`|~0-9A-Z]+$/.test(method) || method === "TRACE" || method === "TRACK";
    });
    return invalid.length ? result(false, "Remove invalid or unsafe methods: " + invalid.join(", ")) : result(true);
  }

  function validateCsp(value) {
    return /[\r\n]/.test(String(value || ""))
      ? result(false, "The CSP value must not contain line breaks.")
      : result(true);
  }

  function validateWebSocketOrigins(value) {
    var hostPattern = /^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/;
    var invalid = splitCsv(value).filter(function invalidOrigin(item) {
      if (item === "*") {
        return true;
      }
      var host = item;
      if (item.includes("://")) {
        try {
          var parsed = new URL(item);
          if (!["http:", "https:"].includes(parsed.protocol) || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.username || parsed.password) {
            return true;
          }
          host = parsed.hostname;
        } catch (error) {
          return true;
        }
      }
      if (host.charAt(0) === "[" && host.charAt(host.length - 1) === "]") {
        host = host.slice(1, -1);
      }
      return !hostPattern.test(host) && !isIPv4(host) && !isIPv6(host);
    });
    return invalid.length ? result(false, "Review these WebSocket origin patterns: " + invalid.join(", ")) : result(true);
  }

  function validateField(fieldId, value) {
    var booleans = {
      httpMode: "HTTP mode",
      preserveHost: "Host preservation",
      enableWaf: "WAF",
      enableResponseInspection: "response inspection",
      enableResponseXss: "response XSS inspection",
      responseDiagnosticsErrorsOnly: "error-only diagnostic inspection",
      enableWebSocketProtection: "WebSocket protection",
      webSocketInspectBinary: "WebSocket binary inspection",
      enableRateLimit: "rate limiting",
      insecureSkipVerify: "insecure upstream TLS",
      hardenCookies: "cookie hardening",
      enableTraining: "training mode",
      trainingRedactSensitive: "training log redaction"
    };
    var integers = {
      burstLimit: "Burst limit",
      maxConns: "Per-IP concurrent requests",
      maxTrackedIps: "Tracked IPs",
      maxConcurrentRequests: "Global concurrent requests",
      maxBodySize: "Maximum body size",
      maxDecodedBodySize: "Maximum decoded body size",
      responseInspectionLimit: "Response inspection limit",
      maxUrlLength: "Maximum URL length",
      maxHeaderBytes: "Maximum header bytes",
      maxHeaderCount: "Maximum header count",
      webSocketMaxMessageSize: "Maximum WebSocket message size",
      webSocketBurstLimit: "WebSocket burst limit"
    };
    if (booleans[fieldId]) {
      return validateBoolean(value, booleans[fieldId]);
    }
    if (integers[fieldId]) {
      return validateNumber(value, integers[fieldId], true, fieldMin(fieldId), fieldMax(fieldId));
    }
    switch (fieldId) {
    case "targetUrl": return validateTargetUrl(value);
    case "proxyPort": return validateProxyPort(value);
    case "wafMode": return validateWafMode(value);
    case "rateLimit": return validateNumber(value, "Requests per second", false, fieldMin(fieldId), fieldMax(fieldId));
    case "webSocketMessagesPerSecond": return validateNumber(value, "WebSocket messages per second", false, fieldMin(fieldId), fieldMax(fieldId));
    case "certFile": return validateRequiredPath(value, "certificate file");
    case "keyFile": return validateRequiredPath(value, "private-key file");
    case "trustedProxies":
    case "blockedIps": return validateOptionalIpCsv(value);
    case "allowedHosts": return validateAllowedHosts(value);
    case "webSocketAllowedOrigins": return validateWebSocketOrigins(value);
    case "allowedMethods": return validateAllowedMethods(value);
    case "contentSecurityPolicy": return validateCsp(value);
    default: return result(true);
    }
  }

  function validateConfig(config) {
    var errors = {};
    global.DoBotAdmin.CONFIG_FIELDS.forEach(function validateKnownField(field) {
      var validation = validateField(field.id, config[field.id]);
      if (!validation.isValid) {
        errors[field.id] = validation.message;
      }
    });
    if (config.httpMode === "true") {
      delete errors.certFile;
      delete errors.keyFile;
    }
    return { isValid: Object.keys(errors).length === 0, errors: errors };
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    splitCsv: splitCsv,
    validateConfig: validateConfig,
    validateField: validateField
  });
})(window);
