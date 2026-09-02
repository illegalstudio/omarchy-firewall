// Pure parsing and formatting for the firewall panel. No Qt types in here, so
// it can be exercised with plain node (see test/run.js).
//
// Everything the panel displays comes from three world-readable files:
//
//   /etc/ufw/ufw.conf        ENABLED / LOGLEVEL
//   /etc/default/ufw         default policies, IPV6
//   /etc/ufw/user{,6}.rules  the rules, as "### tuple ###" lines
//
// which is why the panel needs no privileges to show anything. `ufw status`
// would need root, and asking for a password to refresh a bar widget is not a
// thing anyone would keep enabled.
//
// The tuple layout is ufw's own (backend_iptables.py, _read_rules / _write_rules):
//
//   ### tuple ### action proto dport dst sport src [dapp sapp] ifaces [comment=hex]
//
// with 6/8 fields in the legacy form that omits the trailing direction, 7/9
// with it, an "in"/"out"/"in_eth0"/"in_eth0!out_eth1" direction token, and a
// "route:" prefix on the action for forward rules.

var ANYWHERE_V4 = "0.0.0.0/0"
var ANYWHERE_V6 = "::/0"
var MAX_RULES_PER_FAMILY = 512
var MAX_RENDERED_ROWS = 512

function isAnywhere(address) {
  return address === ANYWHERE_V4 || address === ANYWHERE_V6 || address === "any" || address === ""
}

function hexDecode(hex) {
  var value = String(hex || "")
  if (value === "" || value.length % 2 !== 0 || !/^[0-9A-Fa-f]+$/.test(value)) return ""
  var out = ""
  for (var i = 0; i < value.length; i += 2) {
    out += String.fromCharCode(parseInt(value.substr(i, 2), 16))
  }
  return out
}

// ------------------------------------------------------------------- ufw.conf

function parseUfwConf(text) {
  var enabled = false
  var logLevel = ""
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line === "" || line.charAt(0) === "#") continue
    var match = line.match(/^ENABLED\s*=\s*"?(\w+)"?/)
    if (match) { enabled = match[1].toLowerCase() === "yes"; continue }
    match = line.match(/^LOGLEVEL\s*=\s*"?([\w-]+)"?/)
    if (match) logLevel = match[1]
  }
  return { enabled: enabled, logLevel: logLevel }
}

function parseDefaults(text) {
  var result = { input: "", output: "", forward: "", ipv6: false }
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line === "" || line.charAt(0) === "#") continue
    var match = line.match(/^DEFAULT_(INPUT|OUTPUT|FORWARD)_POLICY\s*=\s*"?(\w+)"?/)
    if (match) {
      result[match[1].toLowerCase()] = match[2].toLowerCase()
      continue
    }
    match = line.match(/^IPV6\s*=\s*"?(\w+)"?/)
    if (match) result.ipv6 = match[1].toLowerCase() === "yes"
  }
  return result
}

function policyLabel(policy) {
  if (policy === "drop") return "deny"
  if (policy === "accept") return "allow"
  if (policy === "reject") return "reject"
  return policy || "unknown"
}

// --------------------------------------------------------------------- tuples

function parseRules(text, family) {
  var rules = []
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var rule = parseTuple(lines[i], family)
    if (rule) {
      if (rules.length >= MAX_RULES_PER_FAMILY) {
        throw new Error("Rule count exceeds the safety limit of " + MAX_RULES_PER_FAMILY
          + " per address family")
      }
      rules.push(rule)
    }
  }
  return rules
}

function parseTuple(line, family) {
  var raw = String(line || "")
  if (raw.indexOf("### tuple ###") !== 0) return null

  var comment = ""
  var body = raw.substring("### tuple ###".length)
  var commentAt = body.indexOf(" comment=")
  if (commentAt !== -1) {
    comment = hexDecode(body.substring(commentAt + " comment=".length).trim())
    body = body.substring(0, commentAt)
  }

  var fields = body.trim().split(/\s+/)
  if (fields.length < 6 || fields.length > 9) return null

  var action = fields[0]
  var forward = false
  if (action.indexOf(":") !== -1) {
    // route rules are written as "route:allow"
    forward = true
    action = action.split(":")[1]
  }

  // ufw stores the log level in the action itself ("allow_log", "deny_log-all").
  var logType = ""
  if (action.indexOf("_") !== -1) {
    var actionParts = action.split("_")
    action = actionParts[0]
    logType = actionParts[1]
  }

  var dapp = ""
  var sapp = ""
  if (fields.length >= 8) {
    dapp = fields[6] === "-" ? "" : fields[6].replace(/%20/g, " ")
    sapp = fields[7] === "-" ? "" : fields[7].replace(/%20/g, " ")
  }

  // The direction token is last, and only present in the 7- and 9-field forms.
  var direction = "in"
  var interfaceIn = ""
  var interfaceOut = ""
  if (fields.length === 7 || fields.length === 9) {
    var ifaces = fields[fields.length - 1]
    direction = ifaces.split("_")[0]
    if (ifaces.indexOf("_") !== -1) {
      if (ifaces.indexOf("!") !== -1) {
        interfaceIn = ifaces.split("!")[0].split("_").slice(1).join("_")
        interfaceOut = ifaces.split("!")[1].split("_").slice(1).join("_")
      } else if (ifaces.indexOf("in_") === 0) {
        interfaceIn = ifaces.substring(3)
      } else if (ifaces.indexOf("out_") === 0) {
        interfaceOut = ifaces.substring(4)
      }
    }
  }
  if (direction !== "in" && direction !== "out") direction = "in"

  return {
    family: family === 6 ? 6 : 4,
    action: action,
    logType: logType,
    forward: forward,
    protocol: fields[1],
    dport: fields[2],
    dst: fields[3],
    sport: fields[4],
    src: fields[5],
    dapp: dapp,
    sapp: sapp,
    direction: direction,
    interfaceIn: interfaceIn,
    interfaceOut: interfaceOut,
    comment: comment
  }
}

// --------------------------------------------------------------- presentation

function portLabel(port, protocol) {
  if (port === "any" || port === "") return ""
  return protocol && protocol !== "any" ? port + "/" + protocol : port
}

function endpointLabel(address, port, app, protocol) {
  if (app) return app
  var place = isAnywhere(address) ? "Anywhere" : address
  var portText = portLabel(port, protocol)
  if (portText === "") return place
  if (place === "Anywhere") return portText
  return place + " " + portText
}

function actionLabel(rule) {
  if (!rule) return ""
  var parts = [String(rule.action || "").toUpperCase()]
  parts.push(rule.forward ? "FWD" : String(rule.direction || "in").toUpperCase())
  return parts.join(" ")
}

function toLabel(rule) {
  return rule ? endpointLabel(rule.dst, rule.dport, rule.dapp, rule.protocol) : ""
}

function fromLabel(rule) {
  return rule ? endpointLabel(rule.src, rule.sport, rule.sapp, rule.protocol) : ""
}

// ---------------------------------------------------------- deletable specs
//
// The tokens handed to the privileged helper. Only rule shapes that can be
// expressed exactly in ufw's own rule syntax get tokens; everything else comes
// back null and the row is shown read-only rather than being deleted by an
// approximation of itself.
//
// Deleting by rule spec is deliberate. `ufw status numbered` interleaves the v4
// and v6 rules and renumbers on every change, so a number worked out from these
// files can point at a different rule by the time it is used, and for a
// firewall deleting the wrong rule means opening a port.

function ruleSpecTokens(rule) {
  if (!rule) return null
  if (rule.forward) return null                             // route rules use another verb
  if (rule.interfaceIn || rule.interfaceOut) return null
  if (rule.sapp) return null                                // source app profiles have no simple form
  if (String(rule.dport).indexOf(",") !== -1) return null    // multiport lists
  if (String(rule.sport).indexOf(",") !== -1) return null

  var tokens = []
  var srcAnywhere = isAnywhere(rule.src) && rule.sport === "any"
  var dstAnywhere = isAnywhere(rule.dst)

  if (rule.dapp) {
    // Application profile rules only round-trip through the simple form.
    if (!srcAnywhere || !dstAnywhere) return null
    if (rule.direction === "out") tokens.push("out")
    tokens.push(rule.dapp)
    return tokens
  }

  if (srcAnywhere && dstAnywhere && rule.dport !== "any") {
    if (rule.direction === "out") tokens.push("out")
    tokens.push(portLabel(rule.dport, rule.protocol))
    return tokens
  }

  tokens.push(rule.direction === "out" ? "out" : "in")
  if (rule.protocol && rule.protocol !== "any") tokens.push("proto", rule.protocol)
  tokens.push("from", isAnywhere(rule.src) ? "any" : rule.src)
  if (rule.sport !== "any" && rule.sport !== "") tokens.push("port", rule.sport)
  tokens.push("to", isAnywhere(rule.dst) ? "any" : rule.dst)
  if (rule.dport !== "any" && rule.dport !== "") tokens.push("port", rule.dport)
  return tokens
}

function readOnlyReason(rule) {
  if (!rule) return ""
  if (rule.forward) return "Route rule. Edit it with ufw route."
  if (rule.interfaceIn || rule.interfaceOut) return "Bound to an interface. Edit it with ufw."
  if (rule.sapp) return "Source application profile. Edit it with ufw."
  return "No single-command equivalent. Edit it with ufw."
}

// ------------------------------------------------------------------ row model
//
// ufw writes one tuple per address family for a rule that covers both, and
// deleting by spec removes both at once. Two rows would mean one of them
// silently vanishing when the other is deleted, so identical v4/v6 pairs are
// merged into a single row carrying both families.

function rowKey(rule) {
  return [
    rule.action, rule.logType, rule.protocol, rule.dport, rule.sport,
    rule.dapp, rule.sapp, rule.direction, rule.interfaceIn, rule.interfaceOut,
    rule.forward ? "fwd" : "", rule.comment,
    isAnywhere(rule.dst) ? "*" : rule.dst,
    isAnywhere(rule.src) ? "*" : rule.src
  ].join(" ")
}

function buildRows(rules4, rules6) {
  var rows = []
  var byKey = {}
  var all = [].concat(rules4 || [], rules6 || [])

  if ((rules4 || []).length > MAX_RULES_PER_FAMILY
      || (rules6 || []).length > MAX_RULES_PER_FAMILY) {
    throw new Error("Rule count exceeds the per-family safety limit")
  }

  for (var i = 0; i < all.length; i++) {
    var rule = all[i]
    var key = rowKey(rule)
    if (Object.prototype.hasOwnProperty.call(byKey, key)) {
      var existing = rows[byKey[key]]
      if (existing.families.indexOf(rule.family) === -1) {
        existing.families.push(rule.family)
        existing.families.sort()
        existing.familyLabel = familyLabel(existing.families)
      }
      continue
    }
    var tokens = ruleSpecTokens(rule)
    if (rows.length >= MAX_RENDERED_ROWS) {
      throw new Error("Rendered row count exceeds the safety limit of "
        + MAX_RENDERED_ROWS)
    }
    byKey[key] = rows.length
    rows.push({
      rule: rule,
      families: [rule.family],
      familyLabel: familyLabel([rule.family]),
      action: rule.action,
      actionLabel: actionLabel(rule),
      to: toLabel(rule),
      from: fromLabel(rule),
      comment: rule.comment,
      managed: isManagedComment(rule.comment),
      specTokens: tokens,
      deletable: tokens !== null,
      readOnlyReason: tokens === null ? readOnlyReason(rule) : ""
    })
  }

  return rows
}

// ----------------------------------------------------- action reconciliation

function combineActionErrors(primary, verification) {
  var first = String(primary || "").trim()
  var second = String(verification || "").trim()
  if (first === "") return second
  if (second === "") return first
  return first + ". Verification also failed: " + second
}

function generationFinished(revisions) {
  var value = revisions || {}
  return Number(value.targetState || 0) > 0
    && Number(value.targetUnit || 0) > 0
    && Number(value.state || 0) >= Number(value.targetState)
    && Number(value.unit || 0) >= Number(value.targetUnit)
}

function generationSucceeded(revisions) {
  var value = revisions || {}
  return generationFinished(value)
    && Number(value.stateSuccess || 0) >= Number(value.targetState)
    && Number(value.unitSuccess || 0) >= Number(value.targetUnit)
}

function evaluateReconciliation(kind, outcome, snapshot, expectation) {
  var actionKind = String(kind || "change")
  var result = outcome || { ok: false, error: "Unknown firewall result" }
  var state = snapshot || {}
  var expected = expectation || {}
  var fresh = state.fresh === true
  var lifecycleKnown = typeof state.configEnabled === "boolean"
    && typeof state.serviceActive === "boolean"
  var inactive = fresh && lifecycleKnown
    && state.configEnabled === false && state.serviceActive === false
  var recovery = actionKind === "enable" && !inactive
  var clearRecovery = (actionKind === "disable" || actionKind === "recovery") && inactive

  if (!fresh || !lifecycleKnown) {
    var verificationError = String(state.error || (!lifecycleKnown
      ? "The resulting firewall lifecycle is incomplete"
      : "Could not verify the resulting firewall state"))
    return {
      ok: false,
      error: combineActionErrors(result.error, verificationError),
      recovery: recovery,
      clearRecovery: false
    }
  }

  if (result.ok !== true) {
    return {
      ok: false,
      error: String(result.error || "The firewall command did not complete")
        + ". A fresh firewall snapshot was loaded.",
      recovery: recovery,
      clearRecovery: clearRecovery
    }
  }

  if (actionKind === "enable" && state.active !== true) {
    return {
      ok: false,
      error: "Enable returned successfully, but the firewall is not fully active",
      recovery: recovery,
      clearRecovery: false
    }
  }

  if ((actionKind === "disable" || actionKind === "recovery") && !inactive) {
    return {
      ok: false,
      error: "Disable returned successfully, but the firewall is not fully inactive",
      recovery: false,
      clearRecovery: false
    }
  }

  if (actionKind === "add" || actionKind === "delete" || actionKind === "reload") {
    var expectedLifecycleKnown = typeof expected.beforeConfigEnabled === "boolean"
      && typeof expected.beforeServiceActive === "boolean"
    var lifecycleChanged = !expectedLifecycleKnown
      || state.configEnabled !== expected.beforeConfigEnabled
      || state.serviceActive !== expected.beforeServiceActive
    if (lifecycleChanged) {
      return {
        ok: false,
        error: "The command returned successfully, but firewall activation state changed unexpectedly",
        recovery: false,
        clearRecovery: false
      }
    }
  }

  if (actionKind === "add" || actionKind === "delete") {
    var beforeDigest = String(expected.beforeRulesDigest || "")
    var afterDigest = String(state.rulesDigest || "")
    if (beforeDigest === "" || afterDigest === "" || beforeDigest === afterDigest) {
      return {
        ok: false,
        error: actionKind === "add"
          ? "Add returned successfully, but the persisted rule set did not change"
          : "Delete returned successfully, but the persisted rule set did not change",
        recovery: false,
        clearRecovery: false
      }
    }
  }

  return { ok: true, error: "", recovery: false, clearRecovery: clearRecovery }
}

function familyLabel(families) {
  var list = families || []
  var hasV4 = list.indexOf(4) !== -1
  var hasV6 = list.indexOf(6) !== -1
  if (hasV4 && hasV6) return "IPv4 + IPv6"
  if (hasV6) return "IPv6"
  return "IPv4"
}

// Rules Omarchy's own installer writes. Flagged so removing one is a considered
// act rather than a surprise the next time something stops working.
var MANAGED_COMMENTS = {
  "omarchy-sshd": true,
  "allow-docker-dns": true
}

function isManagedComment(comment) {
  return MANAGED_COMMENTS[String(comment || "")] === true
}

function ruleSummary(row) {
  if (!row) return ""
  return String(row.actionLabel || "") + "  " + String(row.to || "")
    + " from " + String(row.from || "")
}

// -------------------------------------------------------------- app profiles

function parseAppProfiles(text) {
  var names = []
  var seen = {}
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var match = lines[i].match(/^\s*\[([^\]]+)\]\s*$/)
    if (!match) continue
    var name = match[1].trim()
    if (name === "" || seen[name]) continue
    seen[name] = true
    names.push(name)
  }
  names.sort()
  return names
}

// ------------------------------------------------------------- input parsing
//
// The UI-side mirror of the supervisor's validator, so a typo gets an inline
// message instead of a password prompt followed by an error. The unprivileged
// supervisor parses the closed grammar again before it constructs the fixed
// pkexec, timeout and ufw argv.

var ACTIONS = { allow: true, deny: true, reject: true, limit: true }

// An application profile name as ufw itself allows it: a free-text INI section
// in /etc/ufw/applications.d. The pattern is what keeps anything that is not a
// profile name out of ufw's argv; membership in the live list is checked on top
// of it when the list is available.
var PROFILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$/
var COMMENT_PATTERN = /^[A-Za-z0-9 ._:@/+()-]{1,120}$/

function isAction(action) {
  return ACTIONS[String(action)] === true
}

function isPort(value) {
  if (!/^[0-9]{1,5}$/.test(value)) return false
  var n = parseInt(value, 10)
  return n >= 1 && n <= 65535
}

// A port, or an inclusive range whose ends are ordered. ufw accepts a reversed
// range and writes a rule that never matches, which reads in the panel as "the
// port is open" while nothing is getting through.
function isPortSpec(value) {
  if (value.indexOf(":") !== -1) {
    var parts = value.split(":")
    if (parts.length !== 2) return false
    if (!isPort(parts[0]) || !isPort(parts[1])) return false
    return parseInt(parts[0], 10) <= parseInt(parts[1], 10)
  }
  return isPort(value)
}

function isAddress(value) {
  if (value === "any") return true
  var address = value
  var mask = null
  var slash = value.indexOf("/")
  if (slash !== -1) {
    address = value.substring(0, slash)
    mask = value.substring(slash + 1)
    if (!/^[0-9]{1,3}$/.test(mask)) return false
  }
  if (address.indexOf(":") !== -1) {
    if (mask !== null && parseInt(mask, 10) > 128) return false
    return /^[0-9A-Fa-f:.]+$/.test(address)
  }
  if (mask !== null && parseInt(mask, 10) > 32) return false
  var octets = address.split(".")
  if (octets.length !== 4) return false
  for (var i = 0; i < octets.length; i++) {
    if (!/^[0-9]{1,3}$/.test(octets[i])) return false
    if (parseInt(octets[i], 10) > 255) return false
  }
  return true
}

// ------------------------------------------------------------ the spec walker
//
// The one place a rule specification is checked, used by both the text the user
// types and the tokens reconstructed from /etc/ufw for a deletion.
//
// It does not filter a string: it walks the tokens, recognises each one, and
// returns a NEW array built from what it recognised. What reaches ufw is that
// array, never the caller's, so a token the walker does not understand cannot
// reach the command line by being passed through untouched. No shell is
// involved anywhere on the path either, the command is handed to the process
// as an argv array.
//
// options.allowUnlistedProfile accepts a profile-shaped token that is not in
// the live profile list. Deletions need it: a rule can outlive the
// /etc/ufw/applications.d file that named it, and refusing to delete it then
// would strand it in the panel. The name still has to match PROFILE_PATTERN.

function walkSpec(spec, appProfiles, options) {
  var tokens = spec || []
  var profiles = appProfiles || []
  var allowUnlisted = !!(options && options.allowUnlistedProfile)
  var n = tokens.length
  var i = 0
  var out = []

  function fail(message) { return { ok: false, tokens: null, error: message } }

  if (n === 0) return fail("Add a port, a range or an app profile")

  if (tokens[i] === "in" || tokens[i] === "out") out.push(tokens[i++])
  if (i >= n) return fail("Incomplete rule")

  if (tokens[i] === "proto" || tokens[i] === "from" || tokens[i] === "to") {
    var hasProtocol = false
    if (tokens[i] === "proto") {
      i++
      if (i >= n) return fail("proto needs tcp or udp")
      if (tokens[i] !== "tcp" && tokens[i] !== "udp") return fail("Protocol must be tcp or udp")
      out.push("proto", tokens[i++])
      hasProtocol = true
    }

    var endpoints = 0
    var keywords = ["from", "to"]
    for (var k = 0; k < keywords.length; k++) {
      if (i < n && tokens[i] === keywords[k]) {
        i++
        if (i >= n) return fail(keywords[k] + " needs an address")
        if (!isAddress(tokens[i])) return fail("Not an address: " + tokens[i])
        out.push(keywords[k], tokens[i++])
        if (i < n && tokens[i] === "port") {
          i++
          if (i >= n) return fail("port needs a value")
          if (!isPortSpec(tokens[i])) return fail("Not a port: " + tokens[i])
          if (tokens[i].indexOf(":") !== -1 && !hasProtocol) {
            return fail("A port range needs TCP or UDP")
          }
          out.push("port", tokens[i++])
        }
        endpoints = 1
      }
    }
    // "proto tcp" on its own names no endpoint. ufw rejects it too, but only
    // after the password has been typed; catching it here keeps the prompt for
    // rules that can actually be added.
    if (endpoints === 0) return fail("Add a from or to address")
  } else {
    // Simple form: a port, optionally with a protocol, or an application
    // profile. Profile names can contain spaces ("Web Server"), so the longest
    // run of tokens before an explicit `comment` is tried first and shortened
    // until one matches.
    var portMatch = String(tokens[i]).match(/^([0-9]+(?::[0-9]+)?)(?:\/(tcp|udp))?$/)
    if (portMatch) {
      if (!isPortSpec(portMatch[1])) return fail("Not a port: " + portMatch[1])
      if (portMatch[1].indexOf(":") !== -1 && !portMatch[2]) {
        return fail("A port range needs TCP or UDP")
      }
      out.push(tokens[i++])
    } else {
      var limit = n
      for (var c = i; c < n; c++) {
        if (tokens[c] === "comment") { limit = c; break }
      }
      var matched = -1
      for (var end = limit; end > i; end--) {
        var candidate = tokens.slice(i, end).join(" ")
        if (!PROFILE_PATTERN.test(candidate)) continue
        if (profiles.indexOf(candidate) !== -1 || (allowUnlisted && end === limit)) {
          matched = end
          out.push(candidate)
          break
        }
      }
      if (matched === -1) return fail("Not a port or a known app profile: " + tokens[i])
      i = matched
    }
  }

  if (i < n && tokens[i] === "comment") {
    i++
    var rest = tokens.slice(i).join(" ")
    if (rest === "") return fail("comment needs text")
    // ufw hex-encodes the comment into user.rules so it cannot break that
    // file's syntax, but it is also displayed back in the panel, where a
    // control character has no business being.
    if (!COMMENT_PATTERN.test(rest)) return fail("Comment has unsupported characters")
    out.push("comment", rest)
    i = n
  }

  if (i !== n) return fail("Unexpected: " + tokens.slice(i).join(" "))

  return { ok: true, tokens: out, error: "" }
}

// What the user types in the panel, as one line minus the leading `ufw`.
function parseRuleInput(text, appProfiles) {
  var trimmed = String(text || "").trim()
  if (trimmed === "") return { ok: false, action: "", tokens: null, error: "" }

  var tokens = trimmed.split(/\s+/)
  var action = tokens[0].toLowerCase()
  if (!isAction(action)) {
    return { ok: false, action: "", tokens: null, error: "Start with allow, deny, reject or limit" }
  }

  var walked = walkSpec(tokens.slice(1), appProfiles)
  if (!walked.ok) return { ok: false, action: "", tokens: null, error: walked.error }
  return { ok: true, action: action, tokens: walked.tokens, error: "" }
}

// ------------------------------------------------------------- the guided form
//
// Turns the panel's form state into the same shape everything else here speaks:
// an action plus a token array. The form cannot express a rule ufw would reject
// for shape reasons, and the few combinations it can express that ufw does not
// accept are caught here with a sentence rather than sent off to fail after the
// password has been typed.
//
// The result goes through walkSpec like everything else, so the form is not a
// second way into ufw's argv, it is another producer of tokens for the one
// checkpoint.

function buildRuleTokens(form, appProfiles) {
  function fail(message) { return { ok: false, action: "", tokens: null, error: message } }

  var f = form || {}
  var action = String(f.action || "allow")
  if (!isAction(action)) return fail("Pick an action")

  var direction = f.direction === "out" ? "out" : "in"
  var kind = f.kind === "range" || f.kind === "app" ? f.kind : "port"
  var proto = (f.proto === "tcp" || f.proto === "udp") ? f.proto : "any"
  var sourceCustom = f.sourceMode === "custom"
  var comment = String(f.comment || "").trim()

  var portText = ""
  if (kind === "port") {
    if (!isPort(String(f.port || ""))) return fail("Port must be between 1 and 65535")
    portText = String(f.port)
  } else if (kind === "range") {
    var lo = String(f.portFrom || "")
    var hi = String(f.portTo || "")
    if (!isPort(lo) || !isPort(hi)) return fail("Both ends of the range must be between 1 and 65535")
    if (parseInt(lo, 10) > parseInt(hi, 10)) return fail("The range starts after it ends")
    // ufw refuses a port range without a protocol: it cannot write one rule
    // covering both tcp and udp for a range.
    if (proto === "any") return fail("A port range needs TCP or UDP, not both")
    portText = lo + ":" + hi
  }

  var tokens = []

  if (kind === "app") {
    var app = String(f.app || "")
    if (app === "") return fail("Pick an application profile")
    // ufw has no syntax joining an application profile to a source address.
    if (sourceCustom) return fail("An app profile cannot be limited to one source")
    if (direction === "out") tokens.push("out")
    tokens.push(app)
  } else if (!sourceCustom) {
    if (direction === "out") tokens.push("out")
    tokens.push(proto === "any" ? portText : portText + "/" + proto)
  } else {
    var source = String(f.source || "").trim()
    if (source === "") return fail("Enter a source address, or set Source to Anywhere")
    if (!isAddress(source)) return fail("Not an address: " + source)
    tokens.push(direction)
    if (proto !== "any") tokens.push("proto", proto)
    tokens.push("from", source, "to", "any", "port", portText)
  }

  if (comment !== "") {
    if (!COMMENT_PATTERN.test(comment)) return fail("Comment has unsupported characters")
    tokens.push("comment", comment)
  }

  var safe = validateSpecTokens(tokens, appProfiles)
  if (!safe) return fail("That combination was rejected before it could run")

  return { ok: true, action: action, tokens: safe, error: "" }
}

function previewCommand(action, tokens) {
  if (!action || !tokens) return ""
  return "ufw " + action + " " + tokens.join(" ")
}

// The last checkpoint before a command is built. Everything privileged goes
// through here, including the tokens this file reconstructed itself, so no code
// path can reach ufw with something that was never walked.
function validateSpecTokens(tokens, appProfiles, options) {
  var walked = walkSpec(tokens, appProfiles, options)
  return walked.ok ? walked.tokens : null
}

if (typeof module !== "undefined") {
  module.exports = {
    isAnywhere: isAnywhere,
    hexDecode: hexDecode,
    parseUfwConf: parseUfwConf,
    parseDefaults: parseDefaults,
    policyLabel: policyLabel,
    parseRules: parseRules,
    parseTuple: parseTuple,
    actionLabel: actionLabel,
    toLabel: toLabel,
    fromLabel: fromLabel,
    ruleSpecTokens: ruleSpecTokens,
    readOnlyReason: readOnlyReason,
    buildRows: buildRows,
    familyLabel: familyLabel,
    isManagedComment: isManagedComment,
    ruleSummary: ruleSummary,
    parseAppProfiles: parseAppProfiles,
    isAction: isAction,
    isPortSpec: isPortSpec,
    isAddress: isAddress,
    walkSpec: walkSpec,
    parseRuleInput: parseRuleInput,
    validateSpecTokens: validateSpecTokens,
    buildRuleTokens: buildRuleTokens,
    previewCommand: previewCommand,
    combineActionErrors: combineActionErrors,
    generationFinished: generationFinished,
    generationSucceeded: generationSucceeded,
    evaluateReconciliation: evaluateReconciliation,
    MAX_RULES_PER_FAMILY: MAX_RULES_PER_FAMILY,
    MAX_RENDERED_ROWS: MAX_RENDERED_ROWS
  }
}
