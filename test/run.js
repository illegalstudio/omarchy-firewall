#!/usr/bin/env node
//
// Exercises Model.js against fixtures captured from a real Omarchy machine.
//
//   node test/run.js            run the assertions
//   node test/run.js --show     also print the parsed table, to eyeball it
//                               against `sudo ufw status numbered`
//
// Model.js is plain ES5 with no Qt imports precisely so this can run here,
// where the parsing can be checked without a shell and without root.

var fs = require("fs")
var path = require("path")
var Model = require(path.join(__dirname, "..", "Model.js"))

var FIXTURES = path.join(__dirname, "fixtures")
var failures = 0
var checks = 0

function read(name) {
  return fs.readFileSync(path.join(FIXTURES, name), "utf8")
}

function check(label, actual, expected) {
  checks++
  var a = JSON.stringify(actual)
  var b = JSON.stringify(expected)
  if (a !== b) {
    failures++
    console.log("FAIL  " + label + "\n        got      " + a + "\n        expected " + b)
  }
}

function checkTrue(label, value) {
  check(label, value === true, true)
}

// ------------------------------------------------------------------ ufw.conf

var conf = Model.parseUfwConf(read("ufw.conf"))
check("ufw.conf enabled", conf.enabled, true)
check("ufw.conf loglevel", conf.logLevel, "low")
check("ufw.conf missing file", Model.parseUfwConf("").enabled, false)
check("ufw.conf commented out", Model.parseUfwConf("#ENABLED=yes").enabled, false)

var defaults = Model.parseDefaults(read("default-ufw"))
check("default input policy", defaults.input, "drop")
check("default output policy", defaults.output, "accept")
check("default forward policy", defaults.forward, "drop")
check("ipv6 enabled", defaults.ipv6, true)
check("policy label drop", Model.policyLabel("drop"), "deny")
check("policy label accept", Model.policyLabel("accept"), "allow")

// --------------------------------------------------------------------- tuples

check("hex decode", Model.hexDecode("6f6d61726368792d73736864"), "omarchy-sshd")
check("hex decode rejects odd length", Model.hexDecode("abc"), "")
check("hex decode rejects non-hex", Model.hexDecode("zzzz"), "")

var simple = Model.parseTuple("### tuple ### allow udp 53317 0.0.0.0/0 any 0.0.0.0/0 in", 4)
check("simple action", simple.action, "allow")
check("simple protocol", simple.protocol, "udp")
check("simple dport", simple.dport, "53317")
check("simple direction", simple.direction, "in")
check("simple comment", simple.comment, "")

var commented = Model.parseTuple(
  "### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=6f6d61726368792d73736864", 4)
check("commented action", commented.action, "limit")
check("commented comment", commented.comment, "omarchy-sshd")

var logged = Model.parseTuple("### tuple ### allow_log tcp 443 0.0.0.0/0 any 0.0.0.0/0 in", 4)
check("log type split off the action", [logged.action, logged.logType], ["allow", "log"])

var route = Model.parseTuple("### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in", 4)
check("route rule flagged", route.forward, true)

var iface = Model.parseTuple("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_eth0", 4)
check("interface parsed", [iface.direction, iface.interfaceIn], ["in", "eth0"])

var app = Model.parseTuple(
  "### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 Web%20Server - in", 4)
check("dapp with escaped space", app.dapp, "Web Server")
check("sapp absent", app.sapp, "")

var legacy = Model.parseTuple("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0", 4)
check("legacy 6-field tuple defaults to in", legacy.direction, "in")

check("non-tuple line ignored", Model.parseTuple("-A ufw-user-input -j ACCEPT", 4), null)
check("short tuple ignored", Model.parseTuple("### tuple ### allow tcp", 4), null)

// --------------------------------------------------------------- rendering

check("anywhere port renders bare", Model.toLabel(simple), "53317/udp")
check("anywhere source", Model.fromLabel(simple), "Anywhere")
check("action label", Model.actionLabel(commented), "LIMIT IN")

var scoped = Model.parseTuple(
  "### tuple ### allow udp 53 172.17.0.1 any 172.16.0.0/12 in comment=616c6c6f772d646f636b65722d646e73", 4)
check("scoped destination", Model.toLabel(scoped), "172.17.0.1 53/udp")
check("scoped source", Model.fromLabel(scoped), "172.16.0.0/12")
check("scoped comment", scoped.comment, "allow-docker-dns")

// ------------------------------------------------------------- spec round-trip

check("simple spec", Model.ruleSpecTokens(simple), ["53317/udp"])
check("scoped spec", Model.ruleSpecTokens(scoped),
  ["in", "proto", "udp", "from", "172.16.0.0/12", "to", "172.17.0.1", "port", "53"])
check("app profile spec", Model.ruleSpecTokens(app), ["Web Server"])
check("route rule has no spec", Model.ruleSpecTokens(route), null)
check("interface rule has no spec", Model.ruleSpecTokens(iface), null)

var multiport = Model.parseTuple("### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in", 4)
check("multiport rule has no spec", Model.ruleSpecTokens(multiport), null)
checkTrue("multiport rule explains itself", Model.readOnlyReason(multiport.forward ? multiport : multiport).length > 0)

var outbound = Model.parseTuple("### tuple ### deny tcp 25 0.0.0.0/0 any 0.0.0.0/0 out", 4)
check("outbound spec keeps direction", Model.ruleSpecTokens(outbound), ["out", "25/tcp"])

// ------------------------------------------------------------------ row model

var rules4 = Model.parseRules(read("user.rules"), 4)
var rules6 = Model.parseRules(read("user6.rules"), 6)
var rows = Model.buildRows(rules4, rules6)

checkTrue("fixture has v4 rules", rules4.length > 0)
checkTrue("fixture has v6 rules", rules6.length > 0)
checkTrue("merging cuts the row count", rows.length < rules4.length + rules6.length)

var localsend = rows.filter(function (row) { return row.to === "53317/udp" })
check("LocalSend udp appears once", localsend.length, 1)
check("LocalSend covers both families", localsend[0].familyLabel, "IPv4 + IPv6")
check("LocalSend is deletable", localsend[0].deletable, true)

var sshd = rows.filter(function (row) { return row.comment === "omarchy-sshd" })
check("omarchy sshd rule found", sshd.length, 1)
check("omarchy sshd rule flagged as managed", sshd[0].managed, true)

var dockerDns = rows.filter(function (row) { return row.comment === "allow-docker-dns" })
checkTrue("docker dns rules are v4 only", dockerDns.every(function (row) {
  return row.familyLabel === "IPv4"
}))
checkTrue("docker dns rules stay distinct", dockerDns.length >= 2)

checkTrue("every row renders an action", rows.every(function (row) {
  return typeof row.actionLabel === "string" && row.actionLabel.length > 0
}))
checkTrue("no row is both deletable and unexplained", rows.every(function (row) {
  return row.deletable ? row.readOnlyReason === "" : row.readOnlyReason !== ""
}))

// --------------------------------------------------------------- app profiles

var profiles = Model.parseAppProfiles(read("applications.ini"))
checkTrue("app profiles parsed", profiles.length > 0)
checkTrue("app profiles include mosh", profiles.indexOf("mosh") !== -1)
check("app profiles are sorted", profiles.slice().sort(), profiles)

// -------------------------------------------------------------- input parsing

function accepts(input, expectedAction, expectedTokens) {
  var parsed = Model.parseRuleInput(input, profiles)
  check("accepts: " + input, [parsed.ok, parsed.action, parsed.tokens],
    [true, expectedAction, expectedTokens])
}

function rejects(input) {
  var parsed = Model.parseRuleInput(input, profiles)
  checks++
  if (parsed.ok) {
    failures++
    console.log("FAIL  rejects: " + input + "\n        was accepted as " + JSON.stringify(parsed.tokens))
  }
}

accepts("allow 22", "allow", ["22"])
accepts("allow 53317/udp", "allow", ["53317/udp"])
accepts("limit 22/tcp", "limit", ["22/tcp"])
accepts("allow 60000:61000/udp", "allow", ["60000:61000/udp"])
accepts("allow mosh", "allow", ["mosh"])
accepts("deny out 25/tcp", "deny", ["out", "25/tcp"])
accepts("allow 8080/tcp comment expo metro", "allow", ["8080/tcp", "comment", "expo metro"])
accepts("allow in proto tcp from 192.168.1.0/24 to any port 5432", "allow",
  ["in", "proto", "tcp", "from", "192.168.1.0/24", "to", "any", "port", "5432"])
accepts("reject to fe80::/10 port 5353", "reject",
  ["to", "fe80::/10", "port", "5353"])

rejects("")
rejects("22")                              // no action
rejects("open 22")                         // not a ufw action
rejects("allow")
rejects("allow 0")
rejects("allow 70000")
rejects("allow 61000:60000")               // reversed range
rejects("allow 22/sctp")
rejects("allow NotAProfile")
rejects("allow 22; rm -rf /")
rejects("allow $(id)")
rejects("allow `id`")
rejects("allow --force")
rejects("allow in proto tcp")              // no endpoint
rejects("allow in proto tcp from 999.1.1.1 to any port 22")
rejects("allow from 10.0.0.0/33")
rejects("allow 22 extra")
rejects("allow 22 comment")
rejects("allow 22 comment bad;id")

// ------------------------------------------------------------------- reporting

if (process.argv.indexOf("--show") !== -1) {
  console.log("")
  console.log(pad("To", 34) + pad("Action", 12) + pad("From", 24) + "Comment")
  console.log(new Array(96).join("-"))
  rows.forEach(function (row) {
    console.log(
      pad(row.to, 34) + pad(row.actionLabel, 12) + pad(row.from, 24) +
      (row.comment || "") + (row.deletable ? "" : "  [read-only]") +
      "   (" + row.familyLabel + ")")
  })
  console.log("")
}

function pad(text, width) {
  var value = String(text || "")
  while (value.length < width) value += " "
  return value
}

console.log((failures === 0 ? "PASS" : "FAIL") + "  " + (checks - failures) + "/" + checks + " checks")
process.exit(failures === 0 ? 0 : 1)
