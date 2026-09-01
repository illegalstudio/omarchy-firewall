import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import "Model.js" as Model

// State and actions for the firewall widget.
//
// Reading and writing are deliberately asymmetric:
//
//   Reading  is unprivileged. /etc/ufw/ufw.conf, /etc/default/ufw and
//            /etc/ufw/user{,6}.rules are all world-readable, and they are what
//            `ufw status` itself renders. Watching them means the panel is
//            correct within a moment of any change, including one made from a
//            terminal, and never asks for anything.
//
//   Writing  goes through exactly one function, _runUfw, which runs
//            `pkexec /usr/bin/ufw ...`. pkexec hands authentication to polkit,
//            polkit to the agent running inside omarchy-shell (omarchy.polkit),
//            so the password dialog is Omarchy's own. The action pkexec falls
//            under, org.freedesktop.policykit.exec, is auth_admin rather than
//            auth_admin_keep, so nothing is cached: enabling, disabling, adding
//            a rule and deleting one each raise the dialog on their own.
//
// The program that runs as root is /usr/bin/ufw itself — root-owned, shipped by
// the distribution, nothing to install. An earlier draft put a helper script in
// this plugin directory and ran that under pkexec; that would have meant
// anything able to write the user's home getting root the next time a firewall
// change was authorised, which is the same shape as the NOPASSWD grants
// Omarchy's migration 1788025225 exists to delete. ufw's own binary has no such
// problem, and needs no setup step.
//
// Arguments never reach a shell: Process takes an argv array, and every element
// of it is rebuilt by Model.walkSpec from tokens it recognised, rather than
// being passed through from the caller.

Item {
  id: root

  readonly property string pkexecPath: "/usr/bin/pkexec"
  readonly property string ufwPath: "/usr/bin/ufw"

  property var settings: ({})

  // ---- read state
  property bool installed: true            // ufw present on the machine
  property bool configEnabled: false       // ENABLED= in /etc/ufw/ufw.conf
  property bool serviceActive: false       // systemctl is-active ufw
  property string logLevel: ""
  property var defaults: ({ input: "", output: "", forward: "", ipv6: false })
  property var rows: []
  property var appProfiles: []
  property bool loaded: false

  // Nothing to install: if ufw is here, changes can be made, and each one asks
  // for the password when it is made.
  readonly property bool canManage: installed

  // ---- action state
  property string actionStatus: ""
  property string lastError: ""
  readonly property bool busy: actionProcess.running

  // The firewall is up only when the config says so AND the unit is running.
  // Collapsing the two into one boolean is how a machine ends up looking
  // protected while nothing is filtering, so they stay separate all the way to
  // the UI.
  readonly property bool active: configEnabled && serviceActive
  readonly property bool inconsistent: installed && loaded && (configEnabled !== serviceActive)

  readonly property string statusText: {
    if (!installed) return "ufw is not installed"
    if (!loaded) return "Reading configuration"
    if (configEnabled && serviceActive) return "Active"
    if (!configEnabled && !serviceActive) return "Inactive"
    if (configEnabled && !serviceActive) return "Enabled in config, unit not running"
    return "Disabled in config, unit still running"
  }

  readonly property int refreshIntervalSec: {
    var value = parseInt(String(settings && settings.refreshIntervalSec !== undefined
      && settings.refreshIntervalSec !== null ? settings.refreshIntervalSec : 30), 10)
    if (!isFinite(value)) value = 30
    return Math.max(5, Math.min(3600, value))
  }

  signal actionFinished(bool ok)

  // ------------------------------------------------------------------ reading

  property string _confText: ""
  property string _defaultsText: ""
  property string _rules4Text: ""
  property string _rules6Text: ""

  function _rebuild() {
    var conf = Model.parseUfwConf(_confText)
    configEnabled = conf.enabled
    logLevel = conf.logLevel
    defaults = Model.parseDefaults(_defaultsText)
    rows = Model.buildRows(Model.parseRules(_rules4Text, 4), Model.parseRules(_rules6Text, 6))
    loaded = true
  }

  function refresh() {
    confFile.reload()
    defaultsFile.reload()
    rules4File.reload()
    rules6File.reload()
    if (!unitProcess.running) unitProcess.running = true
    if (!profilesProcess.running) profilesProcess.running = true
  }

  // ------------------------------------------------------------------ writing

  function _describeFailure(exitCode, stderrText, stdoutText) {
    // pkexec's own exit codes, which are not ufw's: 126 covers both "the dialog
    // was dismissed" and "authentication failed", 127 means it could not start
    // the program at all.
    if (exitCode === 126) return "Cancelled at the password prompt"
    if (exitCode === 127) return "Could not start ufw"
    var text = String(stderrText || stdoutText || "").replace(/\s+/g, " ").trim()
    if (text === "") return "The firewall command failed"
    return text.length > 160 ? text.substring(0, 157) + "..." : text
  }

  // The single door to root. Every privileged action in this plugin is one call
  // to this function, and the polkit dialog stands in front of every one of
  // them. `args` is an argv array; no shell ever sees it.
  function _runUfw(args, pendingText) {
    if (!installed) {
      lastError = "ufw is not installed."
      return false
    }
    if (actionProcess.running) return false

    lastError = ""
    actionStatus = pendingText
    // --force is a global flag ufw strips ahead of the command (parser.py). It
    // answers the interactive confirmations — "this may disrupt existing ssh
    // connections" on enable, and the delete confirmation — which have no tty
    // to answer them here.
    actionProcess.command = [pkexecPath, ufwPath, "--force"].concat(args)
    actionProcess.running = true
    return true
  }

  function setEnabled(on) {
    return _runUfw([on ? "enable" : "disable"],
      on ? "Enabling the firewall" : "Disabling the firewall")
  }

  function toggleEnabled() {
    return setEnabled(!configEnabled)
  }

  function reloadFirewall() {
    return _runUfw(["reload"], "Reloading the firewall")
  }

  // Both of the rule paths re-walk their tokens here, immediately before the
  // command is built, even though the panel already validated what was typed
  // and the delete tokens were reconstructed by this plugin's own parser. It is
  // the same check twice on purpose: it means no code path anywhere can put a
  // token into ufw's argv that Model.walkSpec did not recognise.
  function addRule(action, tokens) {
    if (!Model.isAction(action)) {
      lastError = "Unknown action: " + action
      return false
    }
    var safe = Model.validateSpecTokens(tokens, appProfiles)
    if (!safe) {
      lastError = "That rule was rejected before it could run."
      return false
    }
    return _runUfw([String(action)].concat(safe), "Adding the rule")
  }

  function deleteRow(row) {
    if (!row || !row.deletable || !row.specTokens) return false
    if (!Model.isAction(row.action)) return false
    // allowUnlistedProfile: a rule can outlive the /etc/ufw/applications.d file
    // that named its profile, and refusing to delete it then would strand it in
    // the panel with no way out. The name still has to look like a profile name.
    var safe = Model.validateSpecTokens(row.specTokens, appProfiles,
      { allowUnlistedProfile: true })
    if (!safe) {
      lastError = "This rule cannot be expressed as a single ufw command."
      return false
    }
    // Deleted by specification, never by the numbers `ufw status numbered`
    // prints: those interleave the v4 and v6 rules and renumber on every
    // change, so an index worked out from the config files can point at a
    // different rule by the time it is used. ufw does the matching, and its own
    // matcher tolerates a differing comment, so the comment is not sent.
    return _runUfw(["delete", String(row.action)].concat(safe), "Deleting the rule")
  }

  // ---------------------------------------------------------------- watchers

  FileView {
    id: confFile
    path: "/etc/ufw/ufw.conf"
    watchChanges: true
    printErrors: false
    onLoaded: { root.installed = true; root._confText = text(); root._rebuild() }
    onLoadFailed: { root.installed = false; root._confText = ""; root._rebuild() }
    onFileChanged: reload()
  }

  FileView {
    id: defaultsFile
    path: "/etc/default/ufw"
    watchChanges: true
    printErrors: false
    onLoaded: { root._defaultsText = text(); root._rebuild() }
    onLoadFailed: { root._defaultsText = ""; root._rebuild() }
    onFileChanged: reload()
  }

  FileView {
    id: rules4File
    path: "/etc/ufw/user.rules"
    watchChanges: true
    printErrors: false
    onLoaded: { root._rules4Text = text(); root._rebuild() }
    onLoadFailed: { root._rules4Text = ""; root._rebuild() }
    onFileChanged: reload()
  }

  FileView {
    id: rules6File
    path: "/etc/ufw/user6.rules"
    watchChanges: true
    printErrors: false
    onLoaded: { root._rules6Text = text(); root._rebuild() }
    onLoadFailed: { root._rules6Text = ""; root._rebuild() }
    onFileChanged: reload()
  }

  // ---------------------------------------------------------------- processes

  Process {
    id: unitProcess
    running: true
    command: ["systemctl", "is-active", "ufw"]
    stdout: StdioCollector {
      id: unitStdout
      waitForEnd: true
      onStreamFinished: root.serviceActive = String(text || "").trim() === "active"
    }
  }

  Process {
    id: profilesProcess
    running: true
    // Reads the [Section] headers out of /etc/ufw/applications.d, which is
    // world-readable. A profile name is free text, so it is matched against
    // this list rather than a pattern before it can become part of a command.
    command: ["grep", "-rho", "^\\[[^]]*\\]", "/etc/ufw/applications.d"]
    stdout: StdioCollector {
      id: profilesStdout
      waitForEnd: true
      onStreamFinished: root.appProfiles = Model.parseAppProfiles(String(text || ""))
    }
  }

  Process {
    id: actionProcess
    running: false
    command: []
    stdout: StdioCollector { id: actionStdout; waitForEnd: true }
    stderr: StdioCollector { id: actionStderr; waitForEnd: true }
    onExited: function(exitCode) {
      var ok = exitCode === 0
      if (ok) {
        root.lastError = ""
        root.actionStatus = ""
      } else {
        root.lastError = root._describeFailure(exitCode,
          String(actionStderr.text || ""), String(actionStdout.text || ""))
        root.actionStatus = ""
      }
      // ufw rewrites user.rules through a temp file and a rename, which some
      // inotify watches do not survive; re-read explicitly rather than trusting
      // the watch to have followed it.
      root.refresh()
      settleTimer.restart()
      root.actionFinished(ok)
    }
  }

  // ------------------------------------------------------------------- timers

  Timer {
    id: refreshTimer
    interval: root.refreshIntervalSec * 1000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  // `ufw enable` returns before systemd finishes bringing the unit up, so one
  // read straight after the command still sees the old unit state.
  Timer {
    id: settleTimer
    interval: 900
    repeat: false
    onTriggered: root.refresh()
  }

  Timer {
    id: statusClear
    interval: 6000
    repeat: false
    running: root.actionStatus !== ""
    onTriggered: root.actionStatus = ""
  }
}
