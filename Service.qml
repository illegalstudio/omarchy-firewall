import QtQuick
import Quickshell.Io
import "Model.js" as Model

// State and actions for the firewall widget.
//
// Reading and writing are deliberately asymmetric:
//
//   Reading  is unprivileged. scripts/read-state.pl opens the world-readable
//            ufw files through no-follow file descriptors with strict byte,
//            file and profile-count limits. Its JSON output is capped before
//            it reaches this process, and the QML stream has a second cap.
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
  readonly property string stateReaderPath: {
    var value = String(Qt.resolvedUrl("scripts/read-state.pl"))
    return value.indexOf("file://") === 0
      ? decodeURIComponent(value.substring(7))
      : value
  }
  readonly property int stateOutputLimit: 6 * 1024 * 1024
  readonly property int diagnosticOutputLimit: 512

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
  property string readError: ""

  // Nothing to install: if ufw is here, changes can be made, and each one asks
  // for the password when it is made.
  readonly property bool canManage: installed

  // ---- action state
  property string actionStatus: ""
  property string lastError: ""
  property string _actionStdoutText: ""
  property string _actionStderrText: ""
  readonly property bool busy: actionProcess.running

  // The firewall is up only when the config says so AND the unit is running.
  // Collapsing the two into one boolean is how a machine ends up looking
  // protected while nothing is filtering, so they stay separate all the way to
  // the UI.
  readonly property bool active: configEnabled && serviceActive
  readonly property bool inconsistent: installed && loaded && (configEnabled !== serviceActive)

  readonly property string statusText: {
    if (!installed) return "ufw is not installed"
    if (readError !== "") return readError
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
  property string _stateOutput: ""
  property string _stateErrorOutput: ""
  property bool _stateOutputOverflow: false
  property bool _stateErrorOverflow: false

  function _rebuild() {
    var conf = Model.parseUfwConf(_confText)
    configEnabled = conf.enabled
    logLevel = conf.logLevel
    defaults = Model.parseDefaults(_defaultsText)
    rows = Model.buildRows(Model.parseRules(_rules4Text, 4), Model.parseRules(_rules6Text, 6))
    loaded = true
  }

  function refresh() {
    if (!stateProcess.running) stateProcess.running = true
    if (!unitProcess.running) unitProcess.running = true
  }

  function _appendStateOutput(data, errorStream) {
    var chunk = String(data || "")
    var current = errorStream ? _stateErrorOutput : _stateOutput
    var limit = errorStream ? diagnosticOutputLimit : stateOutputLimit
    var remaining = Math.max(0, limit - current.length)
    if (chunk.length > remaining) {
      if (errorStream) _stateErrorOverflow = true
      else _stateOutputOverflow = true
    }
    if (remaining > 0) {
      if (errorStream) _stateErrorOutput += chunk.substring(0, remaining)
      else _stateOutput += chunk.substring(0, remaining)
    }
  }

  function _stateReadFailed(message) {
    var text = String(message || "Could not read firewall state").replace(/\s+/g, " ").trim()
    readError = text.length > 160 ? text.substring(0, 157) + "..." : text
    loaded = false
    rows = []
    appProfiles = []
  }

  function _finishStateRead(exitCode) {
    if (_stateOutputOverflow || _stateErrorOverflow) {
      _stateReadFailed("Firewall state output exceeded its safety limit")
      return
    }
    if (exitCode !== 0) {
      _stateReadFailed(_stateErrorOutput || "The bounded firewall state reader failed")
      return
    }

    var payload
    try {
      payload = JSON.parse(_stateOutput)
    } catch (error) {
      _stateReadFailed("The bounded firewall state reader returned invalid data")
      return
    }
    if (!payload || payload.ok !== true) {
      _stateReadFailed(payload && payload.error
        ? payload.error
        : "The bounded firewall state reader rejected the current files")
      return
    }

    installed = payload.installed === true
    _confText = String(payload.conf || "")
    _defaultsText = String(payload.defaults || "")
    _rules4Text = String(payload.rules4 || "")
    _rules6Text = String(payload.rules6 || "")
    appProfiles = Array.isArray(payload.profiles) ? payload.profiles.slice(0, 256) : []
    readError = ""
    _rebuild()
  }

  function _appendActionOutput(data, errorStream) {
    var chunk = String(data || "")
    var current = errorStream ? _actionStderrText : _actionStdoutText
    var remaining = Math.max(0, diagnosticOutputLimit - current.length)
    if (remaining <= 0) return
    if (errorStream) _actionStderrText += chunk.substring(0, remaining)
    else _actionStdoutText += chunk.substring(0, remaining)
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
    _actionStdoutText = ""
    _actionStderrText = ""
    actionProcess.command = [pkexecPath, ufwPath].concat(args)
    actionProcess.running = true
    return true
  }

  function setEnabled(on) {
    // --force only here, and deliberately not on the rule commands.
    //
    // `ufw enable` asks "this may disrupt existing ssh connections, proceed?",
    // and there is no tty to answer it, so enable needs the flag. But ufw 0.36.2
    // mis-parses --force in front of a rule: frontend.parse_command() inserts
    // the implicit `rule` keyword by looking at argv[1] and only accounts for
    // --dry-run, so with --force there argv[1] is the flag, `rule` is never
    // inserted, and `allow` resolves to the `default` command family instead.
    // `ufw --force allow 8006/tcp` therefore fails without adding anything —
    // it authenticates, runs as root, and does nothing.
    //
    // The rule commands need no confirmation anyway: only `reset` and `enable`
    // prompt, and deletion prompts only for `delete NUM`, which this plugin
    // never uses.
    return _runUfw(on ? ["--force", "enable"] : ["disable"],
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

  // ---------------------------------------------------------------- processes

  Process {
    id: stateProcess
    running: true
    command: ["/usr/bin/perl", root.stateReaderPath]
    stdout: SplitParser {
      splitMarker: ""
      onRead: function(data) { root._appendStateOutput(data, false) }
    }
    stderr: SplitParser {
      splitMarker: ""
      onRead: function(data) { root._appendStateOutput(data, true) }
    }
    onStarted: {
      root._stateOutput = ""
      root._stateErrorOutput = ""
      root._stateOutputOverflow = false
      root._stateErrorOverflow = false
    }
    onExited: function(exitCode) { root._finishStateRead(exitCode) }
  }

  Process {
    id: unitProcess
    running: true
    command: ["/usr/bin/systemctl", "--quiet", "is-active", "ufw"]
    onExited: function(exitCode) { root.serviceActive = exitCode === 0 }
  }

  Process {
    id: actionProcess
    running: false
    command: []
    stdout: SplitParser {
      splitMarker: ""
      onRead: function(data) { root._appendActionOutput(data, false) }
    }
    stderr: SplitParser {
      splitMarker: ""
      onRead: function(data) { root._appendActionOutput(data, true) }
    }
    onExited: function(exitCode) {
      var ok = exitCode === 0
      if (ok) {
        root.lastError = ""
        root.actionStatus = ""
      } else {
        root.lastError = root._describeFailure(exitCode,
          root._actionStderrText, root._actionStdoutText)
        root.actionStatus = ""
      }
      // Re-read explicitly after every action so the panel does not wait for
      // the next bounded polling interval.
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
