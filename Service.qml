import QtQuick
import Quickshell.Io
import "Model.js" as Model

// State and actions for the firewall widget.
//
// Reading is unprivileged. scripts/read-state.pl opens the world-readable ufw
// files through no-follow descriptors and applies byte, line, record, file and
// profile-count limits before data reaches QML.
//
// Writing goes through _runUfw and the unprivileged run-action.pl supervisor.
// The supervisor validates a closed ufw grammar and executes a fixed argv:
// `pkexec --disable-internal-agent /usr/bin/timeout ... /usr/bin/ufw ...`.
// The root-owned timeout controls the privileged process group after approval;
// the unprivileged supervisor bounds output and the whole approval envelope.
//
// Arguments never reach a shell. Lifecycle commands are fixed literal arrays;
// every rule element is rebuilt by Model.walkSpec from recognised tokens.

Item {
  id: root

  readonly property string stateReaderPath: {
    var value = String(Qt.resolvedUrl("scripts/read-state.pl"))
    return value.indexOf("file://") === 0
      ? decodeURIComponent(value.substring(7))
      : value
  }
  readonly property string actionSupervisorPath: {
    var value = String(Qt.resolvedUrl("scripts/run-action.pl"))
    return value.indexOf("file://") === 0
      ? decodeURIComponent(value.substring(7))
      : value
  }
  readonly property string timeoutPath: "/usr/bin/timeout"
  readonly property int stateOutputLimit: 6 * 1024 * 1024
  readonly property int actionResultLimit: 20 * 1024
  readonly property int diagnosticOutputLimit: 512

  property var settings: ({})

  // ---- read state
  property bool installed: false           // ufw configuration present
  property bool actionToolsReady: false
  property string actionToolsError: ""
  property bool configEnabled: false       // ENABLED= in /etc/ufw/ufw.conf
  property bool serviceActive: false       // systemctl is-active ufw
  property bool serviceKnown: false
  property string unitReadError: ""
  property string rulesDigest: ""
  property string logLevel: ""
  property var defaults: ({ input: "", output: "", forward: "", ipv6: false })
  property var rows: []
  property var appProfiles: []
  property bool loaded: false
  property string readError: ""

  readonly property bool stateTrusted: loaded && readError === "" && serviceKnown
    && !stateProcess.running && !unitProcess.running
  readonly property bool canManage: installed && actionToolsReady && stateTrusted
    && !inconsistent
  readonly property string manageError: {
    if (!actionToolsReady) return actionToolsError !== "" ? actionToolsError
      : "Required firewall executables are not trusted"
    if (readError !== "") return "Firewall state is unavailable: " + readError
    if (!loaded) return "Firewall state has not been loaded"
    if (!installed) return "ufw is not installed"
    if (!serviceKnown) return unitReadError !== "" ? unitReadError
      : "The ufw service state is unknown"
    if (inconsistent) return "Firewall state is inconsistent; use emergency disable"
    if (stateProcess.running || unitProcess.running) return "Wait for the current state read"
    return "Firewall management is unavailable"
  }

  // ---- action state
  property string actionStatus: ""
  property string lastError: ""
  property bool enableRecoveryAvailable: false
  property bool preflighting: false
  property bool reconciling: false
  property string _actionOutput: ""
  property string _actionErrorOutput: ""
  property bool _actionOutputOverflow: false
  property bool _actionErrorOverflow: false
  property bool _actionGuardTriggered: false
  property string _actionKind: ""
  property var _reconcileOutcome: ({})
  property var _actionExpectation: ({})
  property var _pendingAction: ({})
  property int _stateRevision: 0
  property int _unitRevision: 0
  property int _stateSuccessRevision: 0
  property int _unitSuccessRevision: 0
  property int _targetStateRevision: 0
  property int _targetUnitRevision: 0
  property int _preflightStateRevision: 0
  property int _preflightUnitRevision: 0
  readonly property bool busy: preflighting || actionProcess.running || reconciling
  readonly property bool canEmergencyDisable: !busy
    && (enableRecoveryAvailable || inconsistent || readError !== ""
      || (installed && unitReadError !== ""))
  readonly property bool recoveryRecommended: enableRecoveryAvailable || inconsistent
    || readError !== "" || (installed && unitReadError !== "")

  // The firewall is up only when the config says so AND the unit is running.
  // Collapsing the two into one boolean is how a machine ends up looking
  // protected while nothing is filtering, so they stay separate all the way to
  // the UI.
  readonly property bool active: configEnabled && serviceActive
  readonly property bool inconsistent: installed && loaded && serviceKnown
    && (configEnabled !== serviceActive)

  readonly property string statusText: {
    if (readError !== "") return readError
    if (!loaded) return "Reading configuration"
    if (!installed) return "ufw is not installed"
    if (!serviceKnown) return "Could not read ufw service state"
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
    try {
      var conf = Model.parseUfwConf(_confText)
      var parsedRows = Model.buildRows(
        Model.parseRules(_rules4Text, 4),
        Model.parseRules(_rules6Text, 6))
      configEnabled = conf.enabled
      logLevel = conf.logLevel
      defaults = Model.parseDefaults(_defaultsText)
      rows = parsedRows
      loaded = true
      return true
    } catch (error) {
      _stateReadFailed(error && error.message
        ? error.message : "Firewall rules exceeded a safety limit")
      return false
    }
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
      return false
    }
    if (exitCode !== 0) {
      _stateReadFailed(_stateErrorOutput || "The bounded firewall state reader failed")
      return false
    }

    var payload
    try {
      payload = JSON.parse(_stateOutput)
    } catch (error) {
      _stateReadFailed("The bounded firewall state reader returned invalid data")
      return false
    }
    if (payload) {
      actionToolsReady = payload.actionToolsReady === true
      actionToolsError = String(payload.actionToolsError || "")
    }
    if (!payload || payload.ok !== true) {
      _stateReadFailed(payload && payload.error
        ? payload.error
        : "The bounded firewall state reader rejected the current files")
      return false
    }

    var digest = String(payload.rulesDigest || "")
    if (!/^[0-9a-f]{64}$/.test(digest)) {
      _stateReadFailed("The bounded firewall state reader returned no valid rule digest")
      return false
    }

    installed = payload.installed === true
    rulesDigest = digest
    _confText = String(payload.conf || "")
    _defaultsText = String(payload.defaults || "")
    _rules4Text = String(payload.rules4 || "")
    _rules6Text = String(payload.rules6 || "")
    appProfiles = Array.isArray(payload.profiles) ? payload.profiles.slice(0, 256) : []
    readError = ""
    return _rebuild()
  }

  function _appendActionOutput(data, errorStream) {
    var chunk = String(data || "")
    var current = errorStream ? _actionErrorOutput : _actionOutput
    var limit = errorStream ? diagnosticOutputLimit : actionResultLimit
    var remaining = Math.max(0, limit - current.length)
    if (chunk.length > remaining) {
      if (errorStream) _actionErrorOverflow = true
      else _actionOutputOverflow = true
    }
    if (remaining > 0) {
      if (errorStream) _actionErrorOutput += chunk.substring(0, remaining)
      else _actionOutput += chunk.substring(0, remaining)
    }
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

  function _parseActionResult(supervisorExitCode) {
    if (_actionGuardTriggered) {
      return { ok: false, error: "Firewall command exceeded its outer deadline" }
    }
    if (_actionOutputOverflow || _actionErrorOverflow) {
      return { ok: false, error: "Firewall action output exceeded its safety limit" }
    }
    if (supervisorExitCode !== 0) {
      return { ok: false, error: "The bounded firewall action supervisor failed" }
    }

    var payload
    try {
      payload = JSON.parse(_actionOutput)
    } catch (error) {
      return { ok: false, error: "The firewall action supervisor returned invalid data" }
    }
    if (!payload || payload.valid !== true) {
      return { ok: false, error: payload && payload.error
        ? String(payload.error) : "The firewall action supervisor rejected the command" }
    }
    if (payload.overflow === true) {
      return { ok: false, error: "Privileged command output exceeded its safety limit" }
    }
    if (payload.privilegedTimedOut === true) {
      return { ok: false, error: "The privileged firewall command exceeded its deadline" }
    }
    if (payload.timedOut === true) {
      return { ok: false, error: "Firewall approval or command exceeded its outer deadline" }
    }
    if (payload.interrupted === true) {
      return { ok: false, error: "Firewall command supervision was interrupted" }
    }
    if (Number(payload.signal || 0) !== 0) {
      return { ok: false, error: "Firewall command stopped on signal " + Number(payload.signal) }
    }

    if (payload.exitCode === null || payload.exitCode === undefined) {
      return { ok: false, error: "Firewall command returned no exit status" }
    }
    var childExitCode = Number(payload.exitCode)
    if (!isFinite(childExitCode) || childExitCode !== 0) {
      return { ok: false, error: _describeFailure(childExitCode,
        String(payload.stderr || ""), String(payload.stdout || "")) }
    }
    return { ok: true, error: "" }
  }

  function _beginReconciliation(outcome) {
    _reconcileOutcome = outcome || ({ ok: false, error: "Unknown firewall result" })
    reconciling = true
    actionStatus = "Checking the resulting firewall state"
    _targetStateRevision = 0
    _targetUnitRevision = 0
    reconcileDelay.restart()
    reconcileGuard.restart()
  }

  function _startReconciliationRead() {
    if (stateProcess.running || unitProcess.running) {
      reconcileDelay.restart()
      return
    }
    _targetStateRevision = _stateRevision + 1
    _targetUnitRevision = _unitRevision + 1
    refresh()
  }

  function _maybeFinishReconciliation() {
    if (!reconciling || !Model.generationFinished({
      state: _stateRevision,
      unit: _unitRevision,
      targetState: _targetStateRevision,
      targetUnit: _targetUnitRevision
    })) return
    _finishReconciliation(false)
  }

  function _startPreflightRead() {
    if (!preflighting) return
    if (stateProcess.running || unitProcess.running) {
      preflightDelay.restart()
      return
    }
    _preflightStateRevision = _stateRevision + 1
    _preflightUnitRevision = _unitRevision + 1
    refresh()
  }

  function _maybeFinishPreflight() {
    if (!preflighting || !Model.generationFinished({
      state: _stateRevision,
      unit: _unitRevision,
      targetState: _preflightStateRevision,
      targetUnit: _preflightUnitRevision
    })) return
    _finishPreflight(false)
  }

  function _finishPreflight(guardFailed) {
    if (!preflighting) return
    preflightDelay.stop()
    preflightGuard.stop()

    var pending = _pendingAction || ({})
    var fresh = !guardFailed && Model.generationSucceeded({
      state: _stateRevision,
      unit: _unitRevision,
      stateSuccess: _stateSuccessRevision,
      unitSuccess: _unitSuccessRevision,
      targetState: _preflightStateRevision,
      targetUnit: _preflightUnitRevision
    })
    var error = ""

    if (guardFailed) {
      error = "Could not verify firewall state immediately before the action"
    } else if (!fresh) {
      error = readError !== "" ? readError
        : (unitReadError !== "" ? unitReadError : "The preflight firewall read failed")
    } else if (!actionToolsReady || !installed || !loaded || !serviceKnown || inconsistent) {
      error = manageError
    } else if (pending.kind === "enable" && (configEnabled || serviceActive)) {
      error = "Enable requires a freshly verified fully inactive starting state"
    } else if (pending.kind === "disable" && (!configEnabled || !serviceActive)) {
      error = "Use emergency disable when firewall state is inconsistent"
    }

    preflighting = false
    _preflightStateRevision = 0
    _preflightUnitRevision = 0
    _pendingAction = ({})

    if (error !== "") {
      actionStatus = ""
      lastError = error
      actionFinished(false)
      return
    }

    _startActionProcess(pending.args, pending.pendingText, pending.kind)
  }

  function _finishReconciliation(guardFailed) {
    if (!reconciling) return
    reconcileDelay.stop()
    reconcileGuard.stop()

    var fresh = !guardFailed && Model.generationSucceeded({
      state: _stateRevision,
      unit: _unitRevision,
      stateSuccess: _stateSuccessRevision,
      unitSuccess: _unitSuccessRevision,
      targetState: _targetStateRevision,
      targetUnit: _targetUnitRevision
    })
    var verificationError = ""
    if (guardFailed) {
      verificationError = "Could not reconcile firewall state before the safety deadline"
    } else if (_stateSuccessRevision < _targetStateRevision) {
      verificationError = readError !== "" ? readError : "The firewall file snapshot failed"
    } else if (_unitSuccessRevision < _targetUnitRevision) {
      verificationError = unitReadError !== "" ? unitReadError : "The ufw service read failed"
    }

    var evaluation = Model.evaluateReconciliation(
      _actionKind,
      _reconcileOutcome,
      {
        fresh: fresh,
        error: verificationError,
        active: active,
        configEnabled: configEnabled,
        serviceActive: serviceActive,
        rulesDigest: rulesDigest
      },
      _actionExpectation)

    if (_actionKind === "enable") {
      enableRecoveryAvailable = evaluation.recovery === true
    }
    if (evaluation.clearRecovery === true) enableRecoveryAvailable = false

    lastError = evaluation.ok ? "" : evaluation.error
    actionStatus = ""
    reconciling = false
    _targetStateRevision = 0
    _targetUnitRevision = 0
    _actionKind = ""
    _actionExpectation = ({})
    actionFinished(evaluation.ok)
  }

  // The single door to root. Every privileged action in this plugin is one call
  // to this function, and the polkit dialog stands in front of every one of
  // them. `args` is an argv array; no shell ever sees it.
  function _startActionProcess(args, pendingText, kind) {
    lastError = ""
    actionStatus = pendingText
    _actionOutput = ""
    _actionErrorOutput = ""
    _actionOutputOverflow = false
    _actionErrorOverflow = false
    _actionGuardTriggered = false
    _actionKind = String(kind || "change")
    _actionExpectation = {
      beforeRulesDigest: rulesDigest,
      beforeConfigEnabled: configEnabled,
      beforeServiceActive: serviceActive
    }
    actionProcess.command = ["/usr/bin/perl", actionSupervisorPath].concat(args)
    actionProcess.running = true
    return true
  }

  function _runUfw(args, pendingText, kind, options) {
    if (busy) return false
    var recovery = options && options.allowUntrusted === true
    if (recovery) {
      if (!canEmergencyDisable) {
        lastError = "Emergency disable is not available"
        return false
      }
      return _startActionProcess(args, pendingText, kind)
    }
    if (!canManage) {
      lastError = manageError
      return false
    }

    lastError = ""
    actionStatus = "Verifying current firewall state"
    _pendingAction = {
      args: args.slice(0),
      pendingText: String(pendingText || "Changing the firewall"),
      kind: String(kind || "change")
    }
    _preflightStateRevision = 0
    _preflightUnitRevision = 0
    preflighting = true
    preflightDelay.restart()
    preflightGuard.restart()
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
    // `ufw --force allow 8006/tcp` therefore fails without adding anything,
    // it authenticates, runs as root, and does nothing.
    //
    // The rule commands need no confirmation anyway: only `reset` and `enable`
    // prompt, and deletion prompts only for `delete NUM`, which this plugin
    // never uses.
    if (on && (configEnabled || serviceActive)) {
      lastError = "Enable requires a verified fully inactive starting state"
      return false
    }
    if (!on && (!configEnabled || !serviceActive)) {
      lastError = "Use emergency disable when firewall state is inconsistent"
      return false
    }
    return _runUfw(on ? ["--force", "enable"] : ["disable"],
      on ? "Enabling the firewall" : "Disabling the firewall",
      on ? "enable" : "disable")
  }

  function toggleEnabled() {
    return setEnabled(!configEnabled)
  }

  function reloadFirewall() {
    return _runUfw(["reload"], "Reloading the firewall", "reload")
  }

  function emergencyDisable() {
    return _runUfw(["disable"], "Emergency disabling the firewall", "recovery",
      { allowUntrusted: true })
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
    return _runUfw([String(action)].concat(safe), "Adding the rule", "add")
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
    return _runUfw(["delete", String(row.action)].concat(safe), "Deleting the rule", "delete")
  }

  // ---------------------------------------------------------------- processes

  Process {
    id: stateProcess
    running: true
    command: [root.timeoutPath, "--signal=TERM", "--kill-after=1s", "5s",
      "/usr/bin/perl", root.stateReaderPath]
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
    onExited: function(exitCode) {
      root._stateRevision++
      if (root._finishStateRead(exitCode)) {
        root._stateSuccessRevision = root._stateRevision
      }
      root._maybeFinishPreflight()
      root._maybeFinishReconciliation()
    }
  }

  Process {
    id: unitProcess
    running: true
    command: [root.timeoutPath, "--signal=TERM", "--kill-after=1s", "3s",
      "/usr/bin/systemctl", "--quiet", "is-active", "ufw"]
    onStarted: {
      root.serviceKnown = false
      root.unitReadError = ""
    }
    onExited: function(exitCode) {
      root.serviceKnown = exitCode === 0 || exitCode === 3
      root.serviceActive = exitCode === 0
      root.unitReadError = root.serviceKnown
        ? "" : (exitCode === 124 || exitCode === 137
          ? "The ufw service read exceeded its deadline"
          : "Could not read the ufw service state")
      root._unitRevision++
      if (root.serviceKnown) root._unitSuccessRevision = root._unitRevision
      root._maybeFinishPreflight()
      root._maybeFinishReconciliation()
    }
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
    onStarted: actionDeadline.restart()
    onExited: function(exitCode) {
      actionDeadline.stop()
      actionKillTimer.stop()
      root._beginReconciliation(root._parseActionResult(exitCode))
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

  Timer {
    id: preflightDelay
    interval: 100
    repeat: false
    onTriggered: root._startPreflightRead()
  }

  Timer {
    id: preflightGuard
    interval: 20000
    repeat: false
    onTriggered: root._finishPreflight(true)
  }

  Timer {
    id: reconcileDelay
    interval: 900
    repeat: false
    onTriggered: root._startReconciliationRead()
  }

  Timer {
    id: reconcileGuard
    interval: 20000
    repeat: false
    onTriggered: root._finishReconciliation(true)
  }

  Timer {
    id: actionDeadline
    interval: 150000
    repeat: false
    onTriggered: {
      root._actionGuardTriggered = true
      actionProcess.signal(15)
      actionKillTimer.restart()
    }
  }

  Timer {
    id: actionKillTimer
    interval: 5000
    repeat: false
    onTriggered: if (actionProcess.running) actionProcess.signal(9)
  }

  Component.onDestruction: {
    if (stateProcess.running) stateProcess.signal(15)
    if (unitProcess.running) unitProcess.signal(15)
    if (actionProcess.running) actionProcess.signal(15)
  }
}
