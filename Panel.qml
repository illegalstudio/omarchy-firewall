import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

// Bar button plus popup panel.
//
// The panel has two modes. "list" shows the state and the rules; "add" replaces
// the list with a guided form. They are modes rather than an expanding section
// because the form is seven rows tall and reading the rules while filling it in
// is not something anyone needs to do.
//
// The form is built from pickers, not from a text box. Every field that has a
// fixed set of answers is a set of chips, and the only things typed are a port
// number, an optional source address and an optional comment. The exact ufw
// command is previewed under the form, so what is about to run is never a
// guess.
Panel {
  id: root
  moduleName: "illegalstudio.omarchy-firewall"
  ipcTarget: "illegalstudio.omarchy-firewall"
  manageIpc: false

  // list | add
  property string mode: "list"

  // list-mode cursor: header | rules | add
  property string focusSection: "header"
  property int ruleIndex: 0
  property bool cursorActive: false

  // add-mode cursor, an index into formRows
  property int formIndex: 0

  property var pendingDelete: null
  property bool confirmDisableOpen: false
  readonly property bool confirmOpen: pendingDelete !== null || confirmDisableOpen

  // ---- form state
  property string fmAction: "allow"
  property string fmDirection: "in"
  property string fmKind: "port"
  property string fmPort: "8080"
  property string fmPortFrom: "60000"
  property string fmPortTo: "61000"
  property string fmApp: ""
  property string fmProto: "tcp"
  property string fmSourceMode: "any"
  property string fmSource: ""
  property string fmComment: ""

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property var rows: firewall.rows

  readonly property var formResult: Model.buildRuleTokens({
    action: root.fmAction,
    direction: root.fmDirection,
    kind: root.fmKind,
    port: root.fmPort,
    portFrom: root.fmPortFrom,
    portTo: root.fmPortTo,
    app: root.fmApp,
    proto: root.fmProto,
    sourceMode: root.fmSourceMode,
    source: root.fmSource,
    comment: root.fmComment
  }, firewall.appProfiles)

  // Which rows the form currently has. Protocol and source disappear for an
  // application profile, because ufw has no syntax that combines them with one.
  readonly property var formRows: {
    var list = ["action", "direction", "kind", "value"]
    if (fmKind !== "app") {
      list.push("proto")
      list.push("source")
      if (fmSourceMode === "custom") list.push("sourceAddr")
    }
    list.push("comment")
    list.push("submit")
    return list
  }

  readonly property string currentFormRow: {
    if (mode !== "add") return ""
    var index = Math.max(0, Math.min(formIndex, formRows.length - 1))
    return formRows[index]
  }

  // True while a text box has the keyboard, which is when PanelKeyCatcher has
  // to stand down or every letter typed would be read as a shortcut.
  readonly property bool editing: portField.activeFocus || portFromField.activeFocus
    || portToField.activeFocus || sourceField.activeFocus || commentField.activeFocus

  readonly property color barIconColor: {
    if (!firewall.installed) return Qt.darker(barForeground, 1.9)
    if (firewall.inconsistent) return bar ? bar.urgent : Color.urgent
    return firewall.active ? barForeground : Qt.darker(barForeground, 1.55)
  }

  readonly property string tooltipText: {
    if (!firewall.installed) return "ufw is not installed"
    if (firewall.inconsistent) return "Firewall: " + firewall.statusText
    return firewall.active ? "Firewall active" : "Firewall inactive"
  }

  readonly property var actionOptions: ["allow", "deny", "reject", "limit"]
  readonly property var directionOptions: [
    { value: "in", label: "incoming" },
    { value: "out", label: "outgoing" }
  ]
  readonly property var kindOptions: [
    { value: "port", label: "port" },
    { value: "range", label: "range" },
    { value: "app", label: "app profile" }
  ]
  readonly property var protoOptions: [
    { value: "tcp", label: "TCP" },
    { value: "udp", label: "UDP" },
    { value: "any", label: "both" }
  ]
  readonly property var sourceOptions: [
    { value: "any", label: "anywhere" },
    { value: "custom", label: "from…" }
  ]

  // -------------------------------------------------------------- list cursor

  function ensureCursor() {
    if (focusSection === "rules") {
      if (rows.length === 0) { focusSection = "header"; ruleIndex = 0; return }
      if (ruleIndex >= rows.length) ruleIndex = rows.length - 1
      if (ruleIndex < 0) ruleIndex = 0
    }
  }

  function moveListCursor(dy) {
    if (dy === 0) return

    if (focusSection === "header") {
      if (dy > 0) {
        if (rows.length > 0) { focusSection = "rules"; ruleIndex = 0 }
        else focusSection = "add"
        scrollCursorIntoView()
      }
      return
    }

    if (focusSection === "rules") {
      var next = ruleIndex + dy
      if (next < 0) { focusSection = "header"; if (panelFlick) panelFlick.contentY = 0; return }
      if (next >= rows.length) { focusSection = "add"; scrollCursorIntoView(); return }
      ruleIndex = next
      scrollCursorIntoView()
      return
    }

    if (focusSection === "add" && dy < 0) {
      if (rows.length > 0) { focusSection = "rules"; ruleIndex = rows.length - 1 }
      else focusSection = "header"
      scrollCursorIntoView()
    }
  }

  function selectedRow() {
    if (mode !== "list" || focusSection !== "rules" || rows.length === 0) return null
    return rows[Math.max(0, Math.min(ruleIndex, rows.length - 1))]
  }

  function setRuleCursor(index) {
    cursorActive = true
    focusSection = "rules"
    ruleIndex = index
  }

  // -------------------------------------------------------------- form cursor

  function setFormCursor(rowId) {
    var index = formRows.indexOf(rowId)
    if (index === -1) return
    cursorActive = true
    formIndex = index
  }

  function formRowHasCursor(rowId) {
    return mode === "add" && cursorActive && currentFormRow === rowId
  }

  // ButtonGroup.selectedOptionIndex() is a function, so a binding calling it
  // would not re-evaluate when the value changes. Compute the index from the
  // properties instead, so the cursor highlight follows the selection.
  function optionIndex(options, value) {
    for (var i = 0; i < options.length; i++) {
      var v = (options[i] && typeof options[i] === "object")
        ? String(options[i].value) : String(options[i])
      if (v === String(value)) return i
    }
    return -1
  }

  // The FormRow item carrying a given row id, so scrolling and measuring do not
  // depend on the child order of a column that also holds separators and hints.
  function formRowItem(rowId) {
    if (!formColumn) return null
    for (var i = 0; i < formColumn.children.length; i++) {
      var child = formColumn.children[i]
      if (child && child.rowId === rowId) return child
    }
    return null
  }

  function cycleValue(options, current, step) {
    var values = []
    for (var i = 0; i < options.length; i++) {
      values.push(options[i] && typeof options[i] === "object"
        ? String(options[i].value) : String(options[i]))
    }
    var at = values.indexOf(String(current))
    if (at === -1) at = 0
    var next = (at + step) % values.length
    if (next < 0) next += values.length
    return values[next]
  }

  function cycleCurrentRow(step) {
    switch (currentFormRow) {
    case "action": fmAction = cycleValue(actionOptions, fmAction, step); return true
    case "direction": fmDirection = cycleValue(directionOptions, fmDirection, step); return true
    case "kind": setKind(cycleValue(kindOptions, fmKind, step)); return true
    case "proto": fmProto = cycleValue(protoOptions, fmProto, step); return true
    case "source": fmSourceMode = cycleValue(sourceOptions, fmSourceMode, step); return true
    case "value":
      if (fmKind === "app" && firewall.appProfiles.length > 0) {
        fmApp = cycleValue(firewall.appProfiles, fmApp, step)
        return true
      }
      return false
    }
    return false
  }

  function setKind(kind) {
    if (fmKind === kind) return
    // A field that keeps focus while being hidden would keep swallowing keys.
    keyCatcher.forceActiveFocus()
    fmKind = kind
    if (kind === "app" && fmApp === "" && firewall.appProfiles.length > 0) {
      fmApp = String(firewall.appProfiles[0])
    }
    // The row list just changed shape underneath the cursor.
    setFormCursor("kind")
  }

  function activateFormRow() {
    switch (currentFormRow) {
    case "action":
    case "direction":
    case "kind":
    case "proto":
    case "source":
      cycleCurrentRow(1)
      return
    case "value":
      if (fmKind === "app") cycleCurrentRow(1)
      else if (fmKind === "range") portFromField.forceActiveFocus()
      else portField.forceActiveFocus()
      return
    case "sourceAddr": sourceField.forceActiveFocus(); return
    case "comment": commentField.forceActiveFocus(); return
    case "submit": submitForm(); return
    }
  }

  // ----------------------------------------------------------------- actions

  function requireManage() {
    if (firewall.canManage) return true
    firewall.lastError = "ufw is not installed."
    return false
  }

  // Disabling asks twice on purpose. The polkit dialog that follows says only
  // that a program is being run as root — it cannot say which one or why — so
  // the question of whether to take the firewall down is put here, where it can
  // name what it means.
  function requestToggle() {
    if (!firewall.installed || firewall.busy) return
    if (!requireManage()) return
    if (firewall.configEnabled) confirmDisableOpen = true
    else firewall.setEnabled(true)
  }

  function confirmDisable() {
    confirmDisableOpen = false
    firewall.setEnabled(false)
  }

  function requestDelete(row) {
    if (!row || firewall.busy) return
    if (!row.deletable) {
      firewall.lastError = row.readOnlyReason
      return
    }
    if (!requireManage()) return
    pendingDelete = row
  }

  function confirmDelete() {
    var row = pendingDelete
    pendingDelete = null
    if (row) firewall.deleteRow(row)
  }

  function openAdd() {
    if (!requireManage()) return
    firewall.lastError = ""
    if (fmKind === "app" && fmApp === "" && firewall.appProfiles.length > 0) {
      fmApp = String(firewall.appProfiles[0])
    }
    mode = "add"
    formIndex = 0
    cursorActive = true
    if (panelFlick) panelFlick.contentY = 0
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function closeAdd() {
    mode = "list"
    focusSection = "add"
    cursorActive = true
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function submitForm() {
    var result = root.formResult
    if (!result.ok) {
      firewall.lastError = result.error
      return
    }
    if (firewall.addRule(result.action, result.tokens)) closeAdd()
  }

  function scrollItemIntoView(item) {
    if (!panelFlick || !item) return
    Qt.callLater(function() {
      if (!item) return
      var margin = Style.space(6)
      var point = item.mapToItem(panelFlick.contentItem, 0, 0)
      var top = point.y
      var bottom = top + item.height
      var viewTop = panelFlick.contentY
      var viewBottom = viewTop + panelFlick.height
      var maxY = Math.max(0, panelFlick.contentHeight - panelFlick.height)
      if (top < viewTop + margin) panelFlick.contentY = Math.max(0, top - margin)
      else if (bottom > viewBottom - margin) panelFlick.contentY = Math.min(maxY, bottom + margin - panelFlick.height)
    })
  }

  function scrollCursorIntoView() {
    if (mode === "list" && focusSection === "rules" && ruleColumn
        && ruleIndex >= 0 && ruleIndex < ruleColumn.children.length) {
      scrollItemIntoView(ruleColumn.children[ruleIndex])
    } else if (mode === "list" && focusSection === "add") {
      scrollItemIntoView(addButton)
    }
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    mode = "list"
    cursorActive = false
    focusSection = "header"
    ruleIndex = 0
    formIndex = 0
    pendingDelete = null
    confirmDisableOpen = false
    firewall.lastError = ""
    if (panelFlick) panelFlick.contentY = 0
    firewall.refresh()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  } else {
    pendingDelete = null
    confirmDisableOpen = false
    mode = "list"
  }

  onRuleIndexChanged: scrollCursorIntoView()

  Service {
    id: firewall
    settings: root.settings
  }

  Connections {
    target: firewall
    function onRowsChanged() { root.ensureCursor() }
    function onAppProfilesChanged() {
      if (root.fmApp === "" && firewall.appProfiles.length > 0) {
        root.fmApp = String(firewall.appProfiles[0])
      }
    }
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { firewall.refresh(); return "ok" }
    function status(): string { return firewall.statusText }
    // Opens the panel straight into the guided form. Handy for a keybind, and
    // it is what makes the form reachable without a mouse from outside.
    function add(): string { root.open(); root.openAdd(); return "ok" }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    tooltipText: root.tooltipText
    iconComponent: Component {
      Item {
        FirewallIcon {
          anchors.centerIn: parent
          iconSize: Style.space(13)
          color: root.barIconColor
          active: firewall.active
          warning: firewall.inconsistent
        }
      }
    }
    // Left click opens the panel; right click only re-reads state. Toggling the
    // firewall from a bar click is one slip away from taking it down, and the
    // password prompt that follows cannot say what it is for — so the toggle
    // lives in the panel, next to the rules it affects.
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) firewall.refresh()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(640))

    Item {
      id: keyGate
      anchors.fill: parent

      // The confirm dialogs are modal to the panel: PanelKeyCatcher goes quiet
      // while one is open and the unhandled keys bubble up to here.
      Keys.onPressed: function(event) {
        if (root.pendingDelete !== null) {
          if (deleteConfirm.handleKey(event)) event.accepted = true
          return
        }
        if (root.confirmDisableOpen) {
          if (disableConfirm.handleKey(event)) event.accepted = true
        }
      }

      PanelKeyCatcher {
        id: keyCatcher
        anchors.fill: parent
        blocked: root.confirmOpen || root.editing

        onMoveRequested: function(dx, dy) {
          if (!root.cursorActive) { root.cursorActive = true; return }
          if (root.mode === "add") {
            if (dy !== 0) {
              root.formIndex = Math.max(0, Math.min(root.formRows.length - 1, root.formIndex + dy))
              root.scrollItemIntoView(root.formRowItem(root.currentFormRow))
            } else if (dx !== 0) {
              root.cycleCurrentRow(dx > 0 ? 1 : -1)
            }
            return
          }
          root.moveListCursor(dy)
        }

        onActivateRequested: {
          if (!root.cursorActive) return
          if (root.mode === "add") { root.activateFormRow(); return }
          if (root.focusSection === "header") root.requestToggle()
          else if (root.focusSection === "add") root.openAdd()
        }

        onDeleteRequested: if (root.mode === "list") root.requestDelete(root.selectedRow())

        onCloseRequested: {
          if (root.mode === "add") root.closeAdd()
          else root.close()
        }

        onTabRequested: function(direction) {
          if (root.mode === "list") root.switchPanel(direction)
        }

        onTextKey: function(t) {
          if (root.mode === "add") return
          var key = String(t).toLowerCase()
          if (key === "r") firewall.refresh()
          else if (key === "t") root.requestToggle()
          else if (key === "a") root.openAdd()
          else if (key === "d") root.requestDelete(root.selectedRow())
        }

        Flickable {
          id: panelFlick
          anchors.fill: parent
          contentWidth: width
          contentHeight: column.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          interactive: contentHeight > height
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: column
            width: panelFlick.width
            spacing: Style.space(12)

            // --------------------------------------------------------- header

            Item {
              id: header
              width: parent.width
              implicitHeight: hero.implicitHeight
              readonly property bool ringVisible: root.mode === "list"
                && root.cursorActive && root.focusSection === "header"
              function focusHero() {
                if (root.mode !== "list") return
                root.cursorActive = true
                root.focusSection = "header"
                if (panelFlick) panelFlick.contentY = 0
              }

              PanelHero {
                id: hero
                width: parent.width
                title: root.mode === "add" ? "New rule" : "Firewall"
                meta: root.mode === "add" ? "Escape to go back" : firewall.statusText
                foreground: root.foreground
                fontFamily: root.fontFamily
                iconOpacity: firewall.active ? 1.0 : 0.6
                iconComponent: Component {
                  FirewallIcon {
                    iconSize: Style.font.display
                    color: firewall.inconsistent ? root.urgent : root.foreground
                    active: firewall.active
                    warning: firewall.inconsistent
                  }
                }

                trailingControl: Component {
                  ToggleSwitch {
                    id: powerSwitch
                    visible: firewall.installed && root.mode === "list"
                    checked: firewall.configEnabled
                    busy: firewall.busy
                    hasCursor: header.ringVisible
                    foreground: hero.foreground
                    onHovered: function(on) { if (on) header.focusHero() }
                    onToggled: root.requestToggle()

                    PanelToolTip {
                      visible: powerSwitch.containsMouse
                      text: firewall.configEnabled ? "Disable the firewall" : "Enable the firewall"
                      fontFamily: hero.fontFamily
                    }
                  }
                }
              }
            }

            // -------------------------------------------------------- notices

            Notice {
              visible: firewall.inconsistent
              width: parent.width
              tone: root.urgent
              text: firewall.configEnabled
                ? "ufw is enabled in its config but the unit is not running. Nothing is being filtered."
                : "ufw is disabled in its config but the unit is still running."
            }

            Notice {
              visible: !firewall.installed
              width: parent.width
              tone: root.urgent
              text: "ufw is not installed on this machine."
            }

            Text {
              textFormat: Text.PlainText
              visible: firewall.actionStatus !== "" || firewall.lastError !== ""
              width: parent.width
              text: firewall.actionStatus !== "" ? firewall.actionStatus : firewall.lastError
              color: firewall.actionStatus !== "" ? root.dim : root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            // ======================================================= LIST MODE

            Column {
              visible: root.mode === "list" && firewall.installed
              width: parent.width
              spacing: Style.spacing.labelGap

              InfoPair { label: "Incoming"; value: Model.policyLabel(firewall.defaults.input) }
              InfoPair { label: "Outgoing"; value: Model.policyLabel(firewall.defaults.output) }
              InfoPair { label: "Routed"; value: Model.policyLabel(firewall.defaults.forward) }
              InfoPair { label: "IPv6"; value: firewall.defaults.ipv6 ? "on" : "off" }
              InfoPair { label: "Logging"; value: firewall.logLevel !== "" ? firewall.logLevel : "unknown" }
            }

            PanelSeparator {
              visible: root.mode === "list" && firewall.installed
              foreground: root.foreground
            }

            Column {
              visible: root.mode === "list" && firewall.installed
              width: parent.width
              spacing: Style.space(10)

              PanelSectionHeader {
                text: "RULES"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Text {
                textFormat: Text.PlainText
                visible: root.rows.length === 0
                width: parent.width
                text: firewall.readError !== ""
                  ? firewall.readError
                  : firewall.loaded ? "No rules." : "Reading /etc/ufw…"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                horizontalAlignment: Text.AlignHCenter
              }

              Column {
                id: ruleColumn
                visible: root.rows.length > 0
                width: parent.width
                spacing: Style.space(6)

                Repeater {
                  model: root.rows
                  RuleRow {
                    required property var modelData
                    required property int index
                    width: ruleColumn.width
                    row: modelData
                    rowIndex: index
                  }
                }
              }

              CursorSurface {
                id: addButton
                width: parent.width
                implicitHeight: addLabel.implicitHeight + Style.spacing.rowPaddingX
                hasCursor: root.cursorActive && root.focusSection === "add"
                foreground: root.foreground

                MouseArea {
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onEntered: { root.cursorActive = true; root.focusSection = "add" }
                  onClicked: root.openAdd()
                }

                Text {
                  id: addLabel
                  textFormat: Text.PlainText
                  anchors.left: parent.left
                  anchors.leftMargin: Style.space(10)
                  anchors.verticalCenter: parent.verticalCenter
                  text: "+  Add rule"
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "a add · x delete · t toggle · r refresh"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                horizontalAlignment: Text.AlignHCenter
              }
            }

            // ======================================================== ADD MODE

            Column {
              id: formColumn
              visible: root.mode === "add"
              width: parent.width
              spacing: Style.space(10)

              FormRow {
                rowId: "action"
                label: "Action"
                ButtonGroup {
                  options: root.actionOptions
                  value: root.fmAction
                  focusable: false
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  cursorIndex: root.formRowHasCursor("action") ? root.optionIndex(root.actionOptions, root.fmAction) : -1
                  onChanged: function(v) { root.setFormCursor("action"); root.fmAction = v }
                  onHovered: function(i, on) { if (on) root.setFormCursor("action") }
                }
              }

              FormRow {
                rowId: "direction"
                label: "Direction"
                ButtonGroup {
                  options: root.directionOptions
                  value: root.fmDirection
                  focusable: false
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  cursorIndex: root.formRowHasCursor("direction") ? root.optionIndex(root.directionOptions, root.fmDirection) : -1
                  onChanged: function(v) { root.setFormCursor("direction"); root.fmDirection = v }
                  onHovered: function(i, on) { if (on) root.setFormCursor("direction") }
                }
              }

              FormRow {
                rowId: "kind"
                label: "Match"
                ButtonGroup {
                  options: root.kindOptions
                  value: root.fmKind
                  focusable: false
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  cursorIndex: root.formRowHasCursor("kind") ? root.optionIndex(root.kindOptions, root.fmKind) : -1
                  onChanged: function(v) { root.setKind(v) }
                  onHovered: function(i, on) { if (on) root.setFormCursor("kind") }
                }
              }

              // ---- the value, whose shape follows "Match"

              FormRow {
                rowId: "value"
                label: root.fmKind === "range" ? "Ports" : (root.fmKind === "app" ? "Profile" : "Port")

                Row {
                  spacing: Style.space(6)

                  TextField {
                    id: portField
                    visible: root.fmKind === "port"
                    width: Style.space(96)
                    placeholderText: "8080"
                    foreground: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    horizontalPadding: Style.spacing.controlGap
                    verticalPadding: Style.spacing.controlPaddingY
                    hasCursor: root.formRowHasCursor("value") && !activeFocus
                    inputMethodHints: Qt.ImhDigitsOnly
                    validator: IntValidator { bottom: 1; top: 65535 }
                    text: root.fmPort
                    onTextChanged: if (text !== root.fmPort) root.fmPort = text
                    onActiveFocusChanged: if (activeFocus) root.setFormCursor("value")
                    onAccepted: keyCatcher.forceActiveFocus()
                    Keys.onEscapePressed: keyCatcher.forceActiveFocus()
                  }

                  TextField {
                    id: portFromField
                    visible: root.fmKind === "range"
                    width: Style.space(90)
                    placeholderText: "from"
                    foreground: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    horizontalPadding: Style.spacing.controlGap
                    verticalPadding: Style.spacing.controlPaddingY
                    hasCursor: root.formRowHasCursor("value") && !activeFocus && !portToField.activeFocus
                    inputMethodHints: Qt.ImhDigitsOnly
                    validator: IntValidator { bottom: 1; top: 65535 }
                    text: root.fmPortFrom
                    onTextChanged: if (text !== root.fmPortFrom) root.fmPortFrom = text
                    onActiveFocusChanged: if (activeFocus) root.setFormCursor("value")
                    onAccepted: portToField.forceActiveFocus()
                    Keys.onEscapePressed: keyCatcher.forceActiveFocus()
                  }

                  Text {
                    textFormat: Text.PlainText
                    visible: root.fmKind === "range"
                    anchors.verticalCenter: parent.verticalCenter
                    text: "→"
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                  }

                  TextField {
                    id: portToField
                    visible: root.fmKind === "range"
                    width: Style.space(90)
                    placeholderText: "to"
                    foreground: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    horizontalPadding: Style.spacing.controlGap
                    verticalPadding: Style.spacing.controlPaddingY
                    inputMethodHints: Qt.ImhDigitsOnly
                    validator: IntValidator { bottom: 1; top: 65535 }
                    text: root.fmPortTo
                    onTextChanged: if (text !== root.fmPortTo) root.fmPortTo = text
                    onActiveFocusChanged: if (activeFocus) root.setFormCursor("value")
                    onAccepted: keyCatcher.forceActiveFocus()
                    Keys.onEscapePressed: keyCatcher.forceActiveFocus()
                  }

                  Dropdown {
                    id: appDropdown
                    visible: root.fmKind === "app"
                    width: Style.space(220)
                    showLabel: false
                    options: firewall.appProfiles
                    value: root.fmApp
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    hasCursor: root.formRowHasCursor("value")
                    onChanged: function(v) { root.setFormCursor("value"); root.fmApp = v }
                    onHovered: function(on) { if (on) root.setFormCursor("value") }
                  }
                }
              }

              FormRow {
                rowId: "proto"
                label: "Protocol"
                visible: root.fmKind !== "app"
                ButtonGroup {
                  options: root.protoOptions
                  value: root.fmProto
                  focusable: false
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  cursorIndex: root.formRowHasCursor("proto") ? root.optionIndex(root.protoOptions, root.fmProto) : -1
                  onChanged: function(v) { root.setFormCursor("proto"); root.fmProto = v }
                  onHovered: function(i, on) { if (on) root.setFormCursor("proto") }
                }
              }

              FormRow {
                rowId: "source"
                label: "Source"
                visible: root.fmKind !== "app"
                ButtonGroup {
                  options: root.sourceOptions
                  value: root.fmSourceMode
                  focusable: false
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  cursorIndex: root.formRowHasCursor("source") ? root.optionIndex(root.sourceOptions, root.fmSourceMode) : -1
                  onChanged: function(v) { root.setFormCursor("source"); root.fmSourceMode = v }
                  onHovered: function(i, on) { if (on) root.setFormCursor("source") }
                }
              }

              FormRow {
                rowId: "sourceAddr"
                label: "Address"
                visible: root.fmKind !== "app" && root.fmSourceMode === "custom"
                TextField {
                  id: sourceField
                  width: Style.space(220)
                  placeholderText: "192.168.1.0/24"
                  foreground: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  horizontalPadding: Style.spacing.controlGap
                  verticalPadding: Style.spacing.controlPaddingY
                  hasCursor: root.formRowHasCursor("sourceAddr") && !activeFocus
                  text: root.fmSource
                  onTextChanged: if (text !== root.fmSource) root.fmSource = text
                  onActiveFocusChanged: if (activeFocus) root.setFormCursor("sourceAddr")
                  onAccepted: keyCatcher.forceActiveFocus()
                  Keys.onEscapePressed: keyCatcher.forceActiveFocus()
                }
              }

              FormRow {
                rowId: "comment"
                label: "Comment"
                TextField {
                  id: commentField
                  width: Style.space(220)
                  placeholderText: "optional"
                  foreground: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  horizontalPadding: Style.spacing.controlGap
                  verticalPadding: Style.spacing.controlPaddingY
                  hasCursor: root.formRowHasCursor("comment") && !activeFocus
                  text: root.fmComment
                  onTextChanged: if (text !== root.fmComment) root.fmComment = text
                  onActiveFocusChanged: if (activeFocus) root.setFormCursor("comment")
                  onAccepted: root.submitForm()
                  Keys.onEscapePressed: keyCatcher.forceActiveFocus()
                }
              }

              PanelSeparator { foreground: root.foreground }

              // The exact command, so nothing about what is going to run has to
              // be inferred from the form.
              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.formResult.ok
                  ? Model.previewCommand(root.formResult.action, root.formResult.tokens)
                  : root.formResult.error
                color: root.formResult.ok ? root.foreground : root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              FormRow {
                rowId: "submit"
                label: ""

                Row {
                  spacing: Style.space(8)

                  Button {
                    text: "Add rule"
                    bordered: true
                    focusable: false
                    enabled: root.formResult.ok && !firewall.busy
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    fontSize: Style.font.bodySmall
                    hasCursor: root.formRowHasCursor("submit")
                    onClicked: root.submitForm()
                  }

                  Button {
                    text: "Cancel"
                    bordered: true
                    focusable: false
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    fontSize: Style.font.bodySmall
                    onClicked: root.closeAdd()
                  }
                }
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "j k move · h l change · enter edit or confirm · esc back"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                horizontalAlignment: Text.AlignHCenter
              }
            }
          }
        }
      }

      ConfirmDialog {
        id: deleteConfirm
        anchors.fill: parent
        z: 20
        opened: root.pendingDelete !== null
        message: root.pendingDelete
          ? "Delete this rule?\n" + Model.ruleSummary(root.pendingDelete)
            + (Model.isManagedComment(root.pendingDelete.comment)
              ? "\n\nThis rule was added by Omarchy's own setup."
              : "")
          : ""
        confirmText: "Delete"
        foreground: root.foreground
        fontFamily: root.fontFamily
        onCanceled: root.pendingDelete = null
        onConfirmed: root.confirmDelete()
      }

      ConfirmDialog {
        id: disableConfirm
        anchors.fill: parent
        z: 20
        opened: root.confirmDisableOpen
        message: "Turn the firewall off?\nEvery rule below stops applying until it is turned back on."
        confirmText: "Turn off"
        foreground: root.foreground
        fontFamily: root.fontFamily
        onCanceled: root.confirmDisableOpen = false
        onConfirmed: root.confirmDisable()
      }
    }
  }

  // ------------------------------------------------------------- components

  // One labelled line of the form. The label column is fixed so the controls
  // line up down the form instead of stepping in and out with the label width.
  component FormRow: Item {
    id: formRow
    property string rowId: ""
    property string label: ""
    default property alias content: contentHolder.children

    width: parent ? parent.width : 0
    implicitHeight: Math.max(labelText.implicitHeight, contentHolder.childrenRect.height)
      + Style.space(4)

    MouseArea {
      anchors.fill: parent
      acceptedButtons: Qt.NoButton
      hoverEnabled: true
      onEntered: root.setFormCursor(formRow.rowId)
    }

    Text {
      id: labelText
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      width: Style.space(78)
      text: formRow.label
      color: root.formRowHasCursor(formRow.rowId) ? root.foreground : Qt.darker(root.foreground, 1.4)
      opacity: root.formRowHasCursor(formRow.rowId) ? 1.0 : 0.75
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      elide: Text.ElideRight
    }

    Item {
      id: contentHolder
      anchors.left: labelText.right
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      implicitHeight: childrenRect.height
      height: childrenRect.height
    }
  }

  component Notice: Text {
    property color tone: root.dim
    textFormat: Text.PlainText
    color: tone
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  component RuleRow: CursorSurface {
    id: ruleRow
    property var row: null
    property int rowIndex: 0

    hasCursor: root.mode === "list" && root.cursorActive
      && root.focusSection === "rules" && root.ruleIndex === rowIndex
    foreground: root.foreground
    implicitHeight: ruleContent.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onEntered: root.setRuleCursor(ruleRow.rowIndex)
      onClicked: root.requestDelete(ruleRow.row)
    }

    RowLayout {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(8)

      Text {
        textFormat: Text.PlainText
        text: ruleRow.row && ruleRow.row.action === "allow" ? "󰅠"
          : (ruleRow.row && ruleRow.row.action === "limit" ? "󰓅" : "󰅚")
        color: ruleRow.row && ruleRow.row.action === "allow" ? root.foreground : root.urgent
        font.family: root.fontFamily
        font.pixelSize: Style.font.icon
        Layout.alignment: Qt.AlignVCenter
      }

      ColumnLayout {
        id: ruleContent
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: ruleRow.row ? String(ruleRow.row.to) : ""
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: {
            if (!ruleRow.row) return ""
            var parts = [String(ruleRow.row.actionLabel), "from " + String(ruleRow.row.from)]
            parts.push(String(ruleRow.row.familyLabel))
            if (ruleRow.row.comment) parts.push(String(ruleRow.row.comment))
            if (!ruleRow.row.deletable) parts.push("read-only")
            return parts.join("  ·  ")
          }
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      PanelActionButton {
        iconText: "󰩺"
        tooltipText: ruleRow.row && ruleRow.row.deletable
          ? "Delete this rule" : (ruleRow.row ? ruleRow.row.readOnlyReason : "")
        foreground: root.foreground
        hoverColor: root.urgent
        fontFamily: root.fontFamily
        enabled: !!(ruleRow.row && ruleRow.row.deletable) && firewall.canManage && !firewall.busy
        Layout.alignment: Qt.AlignVCenter
        onClicked: root.requestDelete(ruleRow.row)
      }
    }
  }

  component InfoPair: Row {
    property string label: ""
    property string value: ""

    width: parent.width
    spacing: Style.space(8)

    InfoLabel { text: label }
    Item {
      width: Math.max(0, parent.width - parent.children[0].implicitWidth - parent.children[2].implicitWidth - parent.spacing * 2)
      height: 1
    }
    InfoValue { text: value }
  }

  component InfoLabel: Text {
    textFormat: Text.PlainText
    color: root.foreground
    opacity: 0.6
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  component InfoValue: Text {
    textFormat: Text.PlainText
    color: root.foreground
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    elide: Text.ElideRight
  }
}
