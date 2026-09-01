import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "nahime.firewall"
  ipcTarget: "nahime.firewall"
  manageIpc: false

  // header | rules | add
  property string focusSection: "header"
  property int ruleIndex: 0
  property bool cursorActive: false

  property bool addOpen: false
  property string addText: ""
  property string addError: ""

  property var pendingDelete: null
  property bool confirmDisableOpen: false
  readonly property bool confirmOpen: pendingDelete !== null || confirmDisableOpen

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property var rows: firewall.rows
  readonly property var parsedInput: Model.parseRuleInput(root.addText, firewall.appProfiles)

  // Amber-ish only in the sense that the theme's urgent colour is what every
  // other widget uses to say "look at this"; the icon shape carries the state
  // too, for anyone who cannot pick the colour out.
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

  // ------------------------------------------------------------------ cursor

  function ensureCursor() {
    if (focusSection === "rules") {
      if (rows.length === 0) { focusSection = "header"; ruleIndex = 0; return }
      if (ruleIndex >= rows.length) ruleIndex = rows.length - 1
      if (ruleIndex < 0) ruleIndex = 0
    }
    if (focusSection === "add" && !addOpen) focusSection = "header"
  }

  function moveCursor(dx, dy) {
    cursorActive = true
    ensureCursor()
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
    if (focusSection !== "rules" || rows.length === 0) return null
    return rows[Math.max(0, Math.min(ruleIndex, rows.length - 1))]
  }

  function setRuleCursor(index) {
    cursorActive = true
    focusSection = "rules"
    ruleIndex = index
  }

  function activateCursor() {
    ensureCursor()
    if (focusSection === "header") requestToggle()
    else if (focusSection === "add") openAdd()
  }

  // ----------------------------------------------------------------- actions

  function requireManage() {
    if (firewall.canManage) return true
    firewall.lastError = "ufw is not installed."
    return false
  }

  // Disabling asks twice on purpose. The password dialog that follows is
  // polkit's, and says only that a program is being run as root, so the
  // question of whether to take the firewall down entirely is put here, where
  // it can name what it means.
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
    addOpen = true
    focusSection = "add"
    cursorActive = true
    Qt.callLater(function() { addField.forceActiveFocus() })
  }

  function closeAdd() {
    addOpen = false
    addText = ""
    addError = ""
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function submitAdd() {
    var parsed = root.parsedInput
    if (!parsed.ok) {
      addError = parsed.error !== "" ? parsed.error : "Type a rule, for example: allow 8080/tcp"
      return
    }
    addError = ""
    if (firewall.addRule(parsed.action, parsed.tokens)) closeAdd()
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
    if (focusSection === "rules" && ruleColumn && ruleIndex >= 0 && ruleIndex < ruleColumn.children.length) {
      scrollItemIntoView(ruleColumn.children[ruleIndex])
    } else if (focusSection === "add") {
      scrollItemIntoView(addSection)
    }
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    cursorActive = false
    focusSection = "header"
    ruleIndex = 0
    pendingDelete = null
    confirmDisableOpen = false
    closeAdd()
    if (panelFlick) panelFlick.contentY = 0
    firewall.refresh()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  } else {
    pendingDelete = null
    confirmDisableOpen = false
    addOpen = false
  }

  onRuleIndexChanged: scrollCursorIntoView()

  Service {
    id: firewall
    settings: root.settings
  }

  Connections {
    target: firewall
    function onRowsChanged() { root.ensureCursor() }
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
    // firewall from a bar click is one slip away from taking the firewall down,
    // and the password prompt that follows does not say what it is for — so the
    // toggle lives in the panel, next to the rules it affects.
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
    contentWidth: panel.fittedContentWidth(Style.space(430))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(620))

    Item {
      id: keyGate
      anchors.fill: parent

      // The confirm dialog is modal to the panel: PanelKeyCatcher goes quiet
      // while it is open and the unhandled keys bubble up to here.
      Keys.onPressed: function(event) {
        if (root.pendingDelete !== null) {
          if (deleteConfirm.handleKey(event)) event.accepted = true
          return
        }
        if (root.confirmDisableOpen) {
          if (disableConfirm.handleKey(event)) event.accepted = true
          return
        }
      }

      PanelKeyCatcher {
        id: keyCatcher
        anchors.fill: parent
        blocked: root.confirmOpen || addField.activeFocus

        onMoveRequested: function(dx, dy) {
          if (!root.cursorActive) { root.cursorActive = true; return }
          root.moveCursor(dx, dy)
        }
        onActivateRequested: if (root.cursorActive) root.activateCursor()
        onDeleteRequested: root.requestDelete(root.selectedRow())
        onCloseRequested: {
          if (root.addOpen) root.closeAdd()
          else root.close()
        }
        onTabRequested: function(direction) { root.switchPanel(direction) }
        onTextKey: function(t) {
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

            // ------------------------------------------------------- header

            Item {
              id: header
              width: parent.width
              implicitHeight: hero.implicitHeight
              readonly property bool ringVisible: root.cursorActive && root.focusSection === "header"
              function focusHero() {
                root.cursorActive = true
                root.focusSection = "header"
                if (panelFlick) panelFlick.contentY = 0
              }

              PanelHero {
                id: hero
                width: parent.width
                title: "Firewall"
                meta: firewall.statusText
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
                    visible: firewall.installed
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

            // ------------------------------------------------------ notices

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

            // ----------------------------------------------------- defaults

            Column {
              visible: firewall.installed
              width: parent.width
              spacing: Style.spacing.labelGap

              InfoPair { label: "Incoming"; value: Model.policyLabel(firewall.defaults.input) }
              InfoPair { label: "Outgoing"; value: Model.policyLabel(firewall.defaults.output) }
              InfoPair { label: "Routed"; value: Model.policyLabel(firewall.defaults.forward) }
              InfoPair { label: "IPv6"; value: firewall.defaults.ipv6 ? "on" : "off" }
              InfoPair { label: "Logging"; value: firewall.logLevel !== "" ? firewall.logLevel : "unknown" }
            }

            PanelSeparator {
              visible: firewall.installed
              foreground: root.foreground
            }

            // -------------------------------------------------------- rules

            Column {
              visible: firewall.installed
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
                text: firewall.loaded ? "No rules." : "Reading /etc/ufw…"
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

              // ---------------------------------------------------- add rule

              Item {
                id: addSection
                width: parent.width
                implicitHeight: root.addOpen ? addForm.implicitHeight : addButton.implicitHeight

                CursorSurface {
                  id: addButton
                  visible: !root.addOpen
                  width: parent.width
                  implicitHeight: addLabel.implicitHeight + Style.spacing.rowPaddingX
                  hasCursor: root.cursorActive && root.focusSection === "add"
                  foreground: root.foreground
                  opacity: firewall.canManage ? 1.0 : 0.5

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

                Column {
                  id: addForm
                  visible: root.addOpen
                  width: parent.width
                  spacing: Style.spacing.labelGap

                  RowLayout {
                    width: parent.width
                    spacing: Style.space(6)

                    TextField {
                      id: addField
                      Layout.fillWidth: true
                      placeholderText: "allow 8080/tcp"
                      foreground: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      horizontalPadding: Style.spacing.controlGap
                      verticalPadding: Style.spacing.controlPaddingY
                      enabled: !firewall.busy
                      text: root.addText
                      onTextChanged: if (text !== root.addText) { root.addText = text; root.addError = "" }
                      onAccepted: root.submitAdd()
                      Keys.onEscapePressed: root.closeAdd()
                    }

                    PanelActionButton {
                      iconText: "󰄬"
                      tooltipText: "Add the rule"
                      foreground: root.foreground
                      fontFamily: root.fontFamily
                      enabled: !firewall.busy && root.parsedInput.ok
                      Layout.alignment: Qt.AlignVCenter
                      onClicked: root.submitAdd()
                    }

                    PanelActionButton {
                      iconText: "󰅖"
                      tooltipText: "Cancel"
                      foreground: root.foreground
                      fontFamily: root.fontFamily
                      Layout.alignment: Qt.AlignVCenter
                      onClicked: root.closeAdd()
                    }
                  }

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    text: {
                      if (root.addError !== "") return root.addError
                      if (root.addText !== "" && !root.parsedInput.ok && root.parsedInput.error !== "")
                        return root.parsedInput.error
                      if (root.parsedInput.ok)
                        return "ufw " + root.parsedInput.action + " " + root.parsedInput.tokens.join(" ")
                      return "allow | deny | reject | limit, then a port, a range, an app profile, or from/to"
                    }
                    color: (root.addError !== "" || (root.addText !== "" && !root.parsedInput.ok))
                      ? root.urgent : root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }
                }
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: firewall.installed
              width: parent.width
              text: "a add · x delete · t toggle · r refresh"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              horizontalAlignment: Text.AlignHCenter
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

    hasCursor: root.cursorActive && root.focusSection === "rules" && root.ruleIndex === rowIndex
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
