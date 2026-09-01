import QtQuick
import QtQuick.Shapes
import qs.Commons

// Shield drawn as a shape rather than loaded as an SVG, for the same reason the
// Tailscale widget draws its mark by hand: a small SVG scaled into a bar slot
// renders unevenly, and a path takes the theme colour directly.
//
// Filled when the firewall is up, hollow when it is down, with a bar struck
// through it when it is down. The state has to be readable at bar size out of
// the corner of an eye, so it is carried by the silhouette and not by colour
// alone.
Item {
  id: root

  property real iconSize: Style.font.icon
  property color color: Color.foreground
  property bool active: true
  // Config and runtime disagree: shown as a hollow shield with a dot, never as
  // the reassuring filled one.
  property bool warning: false

  readonly property real strokeWidth: Math.max(1, iconSize * 0.11)

  width: iconSize * 0.86
  height: iconSize
  implicitWidth: width
  implicitHeight: height

  Shape {
    anchors.fill: parent
    antialiasing: true
    layer.enabled: true
    layer.samples: 4

    ShapePath {
      fillColor: root.active && !root.warning ? root.color : "transparent"
      strokeColor: root.color
      strokeWidth: root.strokeWidth
      joinStyle: ShapePath.RoundJoin
      capStyle: ShapePath.RoundCap

      startX: root.width * 0.5
      startY: root.height * 0.06
      PathLine { x: root.width * 0.93; y: root.height * 0.24 }
      PathLine { x: root.width * 0.93; y: root.height * 0.55 }
      PathLine { x: root.width * 0.5;  y: root.height * 0.96 }
      PathLine { x: root.width * 0.07; y: root.height * 0.55 }
      PathLine { x: root.width * 0.07; y: root.height * 0.24 }
      PathLine { x: root.width * 0.5;  y: root.height * 0.06 }
    }

    // Struck through when the firewall is off.
    ShapePath {
      strokeColor: root.active ? "transparent" : root.color
      strokeWidth: root.strokeWidth
      capStyle: ShapePath.RoundCap
      startX: root.width * 0.16
      startY: root.height * 0.84
      PathLine { x: root.width * 0.84; y: root.height * 0.16 }
    }
  }

  // Config and runtime disagree.
  Rectangle {
    visible: root.warning
    width: root.strokeWidth * 1.6
    height: width
    radius: width / 2
    color: root.color
    anchors.horizontalCenter: parent.horizontalCenter
    anchors.verticalCenter: parent.verticalCenter
    anchors.verticalCenterOffset: -root.height * 0.04
  }
}
