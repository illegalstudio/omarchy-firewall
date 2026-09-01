# Firewall widget for Omarchy

A bar widget for ufw: status at a glance, the rule list in a keyboard-driven
panel, and add / delete / enable / disable — with the Omarchy password dialog in
front of every change.

Plugin id `nahime.firewall`, kind `bar-widget`, built against the Omarchy 4.x
shell plugin contract.

## Security model

This is the part worth reading before anything else. Managing a firewall means
running something as root, and the shape of that matters more than the UI.

### Reading needs no privileges at all

`ufw status` refuses to run as anyone but root, so it is not used here. Every
piece of state the panel shows is read from files that are world-readable by
design, and that are the same source `ufw status` renders from:

| File | What comes from it |
| --- | --- |
| `/etc/ufw/ufw.conf` | `ENABLED`, log level |
| `/etc/default/ufw` | default incoming / outgoing / routed policy, IPv6 |
| `/etc/ufw/user.rules`, `user6.rules` | the rules, as `### tuple ###` lines |
| `/etc/ufw/applications.d/` | application profile names |
| `systemctl is-active ufw` | whether the unit is actually running |

They are watched, not polled, so the panel is right within a moment of any
change — including one made from a terminal. A bar widget that asked for a
password to refresh itself would be turned off within a day, and a firewall
widget nobody keeps on protects nobody.

### Writing goes through exactly one door

Every change runs as:

```
pkexec /usr/local/lib/omarchy-firewall/omarchy-firewall <command> [args...]
```

- **The password dialog is Omarchy's own.** pkexec hands authentication to
  polkit, which hands it to the agent running inside `omarchy-shell`
  (`omarchy.polkit`), so the prompt is the themed Omarchy dialog rather than a
  terminal or a foreign toolkit.
- **Every single change prompts.** The polkit action
  `dev.nahime.firewall.manage` is declared `auth_admin`, not `auth_admin_keep`.
  `auth_admin_keep` would cache the authorisation for a few minutes, so only the
  first change in a burst would ask. Enabling, disabling, adding a rule and
  deleting a rule each authenticate on their own.
- **`allow_any` and `allow_inactive` are `no`.** The change has to come from the
  session actually sitting at the machine.
- **The program that runs as root is root-owned.** The helper is copied to
  `/usr/local/lib/omarchy-firewall/` as `root:root 0755`, and the polkit action
  is pinned to that path. The copy in this plugin directory lives under
  `~/.config` and is writable by the user's session; running *that* under pkexec
  would mean anything able to write the user's home gets root the next time a
  firewall change is authorised. It is never executed.
- **Arguments are validated as root, by the helper.** Nothing the caller sends
  is forwarded to ufw verbatim: the helper walks the tokens, checks each one
  (ports in range, ranges ordered, addresses well-formed, protocols tcp/udp,
  application profiles checked against `ufw app list`), and rebuilds ufw's argv
  from the validated pieces. No shell is involved anywhere on the path. The
  panel validates too, but only so a typo produces an inline message instead of
  a password prompt followed by an error — that check is a convenience and is
  not what makes anything safe.
- **No sudoers entry, ever.** Omarchy's own migration `1788025225` exists to
  delete `NOPASSWD: /usr/bin/ufw` grants left behind by retired installers,
  because they were a privilege escalation. This plugin does not reintroduce
  one under a new name.
- **Deletion is by rule specification, never by number.** `ufw status numbered`
  interleaves the v4 and v6 rules and renumbers on every change, so an index
  worked out from the config files can point at a different rule by the time it
  is used. For a firewall, deleting the wrong rule means opening a port. ufw
  itself does the matching.

Until `install.sh` has been run the plugin still loads and still shows
everything — it is simply read-only, and says so.

## Install

```bash
omarchy plugin add https://github.com/nahime/omarchy-firewall.git
sudo ~/.config/omarchy/plugins/nahime.firewall/install.sh
omarchy plugin enable nahime.firewall --section right
```

`install.sh` is the only step that needs root, and it is needed once. It
installs two files:

```
/usr/local/lib/omarchy-firewall/omarchy-firewall          root:root 0755
/usr/share/polkit-1/actions/dev.nahime.firewall.policy    root:root 0644
```

Re-run it after pulling an update that touches `bin/` or `polkit/`; the plugin
runs the installed copy, not the one in the repo.

`sudo ./uninstall.sh` removes both and drops the plugin back to read-only.

## Using it

**Bar icon.** A shield: filled when the firewall is up, struck through when it
is down, hollow with a dot when the config and the unit disagree. Left click
opens the panel, right click re-reads state.

Right click deliberately does *not* toggle the firewall. One slip would take the
firewall down, and the password dialog that follows says only that the firewall
is being changed — so the toggle lives in the panel, next to the rules it
affects, behind a confirmation that names what it does.

**Panel.**

- `j` / `k` or arrows — move the cursor
- `enter` / `space` — activate the row under the cursor
- `a` — add a rule
- `x` or `d` — delete the rule under the cursor
- `t` — toggle the firewall
- `r` — re-read state
- `esc` — close, or cancel the rule being typed

**Adding a rule.** Type it the way you would type it at a ufw prompt, minus the
`ufw`:

```
allow 8080/tcp
limit 22/tcp
allow 60000:61000/udp
deny out 25/tcp
allow mosh
allow in proto tcp from 192.168.1.0/24 to any port 5432
allow 8080/tcp comment expo metro
```

The line under the field previews the exact `ufw` command that will run, or says
what is wrong with what you typed.

## What it shows read-only, and why

Some rules are displayed but cannot be deleted from the panel, marked
`read-only` with the reason in their tooltip:

- **Route rules** (`ufw route ...`) — a different verb, out of scope here.
- **Interface-bound rules** (`in_eth0`) — no single-command equivalent is
  reconstructed for them.
- **Multiport rules** (`80,443` in one rule) and source application profiles —
  same reason.

The rule shapes that cannot be reproduced exactly are shown as they are rather
than deleted by an approximation of themselves.

Two other things worth knowing:

- **`ufw-docker`.** Docker's rules live in `/etc/ufw/after.rules` and in the
  `DOCKER-USER` chain, outside the tuple model, so they do not appear here at
  all. A published container port can be reachable even when this panel shows
  nothing allowing it. Check `sudo iptables -L DOCKER-USER -n` for those.
- **Config, not kernel.** These files are ufw's configuration. If something has
  edited `iptables`/`nft` directly, the kernel and this panel can disagree; the
  panel is honest about being the former.

Rules Omarchy's own installer wrote (`omarchy-sshd`, `allow-docker-dns`) are
labelled, and deleting one says so in the confirmation.

## Development

`Model.js` is plain ES5 with no Qt imports, so all the parsing is testable
without a shell and without root:

```bash
node test/run.js           # assertions
node test/run.js --show    # plus the parsed table, to compare with
                           # sudo ufw status numbered
```

The fixtures under `test/fixtures/` were captured from a real Omarchy machine
with the stock ufw setup plus a few hand-added rules.

Saving any file under `~/.config/omarchy/plugins/` reloads the plugin
automatically. If a change does not land, force it with:

```bash
omarchy-shell shell rescanPlugins
```

## Layout

```
manifest.json                      plugin manifest (schemaVersion 1)
Panel.qml                          bar button + popup panel
Service.qml                        state, file watchers, the one privileged path
Model.js                           parsing and formatting, no Qt
FirewallIcon.qml                   the shield
bin/omarchy-firewall               the only thing that ever runs as root
polkit/dev.nahime.firewall.policy  the action pkexec authenticates against
install.sh / uninstall.sh          install the two files above, as root
test/                              node test suite and fixtures
```

## Requirements

- Omarchy 4.x (`omarchy-shell` with the plugin registry)
- `ufw`
- `polkit` with the Omarchy agent (`omarchy.polkit`, on by default)

## Licence

MIT
