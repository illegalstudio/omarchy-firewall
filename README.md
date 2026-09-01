<p align="center">
  <img src="assets/logo-mark.png" alt="Omarchy Firewall logo" width="130">
</p>

<h1 align="center">Omarchy Firewall</h1>

<p align="center">
  <em>Your ufw rules in the Omarchy bar, and your password in front of every change.</em>
</p>

<p align="center">
  <a href="https://github.com/illegalstudio/omarchy-firewall/stargazers"><img src="https://img.shields.io/github/stars/illegalstudio/omarchy-firewall?style=flat-square&logo=github&logoColor=white&label=stars&color=E05252" alt="Stars"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/illegalstudio/omarchy-firewall?style=flat-square&color=E05252" alt="License: MIT"></a>
  <a href="https://omarchy.org"><img src="https://img.shields.io/badge/Omarchy-4.x-E05252?style=flat-square" alt="Omarchy 4.x"></a>
  <a href="https://x.com/nahime0"><img src="https://img.shields.io/badge/Follow-%40nahime0-E05252?style=flat-square&logo=x&logoColor=white" alt="Follow @nahime0 on X"></a>
</p>

<p align="center">
  <strong>No setup step &middot; Reads with no privileges &middot; Password prompt on every change &middot; Keyboard-driven</strong>
</p>

<p align="center">
  A bar widget for ufw: firewall state at a glance, the rule list in a keyboard-driven panel,
  and a guided form for adding rules. Reading needs no permissions at all, because it comes
  from the same world-readable files <code>ufw status</code> renders. Changing anything runs
  <code>pkexec ufw</code>, so Omarchy's own password dialog stands in front of every enable,
  disable, add and delete: one prompt per change, nothing cached in between.
</p>

<p align="center">
  <a href="https://opensource.nahi.me"><strong>Official Website</strong></a>
</p>

---

Plugin id `illegalstudio.omarchy-firewall`, kind `bar-widget`, built against the Omarchy 4.x
shell plugin contract.

## Why

Omarchy enables ufw by default. That is a good baseline, but it adds a small
piece of friction to everyday local development: start Expo and your phone may
need access to the Metro port; run `php artisan serve --host=0.0.0.0` and
another device needs Laravel's port; spin up any other development server and
you have to remember which ufw command opens it, and which rule to remove when
you are done. This plugin keeps the firewall configuration one click away in
the Omarchy bar, so you can inspect the current rules, open exactly the port you
need and close it again without leaving your flow. Every change still requires
your password.

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
change, including one made from a terminal. A bar widget that asked for a
password to refresh itself would be turned off within a day, and a firewall
widget nobody keeps on protects nobody.

### Writing goes through exactly one door

Every change runs as:

```
pkexec /usr/bin/ufw --force <command> [args...]
```

- **The password dialog is Omarchy's own.** pkexec hands authentication to
  polkit, which hands it to the agent running inside `omarchy-shell`
  (`omarchy.polkit`), so the prompt is the themed Omarchy dialog rather than a
  terminal or a foreign toolkit.
- **Every single change prompts.** pkexec falls under the polkit action
  `org.freedesktop.policykit.exec`, which is `auth_admin`, not
  `auth_admin_keep`. The `_keep` variant would cache the authorisation for a few
  minutes, so only the first change in a burst would ask. Enabling, disabling,
  adding a rule and deleting a rule each authenticate on their own.
- **The program that runs as root is `/usr/bin/ufw` itself:** `root:root 0755`,
  shipped by the distribution. Nothing to install, and nothing writable by the
  user's session anywhere on the privileged path.

  This is the part worth being deliberate about. An earlier draft of this plugin
  shipped its own helper script and ran *that* under pkexec. A script living
  under `~/.config` is writable by the user's session, so anything able to write
  the home directory would have got root the next time a firewall change was
  authorised. This is the same shape as the `NOPASSWD` grants that Omarchy's
  migration `1788025225` exists to delete. Working around it meant an install
  step, and an install step to use a firewall panel is the wrong trade when
  ufw's own binary already solves the problem.
- **No sudoers entry, ever**, for exactly the reason above.
- **Arguments are rebuilt, not filtered.** Nothing typed or reconstructed
  reaches ufw verbatim. `Model.walkSpec` walks the tokens, recognises each one
  (ports in range, ranges ordered, addresses well-formed, protocols tcp/udp,
  application profiles matched against `/etc/ufw/applications.d`) and returns a
  **new** array built from what it recognised. That array is what becomes the
  command, so a token the walker does not understand cannot reach the command
  line by being passed through untouched. `Service.qml` re-walks the tokens once
  more immediately before building the command, including the ones this plugin
  reconstructed itself, so no code path can skip the check.
- **No shell anywhere.** Quickshell's `Process` takes an argv array. There is no
  string to quote and nothing to escape.
- **`--force` only on `enable`.** ufw 0.36.2 mis-parses `--force` in front of a
  rule: `frontend.parse_command()` inserts the implicit `rule` keyword by
  looking at `argv[1]` and only accounts for `--dry-run`, so with `--force`
  there the keyword is never inserted and `allow` resolves to the `default`
  command family instead of `rule`. `ufw --force allow 8080/tcp` authenticates,
  runs as root and adds nothing. Only `enable` gets the flag, because only
  `enable` has a prompt ("this may disrupt existing ssh connections") and no tty
  to answer it. Rule commands do not prompt at all.
- **Deletion is by rule specification, never by number.** `ufw status numbered`
  interleaves the v4 and v6 rules and renumbers on every change, so an index
  worked out from the config files can point at a different rule by the time it
  is used. For a firewall, deleting the wrong rule means opening a port. ufw
  itself does the matching, and its matcher tolerates a differing comment
  (`common.py:match()` returns `-2` for "equal except the comment"), so the
  comment is not sent.

### What this does not protect against

An attacker who can already write your home directory can change the arguments
this plugin sends, and ride the prompt you answer. They cannot get arbitrary
code execution that way. `pkexec` is pinned to `/usr/bin/ufw`, which
manipulates firewall rules and nothing else, but they could get a rule they
chose. Nothing short of a root-owned helper closes that, and a root-owned helper
costs an install step and reintroduces a user-writable-path problem of its own
if it is ever installed carelessly. The trade is deliberate.

## Install

```bash
omarchy plugin add https://github.com/illegalstudio/omarchy-firewall.git
omarchy plugin enable illegalstudio.omarchy-firewall --section right
```

That is all of it. There is no privileged setup step: the widget reads
everything it shows without permissions, and asks for your password at the
moment it changes something.

## Using it

**Bar icon.** A shield: filled when the firewall is up, struck through when it
is down, hollow with a dot when the config and the unit disagree. Left click
opens the panel, right click re-reads state.

Right click deliberately does *not* toggle the firewall. One slip would take the
firewall down, and the polkit dialog that follows says only that a program is
being run as root; it cannot tell you *what* you are about to authorise. So the
toggle lives in the panel, next to the rules it affects, behind a confirmation
that names what it does.

**Panel.**

- `j` / `k` or arrows: move the cursor
- `enter` / `space`: activate the row under the cursor
- `a`: add a rule
- `x` or `d`: delete the rule under the cursor
- `t`: toggle the firewall
- `r`: re-read state
- `esc`: close, or cancel the rule being typed

**Adding a rule.** `a`, or the *Add rule* row, replaces the list with a guided
form. Everything with a fixed set of answers is a row of chips; the only things
typed are a port number, an optional source address and an optional comment:

| Row | Choices |
| --- | --- |
| Action | allow · deny · reject · limit |
| Direction | incoming · outgoing |
| Match | port · range · app profile |
| Port / Ports / Profile | a number, two numbers, or a profile from `/etc/ufw/applications.d` |
| Protocol | TCP · UDP · both |
| Source | anywhere · from… (then an address) |
| Comment | optional |

`j`/`k` move between rows, `h`/`l` change the value on the row you are on,
`enter` edits a text box or presses the button, `esc` goes back.

Under the form sits either the exact command that will run, such as `ufw allow
8080/tcp`, or the reason the combination is not accepted by ufw. Two such cases
the form will tell you about rather than let you find out after typing your
password: a port range has to name TCP or UDP (ufw cannot write one rule
covering both for a range), and an application profile cannot be narrowed to a
single source address (ufw has no syntax joining the two).

`omarchy-shell illegalstudio.omarchy-firewall add` opens the panel straight into the form, if
you want it on a keybind.

## What it shows read-only, and why

Some rules are displayed but cannot be deleted from the panel, marked
`read-only` with the reason in their tooltip:

- **Route rules** (`ufw route ...`): a different verb, out of scope here.
- **Interface-bound rules** (`in_eth0`): no single-command equivalent is
  reconstructed for them.
- **Multiport rules** (`80,443` in one rule) and source application profiles:
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
                                   (_runUfw: every change goes through it)
Model.js                           parsing and formatting, no Qt
FirewallIcon.qml                   the shield
assets/logo-mark.svg               the same shield, as the project mark
test/                              node test suite and fixtures
```

## Requirements

- Omarchy 4.x (`omarchy-shell` with the plugin registry)
- `ufw`
- `polkit` with the Omarchy agent (`omarchy.polkit`, on by default) and the
  account in an administrator group (`wheel`)

## Licence

MIT
