# Audit: autostart, systemd --user, local SSH, portals, and GPU isolation (2026-07-19)

*[Leia em português](./README.md)*

Started as a broad "is this intrusion?" sweep of `/etc/xdg/autostart`, which pulled the thread all the way to a mechanism this repo hadn't documented yet: [`uwsm`](https://man.archlinux.org/man/uwsm.1) (Universal Wayland Session Manager) binds *any* autostart `.desktop` file — system or user — to the session's `systemctl --user` instance. Complements [`docs/systemd-attack-surface-reduction.md`](../../docs/systemd-attack-surface-reduction.md) (which already flagged `sshd-unix-local.socket` as a mask candidate) and the [firewall/opensnitch/net_guard audit](../2026-07-17-firewall-opensnitch-netguard/) (ports/egress, reconfirmed here but not re-detailed).

## Finding 1: autostart `.desktop` files auto-convert into `systemd --user` services (uwsm)

Hyprland on its own does not read `/etc/xdg/autostart`. But this machine runs its session through `uwsm`, which binds [`xdg-desktop-autostart.target`](https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html) (via `wayland-session-xdg-autostart@.target`, chained `BindsTo=`/`Before=`) to the graphical session's lifecycle. In practice:

```
systemctl --user list-units 'app-*' --all
```

shows `app-picom@autostart.service`, `app-gnome-keyring-pkcs11@autostart.service`, `app-cachyos-hello@autostart.service`, `app-remmina-applet@autostart.service`, etc. — generated from `/etc/xdg/autostart/*.desktop` **and** `~/.config/autostart/*.desktop` on every login, with no full GNOME/KDE session required.

This matters because it's a genuine, non-obvious persistence vector: any malicious `.desktop` dropped into `~/.config/autostart` runs silently on every login, with no cron entry, no dedicated systemd unit, no `.bashrc` edit needed. Every existing file on this machine was verified legitimate here (package owner confirmed via `pacman -Qo`, or a known first-run installer artifact — `cachyos-hello`, `remmina-applet`), but the mechanism itself was worth documenting since it wasn't covered before.

**Mitigation decision** — don't mask unit by unit (that doesn't close the door to a *new* `.desktop`), mask the trigger itself:

```
systemctl --user mask xdg-desktop-autostart.target
```

This is different from masking `systemd --user` entirely (not possible, and wouldn't make sense — under uwsm/Hyprland, `systemd --user` *is* the session's backbone: every terminal, every app tab runs as one of its scopes/slices). The target here is only the `.desktop → systemd unit` bridge.

**Consciously accepted trade-off**: this also stops `gnome-keyring` from autostarting (used by `git`/`gh`/`claude-desktop`/`libsecret` for credentials). If any of those start complaining about a missing token/password, the fix is to start the keyring manually via `exec-once` in `hyprland.conf`, not to undo the mask.

## Finding 2: `sshd-unix-local.socket` was active even with `sshd.service` disabled — applying a finding this repo's own script already predicted

`scripts/systemd-surface-audit.sh` already flagged this family ("local SSH without networking ([`systemd-ssh-generator`](https://www.freedesktop.org/software/systemd/man/latest/systemd-ssh-generator.html), systemd >=256)") as a mask candidate, but it hadn't been applied on this machine yet. Confirmed today: `sshd.service` was `disabled`/`inactive` (never answered on port 22), but `sshd-unix-local.socket` — generated unconditionally by `systemd-ssh-generator` on every boot, independent of `sshd.service` — was `active (listening)` on `/run/ssh-unix-local/socket` since boot.

Not network exposure (it's a local `AF_UNIX` socket), but it's surface nobody here uses (no local containers/VMs depending on SSH-over-Unix-socket). Masked along with the whole family:

```
systemctl mask sshd.service sshd@.service sshdgenkeys.service ssh-access.target sshd-unix-local.socket
systemctl stop sshd-unix-local.socket   # mask alone doesn't stop something already active
```

Reinforces a lesson already on record in the script: **`mask` without `--now`/`stop` does not stop an already-active unit** — it only prevents future reactivation.

## Finding 3: Samba — not installed, nothing to mask

`pacman -Qs samba` empty, `smb.service`/`smbd.service` don't exist (`not-found`). Recorded only to close the loop on the original question — not a "finding", just confirmed absence.

## Finding 4: DNS/`resolved`/`networkd` — clean; one real (non-security) bug documented and left as-is by the user's own call

Full chain audited: `resolvectl status`, `/etc/resolv.conf`, drop-ins under `/etc/systemd/resolved.conf.d`, `/etc/systemd/network/20-wired.network`, who listens on port 53 (`ss` → only `systemd-resolved`, two official, documented systemd stubs — `127.0.0.53` full-stub, `127.0.0.54` *proxy* mode without DNSSEC/cache, confirmed hardcoded in the binary via `strings` + [`man resolved.conf`](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html), nothing injected). `NetworkManager` inactive, no conflict with `networkd`. `FallbackDNS` is the stock default (Quad9/Cloudflare/Google), `LLMNR`/`mDNS` disabled.

The one real finding: `/etc/hosts` line 7 has `127.0.1.1  $onlyletther` — a template variable (`$hostname`) that was never interpolated by some installer/script, not the actual hostname. `systemd-resolved` itself already logs this (`hostname "$onlyletther" is not valid, ignoring`). Harmless — the user chose to leave it, since it makes no practical difference on a desktop machine with no need to resolve that name. Recorded here only so a future audit doesn't re-discover it from scratch and mistake it for something.

## Finding 5: ports — reconfirmation, nothing new beyond [`../2026-07-17-firewall-opensnitch-netguard/`](../2026-07-17-firewall-opensnitch-netguard/)

`ss -tulnp`: only the two `resolved` stubs (loopback), a DHCPv6 client (`systemd-networkd`, link-local, port 546 is the protocol's standard port), and one ephemeral Firefox UDP port (WebRTC). No TCP port exposed. `ufw status verbose` reconfirms `default deny incoming` and the 21 outbound-block rules for classic trojan ports (NetBus, Back Orifice, SubSeven, Metasploit 4444, IRC botnet 6667, RDP, VNC, SMB) already documented in the previous audit — no unexpected `ALLOW IN` rule.

## Finding 6: an orphaned root-owned process traced to its exact cause via `journalctl` (methodology, not an incident)

`ps aux` showed two pairs of `dbus-daemon --session` + `gnome-keyring-daemon --components=secrets` **running as root**, `PPid=1` (orphaned, no traceable parent left in `/proc`). That's the classic shape of "something suspicious" — but before acting, cross-check the journal for the exact start timestamp:

```
journalctl --since "<time-1min>" --until "<time+1min>" | grep -v net_guard
```

revealed the exact cause, PID and command of whoever requested it:

```
dbus-daemon[125008]: Activating service name='org.freedesktop.secrets'
    requested by ':1.0' (uid=0 pid=124989 comm="gh auth token")
```

`gh auth token` run as root (not from this audit session — a separate parallel `sudo -i` session) tried to read the saved GitHub CLI token via the Secret Service D-Bus API; since root never had its own D-Bus session, dbus auto-launched a private bus + keyring just to service that one request, and nothing closed it afterward. Benign, but **auditd had no log for it** (`/var/log/audit/audit.log` doesn't exist — auditd is running but not writing where `ausearch` expects; not chased further here, a candidate finding for next time) — it was the `dbus-daemon`'s own journal entry that made the investigation possible.

**Methodology takeaway**: `PPid=1` alone proves nothing (it's normal orphan-daemon reparenting, not evidence of hiding). The journal of the service that performed the *activation* (not of the process itself) usually still has the `comm=` of whoever asked, even after the original process has exited.

Processes cleaned up after identification (`kill 125008 125010 125150 125152`) — cosmetic, not security (they don't come back on their own, only if something runs `gh auth token` as root again).

## Finding 7: `xdg-desktop-portal` stack masked — with an explicit trade-off call, not a blanket mask

[`xdg-document-portal.service`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Documents.html) (out-of-sandbox file access for Flatpak/Snap) confirmed a genuine orphan — `flatpak` isn't installed on this machine (`which flatpak` empty), so nothing here actually uses that specific component. Masked without reservation.

The rest of the stack (`xdg-desktop-portal.service`, `-gtk`, `-hyprland`, `xdg-permission-store.service`) **has a real, active reverse dependency**: `pacman -Qi xdg-desktop-portal` shows `Required By: claude-desktop xdg-desktop-portal-gtk xdg-desktop-portal-hyprland`, and `xdg-desktop-portal-hyprland` is `Required By: cachyos-hypr-noctalia` (the Hyprland shell in use here). That covers the native open/save file dialog (Claude Desktop), screen capture/sharing in Firefox video calls, and possibly Noctalia's screenshot/wallpaper picker. Masked only after the user explicitly confirmed they're fine losing those — this isn't network surface (it's all local D-Bus), so the gain is a smaller set of processes/APIs available to anything running under the same UID, not a closed port.

```
systemctl --user mask xdg-document-portal.service                                    # genuine orphan
systemctl --user mask xdg-desktop-portal.service xdg-desktop-portal-gtk.service \
    xdg-desktop-portal-hyprland.service xdg-permission-store.service                  # accepted trade-off
```

If Claude Desktop stops opening its native file dialog, or Noctalia loses screenshot capability, this is why — revert with `systemctl --user unmask <unit>`.

## Finding 8: NVIDIA — `/dev/nvidia*` at `666`, Compute Mode `Default`; assessed and deliberately left unmitigated

```
crw-rw-rw- root root /dev/nvidia0 /dev/nvidiactl /dev/nvidia-modeset /dev/nvidia-uvm /dev/nvidia-uvm-tools
nvidia-smi --query-gpu=compute_mode  →  Default
```

This is the proprietary driver's out-of-the-box default on desktop Linux (no custom udev rule found anywhere under `/etc/udev/rules.d`), not something altered. `Default` compute mode ([official NVIDIA docs on `Default` vs `Exclusive_Process`](https://docs.nvidia.com/deploy/mps/index.html)) doesn't guarantee strict GPU-memory isolation between concurrent processes — a real risk class, but one NVIDIA itself frames as mainly relevant to shared multi-tenant GPUs (cloud, lab), not single-user desktops.

**Why it's not mitigated here**: `awk -F: '$3>=1000 && $3<60000'` against `/etc/passwd` confirms **exactly one login account** (`ecode`, already in the `video` group). With no second local account, there's no "other user" to isolate from — tightening to `660 root:video` via a custom udev rule wouldn't close any surface not already closed by the simple fact that only one account has a shell here. Recorded as a conscious decision, not an open item: if this machine ever gets a second login account, revisit this finding first.

## Finding 9: eBPF LSM — only `net_guard`'s 2 hooks, no third-party program, no bpffs persistence

Audited the kernel directly rather than trusting "`systemctl status` says only `net_guard` exists":

```
cat /sys/kernel/security/lsm                    # confirms 'bpf' is among the enabled LSMs
bpftool prog list | grep '^\S*: lsm'             # filters to LSM-type programs only, whole kernel
find /sys/fs/bpf -mindepth 1                     # objects pinned independent of any process
```

Result: exactly two `lsm` programs in the entire kernel — `restrict_filesystems` and `restrict_connect` — both `loaded_at` boot time (12:34:15), owned by `uid 0`, **no duplicates** (confirms the crash-loop documented in the [2026-07-17 audit](../2026-07-17-firewall-opensnitch-netguard/) is still resolved — a single load, not repeated ones from restarts). `find /sys/fs/bpf` empty: no program/map pinned surviving outside a process's normal lifecycle — the classic eBPF rootkit persistence trick (a pinned program stays active even after the loading process dies, with no PID to trace it to) ruled out.

Extra corroboration, not just "it exists, so I trust it": the maps behind `restrict_connect` (`bpftool map show id <n>`) are `blocked_ips` (LPM trie, `max_entries 1024`) and `events` (ringbuf) — the `1024` matches exactly the capacity limit that caused the crash-loop documented in Finding 4 of the 2026-07-17 audit, and the ringbuf is the channel behind the `net_guard[492]: allow/deny ...` lines already seen in the journal. Not just "a program named net_guard exists" — its internals match what was already known about this specific tool.

Side finding, not a problem: the one BPF program that looked odd at first glance (`cgroup_sysctl name sysctl_monitor`, `uid 977`) belongs to `systemd-networkd` itself (`getent passwd 977` → `systemd-network`), an internal feature of its own. The many `sd_fw_egress`/`sd_fw_ingress`/`sd_devices` (`cgroup_skb`/`cgroup_device`) entries are systemd creating one program per scope with `IPAddressAllow=`/`DeviceAllow=` — a fresh cluster per terminal/`sudo -i` session opened, normal behavior since systemd 235+.

## Finding 10: final post-mitigation verification — nothing new, no hiding technique found

After applying every mitigation above (Findings 1, 2, 7), a targeted re-audit to confirm nothing got left behind or reappeared — mitigating once isn't enough, it's worth re-checking with the system already in its final state:

```
find /sys/fs/bpf -mindepth 1                                  # bpffs: still empty
bpftool prog list | grep -c '^[0-9]*:'                        # total BPF program count stable (48)
bpftool prog list | grep '^\S*: lsm'                           # still only net_guard's 2
```

Two new checks, not covered by earlier findings — classic techniques for hiding a malicious process worth running any time you audit a machine already in use, not only right after a specific mitigation:

```
# process running from a typical malware drop location (payload from a script/download)
for p in /proc/[0-9]*; do
  readlink "$p/exe" 2>/dev/null | grep -qE '^/(tmp|dev/shm|var/tmp)/' && echo "$p"
done

# binary deleted from disk but still running in memory (hides from "ls", not from /proc)
for p in /proc/[0-9]*; do
  readlink "$p/exe" 2>/dev/null | grep -q '(deleted)' && echo "$p"
done
```

Both empty. A final pass over `ps -eo ... | grep -v <known kernel daemons>` also turned up no `root` process outside what earlier findings had already mapped (same PIDs for `net_guard`, `opensnitchd`, `fail2ban`, `ly-dm`, the already-identified `sudo -i` sessions). Audit closed with no open item.

**Re-verification on 2026-07-22, after system updates.** The question that prompted this: a systemd unit mask isn't guaranteed permanent — a package update can reinstall/re-enable the unit and silently undo the mask. Ran the full checklist again:

```
systemctl is-enabled sshd.service sshd@.service sshdgenkeys.service ssh-access.target sshd-unix-local.socket
systemctl --user is-enabled xdg-desktop-autostart.target xdg-document-portal.service \
    xdg-desktop-portal.service xdg-desktop-portal-gtk.service xdg-desktop-portal-hyprland.service xdg-permission-store.service
systemctl --user list-units 'app-*' --all
ss -tulnp
sudo bpftool prog list | grep -E '^\S*: lsm'
sudo find /sys/fs/bpf -mindepth 1
```

Result: the whole `sshd` family and the portal stack are still `masked`; `xdg-desktop-autostart.target` too — no `app-picom`, `app-gnome-keyring-pkcs11`, `app-cachyos-hello`, or `app-remmina-applet` reappeared among the `app-*` units (that's the tell that would show up if an update had undone the mask). Ports: only the `resolved` stubs plus Firefox's ephemeral traffic, nothing new. eBPF LSM: still exactly `restrict_filesystems` + `restrict_connect`, no duplicate. `/sys/fs/bpf`: empty. No orphaned/unexpected `root` process, nothing executing from `/tmp`/`/dev/shm`/`/var/tmp`, no deleted-but-running binary, still a single login account. Conclusion: the system updates did not reopen any of the mitigations — no privilege-escalation or arbitrary-command-execution vector via systemd was reintroduced.

## Reusable checklist (for the next audit of this kind)

- [ ] `systemctl --user list-units 'app-*' --all` — any new/unknown `.desktop` in `/etc/xdg/autostart` or `~/.config/autostart` turned into a unit?
- [ ] `systemctl --user is-enabled xdg-desktop-autostart.target sshd-unix-local.socket xdg-document-portal.service xdg-desktop-portal.service xdg-desktop-portal-gtk.service xdg-desktop-portal-hyprland.service xdg-permission-store.service` — all `masked`?
- [ ] `systemctl is-enabled sshd.service sshd@.service sshdgenkeys.service ssh-access.target sshd-unix-local.socket` — all `masked` at the system level too?
- [ ] `ss -tulnp` — no new TCP port exposed beyond `resolved`'s loopback stubs
- [ ] `resolvectl status` + `cat /etc/hosts` — DNS servers match the expected gateway, no new unintentional `/etc/hosts` entry
- [ ] any `root`-owned process with an unexpected name in `ps aux` — before suspecting the worst, cross-check `journalctl --since/--until` at the exact `START` second to find the `comm=` of whoever activated it (don't trust `PPid` alone, which normally becomes `1` through ordinary reparenting)
- [ ] `ls -la /dev/nvidia*` + `awk -F: '$3>=1000 && $3<60000' /etc/passwd` — if a second login account ever shows up, revisit Finding 8 (the `666` permission stops being harmless)
- [ ] `bpftool prog list | grep '^\S*: lsm'` — only the expected hooks (today: `net_guard`'s `restrict_filesystems` + `restrict_connect`), no duplicate (crash-loop) and no third-party program
- [ ] `find /sys/fs/bpf -mindepth 1` — empty, or only objects you recognize; something pinned with no traceable live process is a red flag
- [ ] process running from `/tmp`, `/dev/shm`, or `/var/tmp` (`readlink /proc/<pid>/exe`) — typical drop location for a script/download payload
- [ ] binary deleted from disk but still running in memory (`readlink /proc/<pid>/exe` ends in `(deleted)`) — hides from `ls`, not from `/proc`

## Sources

- [`man resolved.conf`](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html) — `127.0.0.53` vs `127.0.0.54` (proxy mode), `DNSStubListenerExtra`
- [`man systemd-ssh-generator`](https://www.freedesktop.org/software/systemd/man/latest/systemd-ssh-generator.html) — `sshd-unix-local.socket` generated unconditionally since systemd 256
- [`man uwsm`](https://man.archlinux.org/man/uwsm.1) — `wayland-session-xdg-autostart@.target`, integration with `xdg-desktop-autostart.target`
- [XDG Desktop Portal — official docs](https://flatpak.github.io/xdg-desktop-portal/docs/) — role of each backend (`-gtk`, `-hyprland`), sandbox-specific `xdg-document-portal`
- [NVIDIA — Multi-Instance GPU / Compute Mode docs](https://docs.nvidia.com/deploy/mps/index.html) — isolation implications of `Default` vs `EXCLUSIVE_PROCESS`
- [`bpftool-prog(8)`](https://man.archlinux.org/man/bpftool-prog.8) — listing and inspecting loaded BPF programs, including the `lsm` type
