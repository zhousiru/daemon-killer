# daemon-killer

[![CI](https://github.com/zhousiru/daemon-killer/actions/workflows/ci.yml/badge.svg)](https://github.com/zhousiru/daemon-killer/actions/workflows/ci.yml)

A fail-closed kill switch for the [Clash](https://github.com/MetaCubeX/mihomo) TUN. When Clash stops, your traffic stops.

Apps may only reach the network through the Clash TUN. If Clash exits, crashes, or the TUN goes away, a kernel firewall blocks direct traffic on the physical interfaces instead of letting it leak around the proxy. The Clash core itself is exempt, so proxy upstreams, DNS and `DIRECT` rules keep working.

- **Native on both platforms**: PF on macOS, the Windows Filtering Platform on Windows
- **Fail-closed**: rules live in the kernel and keep blocking when the daemon or Clash is gone
- **Self-healing**: if another process changes or removes the rules, the daemon puts them back
- **Safe to enable**: `up` rolls back by itself unless you confirm the network still works

## Installation

Download from [Releases](https://github.com/zhousiru/daemon-killer/releases) (`dev` tracks `main`).

**macOS**

```sh
xattr -d com.apple.quarantine daemon-killer    # the binary is unsigned
sudo ./daemon-killer install    # installs to /usr/local/bin and writes an example config
sudo vi /etc/daemon-killer/config.toml
sudo daemon-killer up           # type `yes` within 60s to keep it on
```

**Windows** (administrator terminal)

```powershell
.\daemon-killer.exe install     # installs to Program Files and adds it to PATH
notepad $env:ProgramData\daemon-killer\config.toml
daemon-killer up                # from a new terminal
```

On Windows, `core_program` must be set to the full path of `mihomo.exe`. Find it with `(Get-Process mihomo).Path`.

## Usage

| Command        | Description                                                              |
| -------------- | ------------------------------------------------------------------------ |
| `status`       | Show protection, Clash, firewall and service state, and what to do next  |
| `up`           | Turn protection on, or apply a changed config; asks to confirm           |
| `down`         | Turn protection off                                                      |
| `pause -m <N>` | Turn protection off for N minutes (default 5), e.g. for a captive portal |
| `install`      | Install or update the binary and its service; leaves the network alone   |
| `uninstall`    | Turn protection off and remove the binary and service; keeps the config  |

Every command except `status` needs root or an administrator terminal. On/off state survives reboots and upgrades.

The config is read from a fixed, admin-owned location: `/etc/daemon-killer/config.toml` on macOS and `%ProgramData%\daemon-killer\config.toml` on Windows. Run `up` after editing it.

## Troubleshooting

**The network is blocked and I can't fix Clash right now.** Run `daemon-killer down` as root or administrator. It removes the rules even if the program is not installed.

**Still offline after `down`.** daemon-killer's rules are gone; the problem is in Clash. Restart the core from Clash Party, or quit and reopen it. On Windows, disabling and re-enabling the `Mihomo` adapter does not bring the TUN back.

`status` reports Clash healthy when the adapter, core process and controller are up; that does not prove sites load, so check one before confirming `up`.

**Logs** are in `/var/log/daemon-killer.log` on macOS and `%ProgramData%\daemon-killer\daemon-killer.log` on Windows.

## Limitations

- It protects apps on this machine. Traffic from WSL, virtual machines or connection sharing is out of scope.
- Traffic is not guaranteed to go through a remote proxy: Clash `DIRECT` rules still apply, and local proxies can relay traffic for other apps.
- macOS exempts the Clash core by UID. Clash Party runs mihomo as root, so every root process may go direct. Windows exempts the core by its executable path.
- Tampering is repaired by polling, so this cannot stop an administrator process that keeps changing the rules.
- On macOS, the network is unprotected after boot until the daemon starts.

## Building

```sh
cargo build --release
```

To release, bump `version` in `Cargo.toml` and push a matching `v*` tag.

## License

[MIT](LICENSE)
