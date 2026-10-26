# ssh2mcp

MCP server exposing one remote host (reached over `ssh`) as three tools: `s_shell`,
`s_xfer`, `s_file`. Built for the "compile on the server, install on the phone" workflow:
the agent keeps its workspace on the device and reaches the build machine through this
server instead of binding a second workspace.

## Transport and auth

- Binds `127.0.0.1:6222` (`SSH2MCP_BIND`, `MCP_PORT`).
- Streamable HTTP only: `POST /mcp`, stateless (a fresh server + transport per request).
  `GET`/`DELETE /mcp` answer 405, as the SDK's own stateless example does.
- Every route requires `Authorization: Bearer <token>`, read per request from
  `~/.ssh2mcp-token` (or `SSH2MCP_TOKEN_FILE`). Rotating the file needs no restart.
- The server **refuses to start** without a token. Binding to loopback is not access
  control: any app on the device with INTERNET permission can reach 127.0.0.1, and this
  process runs commands as root on a machine that has a public port.
- `localhostHostValidation()` rejects DNS-rebinding hosts on every route.

Generate the token yourself so it never passes through the model:

```bash
python3 -c "import secrets;print(secrets.token_hex(24))" > ~/.ssh2mcp-token && chmod 600 ~/.ssh2mcp-token
```

Client config: URL `http://127.0.0.1:6222/mcp`, header `Authorization: Bearer <token>`.

## Permission levels

`--perm ro|rw|full|selfcheck` (default `rw`), or `SSH2MCP_PERM`. Raising the level to
`full` through the CLI needs `--force` (`s2m perm full --force`), and `s2m st` prints a
warning line whenever the live level is not `rw`. The live value is read
per request from `~/.ssh2mcp-perm`, so `echo ro > ~/.ssh2mcp-perm` switches without a
restart. An unreadable or invalid file falls back to the startup value (never widens it).

| | `ro` | `rw` | `full` | `selfcheck` |
|---|---|---|---|---|
| `s_shell` command | read-only allowlist | any | any | refused |
| `s_shell` bg / kill | log only | yes | yes | refused |
| `s_xfer` pull | yes | yes | yes | refused |
| `s_xfer` push | no | yes (+ reminder) | yes | refused |
| `s_file` | yes | yes | yes | refused |
| risk rules | block | block | warn only | n/a |
| path jail | on | on | off | n/a |

`ro` allows a single command line: no `>`, `<`, `;`, `&&`, `||`, `$()`, backticks, and
`|` only between allowlisted commands. `find` may not use `-delete`/`-exec`, `java` only
`-version`, `apksigner` only `verify`, `aapt2` only `dump`, `date` not `-s`, and `env` is
excluded because it executes its arguments. This is a guard against accidents, not a
sandbox: a deliberately crafted equivalent command will get through.

## Tools

### `s_shell`

`{op: "run"|"bg"|"log"|"kill", command, cwd?, timeout_s?, job?, since?}`

- `run` returns `{exit, ms, stdout, stderr, timed_out}`; output keeps the first 70% and
  last 30% of `SSH2MCP_MAX_OUTPUT` characters.
- `bg` writes the command to `/tmp/s2m-<job>.cmd` over stdin (no shell quoting of the
  payload), starts it with `setsid`, and returns a job id plus pid.
- `log` returns the chunk after `since` (a byte offset) plus `next_since` and the state
  (`running` / `done:<code>` / `gone`), so a client polls without re-reading the log.
- `run` is bounded on both ends: the command goes to the host as
  `timeout -k 5 <N> sh -c '<cmd>'`, so the deadline stops the remote process group too,
  and the call returns at the deadline instead of at the end of the remote command.
  `bg` is not bounded — use it for anything that must outlive a call.
- `run` opts out of connection multiplexing (`ControlPath=none`). Under `ControlMaster`
  the mux master keeps the stdio pipe open after the client is killed, so the call used
  to stay blocked until the remote command finished; the opt-out costs ~0.6 s per call.

### `s_xfer`

`{op: "pull"|"push"|"status", local, remote, verify?}`

`pull` = remote to device, `push` = device to remote. The exit code is read from the ssh
child itself rather than from the closing of its stdio pipe: on small files the child can
exit before the pipe drains, and waiting for `close` afterwards hung the call. Both resume
from the first missing
byte (`tail -c +N` on the sending side), write to `<dest>.part`, and only rename after
`sha256` matches on both ends. A mismatch renames the partial to `.corrupt` and fails; it
never reports success for a truncated file. Bytes never enter the model context.

`push` always verifies (`verify:false` is rejected): a silent half file on the build
machine is worse than a failure.

### `s_file`

`{op: "compare"|"stat"|"hash"|"list"|"read", path, side?, local_root?, remote_root?, local_path?, remote_path?}`

Path rules: `path` plus `local_root`/`remote_root` addresses the *same relative path* in
both trees; an absolute `path` is used verbatim on both sides (so it only makes sense when
the trees share a layout, and combining an absolute `path` with a root is rejected rather
than silently resolved against one tree twice). To compare two files that live at
different paths, pass `local_path` + `remote_path`.

Read-only by design. Writes exist only in `s_xfer`, so a remote tree cannot be edited
behind git's back. `compare` returns `same` / `size-differs` / `content-differs` /
`missing:<side>`, plus the first differing line for text files up to 64 KB. Files above
128 MB are compared by size and mtime only.

## Environment

| var | default | meaning |
|---|---|---|
| `MCP_PORT` | 6222 | listen port |
| `SSH2MCP_BIND` | 127.0.0.1 | bind address |
| `SSH2MCP_SSH_HOST` | `cloud` | `~/.ssh/config` Host alias |
| `SSH2MCP_ROOT` | unset | remote path jail (`s_file`, `s_xfer`, `cwd`) |
| `SSH2MCP_PERM` | `rw` | startup permission level |
| `SSH2MCP_TOKEN_FILE` | `~/.ssh2mcp-token` | bearer token |
| `SSH2MCP_PERM_FILE` | `~/.ssh2mcp-perm` | hot-switch permission file |
| `SSH2MCP_MAX_OUTPUT` | 20000 | chars of stdout/stderr kept per call |
| `SSH2MCP_TIMEOUT_MS` | 120000 | default `run` timeout (max 3600000) |
| `SSH2MCP_SSH_BIN` | `ssh` | ssh binary |

Prerequisite: key-based auth to the host (`BatchMode=yes` is forced, so a password prompt
is a hard failure rather than a hang).

## CLI

```
node index.js [--perm <level>] [--port N]
node index.js --self-test     # offline: risk table + ro allowlist assertions, exit 1 on failure
node index.js --self-check    # connectivity, remote toolchain, tmp roundtrip, token/perm state
node index.js --help
```

`--self-check` is the fastest way to answer "is the build machine actually ready".

## s2m (short command line)

`~/ssh2mcp/s2m`, symlinked into `$PREFIX/local/bin` as `s2m` plus five-letter aliases.
Every subcommand talks to the MCP endpoint, so the permission level, the path jail and the
risk table apply to the CLI exactly as they do to the agent — there is no second code path
that could bypass them.

| command | alias | does |
|---|---|---|
| `s2m st` | `s2mstl` | server state, effective perm, last log + audit line |
| `s2m start [--perm L]` | | (re)start detached |
| `s2m stop` | | stop |
| `s2m perm [L\|off]` | | show / hot-switch `ro`, `rw`, `full`, `selfcheck` |
| `s2m sh [--cwd D] [--timeout S] CMD` | `s2msh` | run remotely, exit code passes through |
| `s2m bg [--cwd D] CMD` | `s2mbg` | detached job, prints the id |
| `s2m log JOB [since]` | | job output from a byte offset |
| `s2m kill JOB` | | stop a job |
| `s2m jobs` | | list jobs on the host (`running` / `done:N` / `gone`) |
| `s2m pull REMOTE [LOCAL]` | `s2mpl` | host -> device, default `~/incoming/` |
| `s2m push LOCAL REMOTE` | `s2mps` | device -> host |
| `s2m cmp PATH [--local-root D] [--remote-root D]` | | both-sides compare |
| `s2m token [new]` | `s2mtk` | show the bearer token masked / rotate it |
| `s2m audit [N]` | | tail the audit log |
| `s2m check` | `s2mck` | remote connectivity + toolchain |
| `s2m test [--full]` | | offline rules + smoke (+ end-to-end) |

## Audit

A permission change is recorded too (`perm-change`, with the previous level): the hot
file can be edited by hand, so the server logs the first call made under a new level
rather than the write itself. Every call appends one JSON line to `~/.ssh2mcp/audit.log`: timestamp, tool, op, perm,
matched rule ids, exit code, duration. Commands are stored as a sha256 prefix, not as
text, so credentials on a command line do not land in the log.

## Known limits

- The risk table is regex over the command string: it catches the usual destructive
  shapes, not an obfuscated equivalent.
- `ro` cannot tell a read-only `git` invocation from a state-changing one beyond the
  subcommand allowlist.
- Stateless Streamable HTTP cannot push token-by-token text; progress is delivered by
  `bg` + `log` polling instead.
- The `run` timeout is a hard cap on the host as well: a long build is killed mid-way if
  `timeout_s` is left at the default 120 s.
- One remote at a time (one `SSH2MCP_SSH_HOST`). Multiple hosts need multiple instances
  on different ports.

## License

MIT — see [LICENSE](LICENSE).
