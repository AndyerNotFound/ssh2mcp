# ssh2mcp

An MCP server that exposes one remote host, reached over `ssh`, as three tools: `s_shell`,
`s_xfer` and `s_file`. It serves the "compile on the server, install on the phone" workflow:
the agent keeps its workspace on the device and reaches the build machine through this
server, rather than binding a second workspace.

## Requirements

- Key-based `ssh` access to the host, configured as a Host alias in `~/.ssh/config`.
  `BatchMode=yes` is forced, so a password prompt is a hard failure rather than a hang.
- Node.js with the MCP SDK, Express and Zod (`npm install`).

## Transport and auth

- Listens on `127.0.0.1:6222` (`SSH2MCP_BIND`, `MCP_PORT`) and speaks Streamable HTTP only.
  `POST /mcp` is stateless, with a fresh server and transport per request; `GET` and
  `DELETE /mcp` answer 405.
- Every route requires `Authorization: Bearer <token>`, read per request from
  `~/.ssh2mcp-token` (`SSH2MCP_TOKEN_FILE`); rotating the file needs no restart. The server
  refuses to start without one.
- `localhostHostValidation()` rejects DNS-rebinding hosts on every route.
- Loopback is not access control: any app on the device with the INTERNET permission can
  reach 127.0.0.1, while the commands themselves run with the privileges of the ssh user on
  the remote host. Keep the token at mode 600 and treat both ends as privileged.

Generate the token yourself, so that it never passes through a model:

```bash
python3 -c "import secrets;print(secrets.token_hex(24))" > ~/.ssh2mcp-token
chmod 600 ~/.ssh2mcp-token
```

Client: `http://127.0.0.1:6222/mcp`, header `Authorization: Bearer <token>`.

## Permission levels

`--perm ro|rw|full|selfcheck` (default `rw`, or `SSH2MCP_PERM`). The live value is read per
request from `~/.ssh2mcp-perm`, so `echo ro > ~/.ssh2mcp-perm` switches without a restart; an
unreadable or invalid file falls back to the startup level and never widens it. Raising the
level to `full` from the CLI requires `--force`, and `s2m st` warns whenever the live level is
not `rw`.

| | `ro` | `rw` | `full` | `selfcheck` |
|---|---|---|---|---|
| `s_shell` command | read-only allowlist | any | any | refused |
| `s_shell` bg / kill | log only | yes | yes | refused |
| `s_xfer` pull | yes | yes | yes | refused |
| `s_xfer` push | no | yes (+ reminder) | yes | refused |
| `s_file` | yes | yes | yes | refused |
| risk rules | block | block | warn only | n/a |
| path jail | on | on | off | n/a |

`ro` accepts a single command line: no `>`, `<`, `;`, `&&`, `||`, `$()` or backticks, and `|`
only between allowlisted commands. `find` may not use `-delete` or `-exec`; `java` only
`-version`; `apksigner` only `verify`; `aapt2` only `dump`; `date` not `-s`; `env` is excluded
because it executes its arguments. This is a guard against accidents, not a sandbox; a
deliberately crafted equivalent command passes.

## Tools

### `s_shell`

`{op: "run" | "bg" | "log" | "kill", command, cwd?, timeout_s?, job?, since?}`

- `run` returns `{exit, ms, stdout, stderr, timed_out}`, keeping the first 70% and the last
  30% of `SSH2MCP_MAX_OUTPUT` characters.
- `run` is bounded on both ends: the command is sent as `timeout -k 5 <N> sh -c '<cmd>'`, so
  the deadline stops the remote process group as well, and the call returns at the deadline.
- `run` opts out of connection multiplexing (`ControlPath=none`; under `ControlMaster` a
  killed client leaves the pipe to the mux master open, and the call blocks until the remote
  command ends). Cost: about 0.6 s per call.
- `bg` writes the command to `/tmp/s2m-<job>.cmd` over stdin, so the payload needs no shell
  quoting, starts it with `setsid`, and returns a job id and pid. A background job is not
  bounded by `timeout_s`.
- `log` returns the chunk after `since`, a byte offset, with `next_since` and the state
  (`running`, `done:<code>`, `gone`), so a client polls without re-reading the log.

### `s_xfer`

`{op: "pull" | "push" | "status", local, remote, verify?}`

- `pull` copies from the host to the device; `push` copies from the device to the host.
- Both resume from the first missing byte (`tail -c +N` on the sending side), write to
  `<dest>.part`, and rename only after `sha256` matches on both ends. A mismatch renames the
  partial to `.corrupt` and fails; a truncated file is never reported as success.
- Bytes never enter the model context.
- `push` always verifies; `verify: false` is rejected, because a silently truncated file on
  the build machine is worse than a failure.

### `s_file`

```js
{op: "compare" | "stat" | "hash" | "list" | "read", path, side?,
 local_root?, remote_root?, local_path?, remote_path?}
```

- `path` with `local_root` and `remote_root` addresses the same relative path in both trees;
  an absolute `path` is used verbatim on both sides, and combining it with a root is rejected
  rather than resolved against one tree twice.
- To compare two files at different paths, pass `local_path` and `remote_path`.
- The tool is read-only. Writes live only in `s_xfer`, so a remote tree cannot be edited
  behind git's back.
- `compare` returns `same`, `size-differs`, `content-differs` or `missing:<side>`, plus the
  first differing line for text files up to 64 KB. Files above 128 MB are compared by size
  and mtime only.

## Configuration

| var | default | meaning |
|---|---|---|
| `MCP_PORT` | 6222 | listen port |
| `SSH2MCP_BIND` | 127.0.0.1 | bind address |
| `SSH2MCP_SSH_HOST` | `myhost` | `~/.ssh/config` Host alias |
| `SSH2MCP_ROOT` | unset | remote path jail (`s_file`, `s_xfer`, `cwd`) |
| `SSH2MCP_PERM` | `rw` | startup permission level |
| `SSH2MCP_TOKEN_FILE` | `~/.ssh2mcp-token` | bearer token |
| `SSH2MCP_PERM_FILE` | `~/.ssh2mcp-perm` | hot-switch permission file |
| `SSH2MCP_MAX_OUTPUT` | 20000 | characters of stdout and stderr kept per call |
| `SSH2MCP_TIMEOUT_MS` | 120000 | default `run` timeout (maximum 3600000) |
| `SSH2MCP_SSH_BIN` | `ssh` | ssh binary |

## Local configuration

Values that describe a particular machine stay outside the repository. `restart.sh` sources
`~/.ssh2mcp.env` before starting the server:

```bash
SSH2MCP_SSH_HOST=myhost     # a Host alias from ~/.ssh/config
MCP_PORT=6222
```

Keep that file at mode 600. `check-public.sh` rejects commits that carry public IPv4
addresses, key material, GitHub tokens or personal mail addresses, and the pre-push hook runs
it automatically:

```bash
git config core.hooksPath hooks
```

## Command line

```
node index.js [--perm <level>] [--port N]
node index.js --self-test     # offline: risk table and ro allowlist assertions
node index.js --self-check    # connectivity, remote toolchain, tmp roundtrip, token and perm state
node index.js --help
```

`--self-test` exits non-zero on failure; `--self-check` answers "is the build machine ready"
in a single call.

### `s2m`

`~/ssh2mcp/s2m`, symlinked into `$PREFIX/local/bin` as `s2m` and as five-letter aliases. Every
subcommand goes through the MCP endpoint, so the permission level, the path jail and the risk
table apply to the CLI exactly as they apply to the agent; there is no second code path that
could bypass them.

| command | alias | does |
|---|---|---|
| `s2m st` | `s2mstl` | server state, effective perm, last log and audit line |
| `s2m start [--perm L]` | | (re)start detached |
| `s2m stop` | | stop |
| `s2m perm [L\|off]` | | show or hot-switch `ro`, `rw`, `full`, `selfcheck` |
| `s2m sh [--cwd D] [--timeout S] CMD` | `s2msh` | run remotely, exit code passes through |
| `s2m bg [--cwd D] CMD` | `s2mbg` | detached job, prints the id |
| `s2m log JOB [since]` | | job output from a byte offset |
| `s2m kill JOB` | | stop a job |
| `s2m jobs` | | list jobs on the host (`running`, `done:N`, `gone`) |
| `s2m pull REMOTE [LOCAL]` | `s2mpl` | host to device, default `~/incoming/` |
| `s2m push LOCAL REMOTE` | `s2mps` | device to host |
| `s2m cmp PATH [--local-root D] [--remote-root D]` | | both-sides compare |
| `s2m token [new]` | `s2mtk` | show the bearer token masked, or rotate it |
| `s2m audit [N]` | | tail the audit log |
| `s2m check` | `s2mck` | remote connectivity and toolchain |
| `s2m test [--full]` | | offline rules and smoke test, plus end-to-end |

## Audit log

Every call appends one JSON line to `~/.ssh2mcp/audit.log`: timestamp, tool, op, permission
level, matched rule ids, exit code and duration. Commands are stored as a sha256 prefix rather
than as text, so credentials on a command line do not land in the log. A permission change is
recorded as `perm-change` with the previous level.

## Known limits

- The risk table is a set of regular expressions over the command string. It catches the usual
  destructive shapes, not an obfuscated equivalent.
- `ro` cannot distinguish a read-only `git` invocation from a state-changing one beyond the
  subcommand allowlist.
- Stateless Streamable HTTP cannot stream text token by token; progress is delivered by
  polling `bg` with `log`.
- The `run` timeout is a hard cap on the host as well: a long build is killed mid-way if
  `timeout_s` stays at its 120 s default.
- One remote per instance (`SSH2MCP_SSH_HOST`). Several hosts need several instances on
  different ports.

## License

MIT. See [LICENSE](LICENSE).
