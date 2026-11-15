# conn3x-ui

A web UI for [Conn3x](https://conn3x.org). You point it at a Git repository with circuits in it, press Plan, and it shows you what would change on each host, step by step, while Conn3x is still working it out. Press Apply, and exactly that plan runs.

It's one binary. It runs the `conn3x` CLI as a child process for every run and reads the `-json` stream through [conn3x-exec](https://github.com/conn3xorg/conn3x-exec), so a run here and a run in your terminal can't drift apart, and each project pins its own Conn3x.

This is the second slice of the design in [conn3xorg/conn3x#525](https://github.com/conn3xorg/conn3x/issues/525). Expect it to change.

## Run it

You need Go 1.27, `git` on PATH, and a `conn3x` binary.

```sh
go build -o conn3x-ui .
./conn3x-ui serve -listen 127.0.0.1:8080 -data ./data
```

The first start creates an `admin` account and prints its password to the log, once. Sign in at <http://127.0.0.1:8080>, add a project, press Plan.

`-data` is where the SQLite database and each run's saved plan live. Back it up like any other file.

Listening on anything other than localhost? Put TLS in front. The session cookie is marked Secure off localhost, so plain http to another machine won't sign you in.

## A project

- **Git URL**: `https://`, `ssh://` or `git@host:repo`. The UI's host clones it for every run, shallowly, so it needs access without a prompt: a deploy key in `~/.ssh` for now. Don't put a token in the URL: it's stored as plain text, like the environment variables below. Tokens come with credentials ([#891](https://github.com/conn3xorg/conn3x/issues/891)).
- **Branch or tag** and a **path** inside the repository.
- **Conn3x binary**: a path, or `conn3x` for the one on PATH. Each project can pin a different one.
- **Environment variables**: `NAME=value` lines the run gets, such as `AWS_PROFILE`. Plain text in the database for now; see below.

Your configuration needs a remote state backend: S3, Azure Blob, GCS, `pg`, `http`, any of them. The UI holds no state, so losing the UI never loses state. A plan of a configuration with local state fails and says so. The check reads the backend Conn3x configured during `init`, so it works whichever file or module the backend block is in.

## What a plan does

1. `git clone --depth 1 --branch REF URL` into a fresh temp directory.
2. `conn3x init -input=false`, then `conn3x plan -input=false -out=plan.bin`, both with `-json`.
3. Every line of the stream goes to the database and to your browser as it arrives.
4. When it's done, the page groups the planned actions by host, then by `circuit.step`.
5. `plan.bin` is kept under `DATA/runs/ID/`, ready for Apply.

One run at a time per project; a second one waits its turn.

## What an apply does

A finished plan with changes gets an Apply button, as long as it's the project's newest plan and hasn't been applied. Pressing it records who approved and when, then:

1. Clones the ref and moves to the commit the plan was made from, even if the branch has moved on since.
2. `conn3x init -input=false`, then `conn3x apply -input=false plan.bin` with the saved plan file.
3. Streams the output as the plan did, and shows each host's steps with ok or failed and the seconds each took.

What was approved is what runs. If the state changed since the plan, Conn3x refuses the stale plan and the run fails with its error. A plan applies once; a newer plan in the project retires the older ones.

**Cancel** on a running plan or apply sends Conn3x an interrupt, as Ctrl-C would, so it stops after the current step and releases its state lock. The run ends as `cancelled`.

The apply's `-report` file isn't kept: `conn3x apply -report` doesn't go with `-json`, and the stream carries the same information.

## Not here yet

The rest of the design, in the order it's planned:

- History with each run's plan, output and report: [#890](https://github.com/conn3xorg/conn3x/issues/890)
- Encrypted credentials, SSH keys and `become` passwords: [#891](https://github.com/conn3xorg/conn3x/issues/891)
- OIDC sign-in, roles and an audit log: [#892](https://github.com/conn3xorg/conn3x/issues/892). Until then the one admin may apply any plan; the approver role and the "planners may apply their own plan" setting come with the roles.
- Scheduled drift checks: [#893](https://github.com/conn3xorg/conn3x/issues/893)
- Releases, a container image and a circuit that installs it: [#894](https://github.com/conn3xorg/conn3x/issues/894)

Until then, treat it as a lab tool: one admin, plain-text environment variables, runs on the UI's own host.

## Developing

```sh
go vet ./... && test -z "$(gofmt -l .)" && go test -race ./...
```

The tests use the test binary as a fake `conn3x` and serve a bare Git repository over HTTP, so they need only Go and `git`. Set `CONN3X_BIN` to a real `conn3x` to also plan and apply a real configuration against an in-memory `http` backend.

## License

[MPL-2.0](LICENSE), like Conn3x.
