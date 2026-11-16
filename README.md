# conn3x-ui

A web UI for [Conn3x](https://conn3x.org). You point it at a Git repository with circuits in it, press Plan, and it shows you what would change on each host, step by step, while Conn3x is still working it out. Press Apply, and exactly that plan runs.

It's one binary. It runs the `conn3x` CLI as a child process for every run and reads the `-json` stream through [conn3x-exec](https://github.com/conn3xorg/conn3x-exec), so a run here and a run in your terminal can't drift apart, and each project pins its own Conn3x.

This is the second slice of the design in [conn3xorg/conn3x#525](https://github.com/conn3xorg/conn3x/issues/525). Expect it to change.

## Install

Each [release](https://github.com/conn3xorg/conn3x-ui/releases) has a binary for Linux, macOS and Windows on amd64 and arm64. Download the archive for your platform, unpack it, and put `conn3x-ui` on your PATH. It still needs `git` and a `conn3x` binary beside it.

Or run the container image, which has both, plus an ssh client for `git@` URLs:

```sh
docker run -d --name conn3x-ui -v ui-data:/data -p 127.0.0.1:8080:8080 \
  ghcr.io/conn3xorg/conn3x-ui:vX.Y.Z serve -listen 0.0.0.0:8080 -data /data
docker logs conn3x-ui   # the admin password
```

`-listen 0.0.0.0:8080` is inside the container; `-p 127.0.0.1:8080:8080` keeps it on your machine. Publish it wider only with TLS in front, as [below](#run-it). The image runs as UID 65532, so a named volume just works; a host directory for `/data` must be writable by that UID. Add the key with `-e CONN3X_UI_KEY` or a mounted `-key-file`.

The image carries the `conn3x` that was current when it was built. Want a project on a different one? Mount that binary into the container and give the project its path.

### Verify a download

`checksums.txt` is signed with [Sigstore](https://www.sigstore.dev/), keyless, by the release workflow. Check the signature, then the file you downloaded:

```sh
cosign verify-blob \
  --certificate-identity 'https://github.com/conn3xorg/conn3x-ui/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

And the image:

```sh
cosign verify ghcr.io/conn3xorg/conn3x-ui:vX.Y.Z \
  --certificate-identity 'https://github.com/conn3xorg/conn3x-ui/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each release also has SBOMs and a build provenance attestation: `gh attestation verify conn3x-ui_VERSION_linux_amd64.tar.gz --repo conn3xorg/conn3x-ui`.

## Run it

To build it yourself, you need Go 1.27, `git` on PATH, and a `conn3x` binary.

```sh
go build -o conn3x-ui .
./conn3x-ui serve -listen 127.0.0.1:8080 -data ./data
```

The first start creates an `admin` account and prints its password to the log, once. Sign in at <http://127.0.0.1:8080>, add a project, press Plan.

`-data` is where the SQLite database and each run's saved plan live. Back it up like any other file.

Credentials need a key. Without one the UI runs, but won't save or use them:

```sh
(umask 077; openssl rand -base64 32 > conn3x-ui.key)
./conn3x-ui serve -listen 127.0.0.1:8080 -data ./data -key-file conn3x-ui.key
```

Or put the same base64 in `CONN3X_UI_KEY` instead of `-key-file`; the flag wins when both are set. The UI takes the variable out of its environment once it's read, so no run inherits it. Keep the key apart from `-data`'s backups: one without the other opens nothing. Lose the key and the saved credentials are gone; set them again.

Listening on anything other than localhost? Put TLS in front. The session cookie is marked Secure off localhost, so plain http to another machine won't sign you in.

## A project

- **Git URL**: `https://`, `ssh://` or `git@host:repo`. The UI's host clones it for every run, shallowly, so it needs access without a prompt: a deploy key in `~/.ssh`, or one in the project's [credentials](#credentials). Don't put a token in the URL: it's stored as plain text, like the environment variables below.
- **Branch or tag** and a **path** inside the repository.
- **Conn3x binary**: a path, or `conn3x` for the one on PATH. Each project can pin a different one.
- **Environment variables**: `NAME=value` lines the run gets, such as `AWS_PROFILE`. Plain text in the database, so nothing secret: that goes in credentials.

Your configuration needs a remote state backend: S3, Azure Blob, GCS, `pg`, `http`, any of them. The UI holds no state, so losing the UI never loses state. A plan of a configuration with local state fails and says so. The check reads the backend Conn3x configured during `init`, so it works whichever file or module the backend block is in.

## Credentials

SSH keys, `become` passwords, cloud keys: each project keeps its own, under **Credentials** on its page. A credential has a name, a value, and how it reaches the run:

- **a file**: written to a private temp directory (`0700`, the file `0600`), with its path in `CONN3X_CRED_` plus the name in upper case. A file named `ssh_key` is at `$CONN3X_CRED_SSH_KEY`.
- **an environment variable**: the name is the variable, such as `AWS_SECRET_ACCESS_KEY`. It wins over an environment line with the same name.

Names are letters, digits and `_`, not starting with a digit, and unique in a project whatever their case. Saving a name that's there already replaces it.

Values are sealed with AES-256-GCM under the key, each bound to its project and name, so a value copied to another row won't open. Once saved, the page shows a credential's name, kind and when it was set, never its value. The temp directory is removed when the run ends, however it ends. Nothing about a credential is stored with the run, and any value that turns up in a run's output or error is replaced with `<hidden>` before it's kept or shown.

Git gets the credentials too, so a project can bring its own deploy key: a file credential `git_key`, and a variable `GIT_SSH_COMMAND` set to `ssh -i "$CONN3X_CRED_GIT_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new`. For an https token, set git's own `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0` and `GIT_CONFIG_VALUE_0` variables, such as `http.extraHeader` and `Authorization: Bearer TOKEN`.

## What a plan does

1. Writes the project's credentials into a private temp directory, then `git clone --depth 1 --branch REF URL` into another.
2. `conn3x init -input=false`, then `conn3x plan -input=false -out=plan.bin`, both with `-json`.
3. Every line of the stream goes to the database and to your browser as it arrives.
4. When it's done, the page groups the planned actions by host, then by `circuit.step`.
5. `plan.bin` is kept under `DATA/runs/ID/`, ready for Apply.

One run at a time per project; a second one waits its turn.

## What an apply does

A finished plan with changes gets an Apply button, as long as it's the project's newest plan and hasn't been applied. Pressing it records who approved and when, then:

1. Clones the ref and moves to the commit the plan was made from, even if the branch has moved on since.
2. `conn3x init -input=false`, then `conn3x apply -input=false -report=report.json plan.bin` with the saved plan file. The stream goes through `-json-into`, since `-report` doesn't go with `-json`.
3. Streams the output as the plan did, and shows each host's steps with ok or failed and the seconds each took.

What was approved is what runs. If the state changed since the plan, Conn3x refuses the stale plan and the run fails with its error. A plan applies once; a newer plan in the project retires the older ones.

**Cancel** on a running plan or apply sends Conn3x an interrupt, as Ctrl-C would, so it stops after the current step and releases its state lock. The run ends as `cancelled`.

The report is kept beside the plan, under `DATA/runs/ID/`, and the apply's page has a link to download it.

## History

**Runs** at the top lists every run across projects, newest first: who started it, when, the commit, the Conn3x version and how it ended. Filter by project, host and outcome. Each run's page shows who started and who approved it, and each host's steps with how it came out there.

## Not here yet

The rest of the design, in the order it's planned:

- OIDC sign-in, roles and an audit log: [#892](https://github.com/conn3xorg/conn3x/issues/892). Until then the one admin may apply any plan; the approver role and the "planners may apply their own plan" setting come with the roles.
- Scheduled drift checks: [#893](https://github.com/conn3xorg/conn3x/issues/893)
- apt, dnf, Homebrew and Scoop packages, and a circuit that installs it: [#894](https://github.com/conn3xorg/conn3x/issues/894). Release binaries and the image are in.

Credentials are in, with the key from a file or a variable; a KMS for the key comes later, also under [#891](https://github.com/conn3xorg/conn3x/issues/891).

Until then, treat it as a lab tool: one admin, runs on the UI's own host.

## Developing

```sh
go vet ./... && test -z "$(gofmt -l .)" && go test -race ./...
```

The tests use the test binary as a fake `conn3x` and serve a bare Git repository over HTTP, so they need only Go and `git`. Set `CONN3X_BIN` to a real `conn3x` to also plan and apply a real configuration against an in-memory `http` backend.

## License

[MPL-2.0](LICENSE), like Conn3x.
