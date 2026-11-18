# conn3x-ui

A web UI for [Conn3x](https://conn3x.org). You point it at a Git repository with circuits in it, press Plan, and it shows you what would change on each host, step by step, while Conn3x is still working it out. Press Apply, and exactly that plan runs.

It's one binary. It runs the `conn3x` CLI as a child process for every run and reads the `-json` stream through [conn3x-exec](https://github.com/conn3xorg/conn3x-exec), so a run here and a run in your terminal can't drift apart, and each project pins its own Conn3x.

This is the second slice of the design in [conn3xorg/conn3x#525](https://github.com/conn3xorg/conn3x/issues/525). Expect it to change.

## Install

Each [release](https://github.com/conn3xorg/conn3x-ui/releases) has a binary for Linux, macOS and Windows on amd64 and arm64. Download the archive for your platform, unpack it, and put `conn3x-ui` on your PATH. It still needs `git` and a `conn3x` binary beside it.

To install it on a server, with `conn3x`, `git` and a systemd unit, apply [circuit-conn3x-ui](https://github.com/conn3xorg/circuit-conn3x-ui).

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

`./conn3x-ui version` prints the release you have.

## Run it

To build it yourself, you need Go 1.27, `git` on PATH, and a `conn3x` binary.

```sh
go build -o conn3x-ui .
./conn3x-ui serve -listen 127.0.0.1:8080 -data ./data
```

The first start creates an `admin` account and prints its password to the log, once. Sign in at <http://127.0.0.1:8080>, add a project, press Plan. Then make everyone else an account under [Users](#users-and-roles).

`-data` is where the SQLite database and each run's saved plan live. Back it up like any other file.

Credentials need a key. Without one the UI runs, but won't save or use them:

```sh
(umask 077; openssl rand -base64 32 > conn3x-ui.key)
./conn3x-ui serve -listen 127.0.0.1:8080 -data ./data -key-file conn3x-ui.key
```

Or put the same base64 in `CONN3X_UI_KEY` instead of `-key-file`; the flag wins when both are set. The UI takes the variable out of its environment once it's read, so no run inherits it. Keep the key apart from `-data`'s backups: one without the other opens nothing. Lose the key and the saved credentials are gone; set them again.

At start, the UI opens one saved credential with the key. If it won't open, the UI doesn't start, so a wrong key shows up now and not at the first run that needs it. Start without a key while credentials are saved and the log says how many, and that their projects' runs will fail until the key is back.

To move to a new key, stop the UI, then re-seal every credential under it:

```sh
(umask 077; openssl rand -base64 32 > conn3x-ui.key.new)
./conn3x-ui rotate-key -data ./data -old-key-file conn3x-ui.key -new-key-file conn3x-ui.key.new
mv conn3x-ui.key.new conn3x-ui.key
```

`CONN3X_UI_KEY` and `CONN3X_UI_NEW_KEY` work in place of the two flags. It's one transaction: if the old key doesn't open every credential, nothing changes. The audit log records the rotation with a count, never a key or a value. Start the UI with the new key; the old one opens nothing any more, but backups of `-data` made before the rotation still need it.

Listening on anything other than localhost? Put TLS in front. The session cookie is marked Secure off localhost, so plain http to another machine won't sign you in.

## A project

- **Git URL**: `https://`, `ssh://` or `git@host:repo`. The UI's host clones it for every run, shallowly, so it needs access without a prompt: a deploy key in `~/.ssh`, or one in the project's [credentials](#credentials). Don't put a token in the URL: it's stored as plain text, like the environment variables below.
- **Branch or tag** and a **path** inside the repository.
- **Conn3x binary**: a path, or `conn3x` for the one on PATH. Each project can pin a different one.
- **Environment variables**: `NAME=value` lines the run gets, such as `AWS_PROFILE`. Plain text in the database, so nothing secret: that goes in credentials.

Your configuration needs a remote state backend: S3, Azure Blob, GCS, `pg`, `http`, any of them. The UI holds no state, so losing the UI never loses state. A plan of a configuration with local state fails and says so. The check reads the backend Conn3x configured during `init`, so it works whichever file or module the backend block is in.

## Credentials

SSH keys, `become` passwords, cloud keys: each project keeps its own, under **Credentials** on its page. A credential has a name, a value, and how it reaches the run:

- **a file**: written to a private directory under `-data`'s `credentials` (`0700`, the file `0600`), with its path in `CONN3X_CRED_` plus the name in upper case. A file named `ssh_key` is at `$CONN3X_CRED_SSH_KEY`.
- **an environment variable**: the name is the variable, such as `AWS_SECRET_ACCESS_KEY`. It wins over an environment line with the same name.

Names are letters, digits and `_`, not starting with a digit, and unique in a project whatever their case. Saving a name that's there already replaces it.

Values are sealed with AES-256-GCM under the key, each bound to its project and name, so a value copied to another row won't open. Once saved, the page shows a credential's name, kind and when it was set, never its value. The directory is removed when the run ends, however it ends; if the UI itself dies mid-run, the next start removes what's left and logs how many. Nothing about a credential is stored with the run, and any value that turns up in a run's output or error is replaced with `<hidden>` before it's kept or shown.

Git gets the credentials too, so a project can bring its own deploy key: a file credential `git_key`, and a variable `GIT_SSH_COMMAND` set to `ssh -i "$CONN3X_CRED_GIT_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new`. For an https token, set git's own `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0` and `GIT_CONFIG_VALUE_0` variables, such as `http.extraHeader` and `Authorization: Bearer TOKEN`.

## What a plan does

1. Writes the project's credentials into a private directory under `-data`, then `git clone --depth 1 --branch REF URL` into another.
2. `conn3x init -input=false`, then `conn3x plan -input=false -out=plan.bin`, both with `-json`.
3. Every line of the stream goes to the database and to your browser as it arrives.
4. When it's done, the page groups the planned actions by host, then by `circuit.step`.
5. `plan.bin` is kept under `DATA/runs/ID/`, ready for Apply.

One run at a time per project; a second one waits its turn.

## What an apply does

A finished plan with changes gets an Apply button, as long as it's the project's newest plan, it hasn't been applied, and your [role](#users-and-roles) lets you apply it. Pressing it records who approved and when, then:

1. Clones the ref and moves to the commit the plan was made from, even if the branch has moved on since.
2. `conn3x init -input=false`, then `conn3x apply -input=false -report=report.json plan.bin` with the saved plan file. The stream goes through `-json-into`, since `-report` doesn't go with `-json`.
3. Streams the output as the plan did, and shows each host's steps with ok or failed and the seconds each took.

What was approved is what runs. If the state changed since the plan, Conn3x refuses the stale plan and the run fails with its error. A plan applies once; a newer plan in the project retires the older ones.

**Cancel** on a running plan or apply sends Conn3x an interrupt, as Ctrl-C would, so it stops after the current step and releases its state lock. The run ends as `cancelled`.

The report is kept beside the plan, under `DATA/runs/ID/`, and the apply's page has a link to download it.

## History

**Runs** at the top lists every run across projects, newest first: who started it, when, the commit, the Conn3x version and how it ended. Filter by project, host and outcome. Each run's page shows who started and who approved it, and each host's steps with how it came out there.

## Drift checks

Somebody fixed a host by hand at 2am, and the state doesn't know. A drift check finds out for you. Give a project a **drift check schedule** in its settings:

- an interval, such as `1h`, `6h` or `24h`, or
- five cron fields in UTC, minute hour day month weekday, such as `0 3 * * 1-5` for 03:00 on weekdays. Each field takes `*`, numbers, ranges like `1-5`, lists like `1,15`, and steps like `*/15`.

When a check is due, the UI queues it like any other run, so one run at a time per project still holds. A check clones the ref, runs `conn3x init -input=false`, then `conn3x plan -refresh-only -detailed-exitcode -input=false` with `-json`. Nothing is planned or applied. Exit 2 means a host no longer matches the state, and the run ends `drift`; exit 0 ends it `clean`. Both show in **Runs**, where the outcome filter takes `drift` and `clean`, and the host filter finds the hosts that drifted.

Set a **splay** to start each check up to that many minutes after it's due, a different delay each time, so fifty projects on `0 * * * *` don't all clone and plan at once.

Want to know now? **Check drift now** on the project page runs a check straight away, for anyone who can plan. It only looks: even in a project set to correct or converge, a check you start yourself never plans or applies.

When is a check due? One interval, or the next cron slot, after the last check started. That survives a restart: a UI that was down past a slot runs the check once when it starts, not once for every slot it missed. A project's first check comes one slot after the schedule was saved.

### Putting drift back

A check can do more than report. **When a check finds drift**, in a project's settings, has three choices:

| Choice | What happens after a check finds drift |
| --- | --- |
| **Report it** (the default) | Nothing more. The check's run says what drifted. |
| **Correct it** | The UI plans, and applies that plan only when every change in it is an in-place update of something the same plan saw drift. |
| **Converge** | The UI plans, and applies any plan with no delete or replace in it, the way an agent that keeps hosts converged would. |

Whichever you pick, the plan is the same plan-then-apply-that-plan a person runs, and it shows in **Runs** as started, and approved, by the schedule. Some plans always wait for a person, in either mode:

- **A delete or a replace.** The schedule never removes anything.
- **More changes than the limit.** Set **Most changes a schedule may apply** and a plan over it waits. Forty hosts drifting at once is more likely a mistake upstream than forty broken servers.
- **When correcting, anything that isn't putting back drift.** A create, or an update to something that didn't drift, means the configuration changed, and that's for a person to approve.

A plan that waits is an ordinary plan: an approver can apply it from its run page. `confirm_after` steps work as they do by hand, so a scheduled firewall change that locks Conn3x out still undoes itself.

Only a site admin can pick **Correct** or **Converge**, or change the limit. Either lets the schedule change hosts with nobody approving, so anyone who can push to the project's repository can then change its hosts without review.

Add a **drift webhook** to hear about it. When a check finds drift, or fails, the UI POSTs this, with a 10-second timeout:

```json
{
  "project": "web",
  "run_id": 42,
  "status": "succeeded",
  "outcome": "drift",
  "link": "/runs/42",
  "hosts": ["web1"],
  "time": "2026-11-16T03:00:41Z",
  "text": "Conn3x: web drifted on web1 (run 42)"
}
```

`link` is the run's path on the UI. Start the UI with `-public-url https://conn3x.example.com` and the payload also has `url`, the full address, and `text` ends with it. `text` is a one-line summary, for chat webhooks that read a `text` field. A failed check has `"status": "failed"` and an empty `outcome`. If the webhook fails, the log says so and the run stands as it ended.

When a check corrects or converges, the webhook hears twice: once for the drift, and once for what came of it. A plan that waits has `"outcome": "waiting"`, its `run_id` is the plan's, and `text` says why it waits. An apply the schedule made has `"outcome": "corrected"` when it succeeds, or its `status` when it doesn't. A plan that found nothing to change sends nothing more.

The URL must be `http://` or `https://`. Webhook URLs often carry a token, so once saved the page shows only the host, and the log never prints it. Leave the field blank to keep the saved one, or tick **Remove the webhook**.

Rather have an email? Give the project **Drift email** addresses, comma-separated, and they get one every time the webhook would get a POST, whether or not there's a webhook. The subject is the payload's `text`, and the body adds the hosts and the run's link. Start the UI with a mail server for it:

```sh
CONN3X_UI_SMTP_PASSWORD=... ./conn3x-ui serve -smtp-addr smtp.example.com:587 -smtp-from conn3x@example.com -smtp-user conn3x
```

The UI only sends mail over STARTTLS, except to a server on loopback, such as a local relay. `-smtp-password-file` takes the password from a file instead, and the UI takes the variable out of its environment once it's read. A mail that can't be sent is logged, and the run stands as it ended.

## Runs started by events

A disk fills up at 3am. Alertmanager knows; the UI doesn't. An **event rule** closes that gap: when an alert or a signed webhook arrives, it starts a drift check of its project, and the check can report, correct or converge as a schedule's does, under the same guards.

A site admin adds rules under **Event rules** on the project page. A rule has:

- a **name**,
- an **alertname** and **labels**, `LABEL=VALUE` lines, that a firing Alertmanager alert must all have. Leave both empty and any request signed with the rule's secret starts a run,
- what the run does about drift: **reports it**, **corrects it** or **converges**,
- a **debounce**, 1 to 1440 minutes. After the rule starts a run, events in that time are folded into it, so a flood of alerts is one run.

Saving a rule shows its URL, `/hooks/<id>`, and a secret, once. The secret is sealed with the credentials key like a credential, so rules need the key too, and `rotate-key` re-seals them.

Point Alertmanager at the URL with the secret as a bearer token:

```yaml
receivers:
  - name: conn3x
    webhook_configs:
      - url: https://conn3x.example.com/hooks/3
        http_config:
          authorization:
            credentials_file: /etc/alertmanager/conn3x-hook-3
```

Anything else signs each request. Send `X-Conn3x-Timestamp`, the time in Unix seconds, a unique `X-Conn3x-Delivery` of up to 128 letters, digits, `-` and `_`, and `X-Conn3x-Signature: sha256=` followed by the hex HMAC-SHA256 of the timestamp, a dot, the delivery ID, a dot and the body, keyed with the secret:

```sh
ts=$(date +%s); id=$(uuidgen); body='{"reason":"deploy finished"}'
sig=$(printf '%s.%s.%s' "$ts" "$id" "$body" | openssl dgst -sha256 -hmac "$SECRET" -hex | cut -d' ' -f2)
curl -X POST https://conn3x.example.com/hooks/3 -H "X-Conn3x-Timestamp: $ts" \
  -H "X-Conn3x-Delivery: $id" -H "X-Conn3x-Signature: sha256=$sig" -d "$body"
```

A timestamp more than five minutes off, a delivery ID the rule has seen, a wrong secret and a rule that doesn't exist are all refused, the last two alike. The answer is JSON: `"started"` with the run's ID, `"folded"` inside the debounce, or `"no match"`. Bodies are capped at 1 MiB.

The run shows in **Runs** as started by its rule, with the event that started it on its run page, and so do the plan and apply that follow when the rule corrects or converges. The audit log records each rule added and deleted, and each run a rule started.

Not yet: taking variables or the hosts to run on from the event, and keeping parts of an event out of the run page.

## The fleet store

"Which hosts run Rocky Linux 10?" and "what changed on db3 last Tuesday?" shouldn't mean reading run logs. The UI keeps the answers as runs finish:

- **Step results.** Every step an apply ran on every host, with its outcome and how long it took, and every step a drift check or plan found drifted.
- **Facts.** The latest of what each project's `conn3x_host`, `conn3x_packages` and `conn3x_services` data sources read about each host, from every plan and drift check. How a fact was read, such as the `ssh` block, isn't kept, and neither is anything the plan marks sensitive.

Ask it over a read-only JSON API, as yourself; you see only the projects you can view. For a script, make an **API token** on your **Account** page: name it, give it 1 to 365 days, and copy it, since it's shown once. Send it as a bearer token:

```sh
H="Authorization: Bearer $CONN3X_UI_TOKEN"
# Hosts that run Rocky Linux and have openssl installed
curl -H "$H" 'https://conn3x.example.com/api/v1/hosts?fact=os_id:rocky&fact=packages:openssl'
# What was applied to db3, or drifted there, since Tuesday
curl -H "$H" 'https://conn3x.example.com/api/v1/hosts/db3/changes?since=2026-11-10'
# Steps of the hardening circuit that failed
curl -H "$H" 'https://conn3x.example.com/api/v1/steps?circuit=hardening&outcome=failed'
```

A token reads `/api/` and nothing else, and only with GET. It has your roles, so when they change, so does what it sees. Disable a user and their tokens stop working with their sign-in. A new password, whether an admin resets it or the user changes it, revokes all their tokens too, so resetting a taken-over account closes every way in. For an OIDC user, a token keeps working after they're removed at the identity provider, until it expires or you disable them here: the UI only asks the provider at sign-in. The UI keeps only each token's SHA-256 hash, and the Account page shows when each was last used. Tokens start `c3ui_`, so a secret scanner can spot one in a commit. Making and revoking one go in the audit log.

A `fact=name:value` matches a fact's value, or one key of a map, which is how `packages:openssl` finds a package. Results come newest first, at most 1,000 at a time, with `"truncated": true` when there are more. Step results are kept for 90 days, `-fleet-retention` to change it; the latest facts per host are kept for good.

The facts are what the circuits read: for a package list, the project's circuit needs a `data "conn3x_packages"` with `for_each` over its hosts.

## Trust model

Every run executes a project's circuit on this server. A circuit can run commands on the machine that plans it, for example through an `external` data source, so what those commands can reach matters.

**On Linux, each run is sandboxed with [Landlock](https://landlock.io).** conn3x, and everything it starts, can write only in the run's own temporary directory, which holds its checkout, and read only the system's programs and libraries, the parts of `/etc` that name hosts, users, certificates and time zones, that run's credential files, and `~/.ssh` and the Terraform CLI settings in the home directory. The UI's database, its credentials key, saved plans and other runs are out of reach, as is signalling the UI itself. Network access is unchanged, so runs reach hosts and cloud APIs as before. It needs a kernel with Landlock turned on, 5.13 or later. The container image has been tested with it under Podman's default seccomp profile.

`-sandbox` picks the mode. `auto`, the default, sandboxes runs when the kernel can and says at start which it is. `on` refuses to start without it, and `off` turns it off. A project that sets `TF_PLUGIN_CACHE_DIR` gets write access to that directory too.

Without the sandbox (`-sandbox=off`, macOS, or an older kernel), a run executes as the user the UI runs as, can read the UI's database and its credentials key, and so:

- **Anyone who can push to a project's repository can run commands here**, and through them read every project's credentials, not only that project's. It's the same with other tools that plan infrastructure code from Git. Give push access only to people you'd trust with this server.

Either way:

- **Only a site admin can change what a run executes:** a project's Git URL, its Conn3x binary and its environment variables. A project admin can't, and the form shows them read-only.
- **Only a site admin can add or delete an event rule.** A rule lets whoever holds its secret start runs of its project, and correct or converge with nobody approving. `/hooks/` is the one path that takes no session, so put the UI behind TLS before you give a rule's URL to anything.
- **No credential can be named for a variable that changes how a run's programs start**, such as `PATH`, `LD_PRELOAD`, `GIT_SSH_COMMAND` or anything starting `TF_` or `CONN3X_`. They're refused when a credential is saved and again when a run starts.
- **A run can still read what the system lets anyone read**, such as `/etc`, and use the network as this server can. Keep cloud metadata endpoints and internal services behind their own auth, as for any CI runner.

Roles keep people from seeing or changing projects they have no part in. With the sandbox, one project's run can't read another's credentials either.

## Users and roles

Everyone signs in with their own account. A site admin makes them under **Users**: a name, and a password you type or leave blank for a generated one, shown once. Pass it on, and they can change it under their name at the top. From the same page a site admin resets a password or disables an account. Either one signs that person out everywhere, and a disabled account can't sign in. Nobody can disable themselves or drop their own admin, so the last admin can't lock everyone out.

Nobody sees a project until they have a role on it. A project admin gives roles under **Roles** on the project's page. Each role can do what the one above it can, and more:

| Role | Can |
| --- | --- |
| viewer | See the project, its runs, their output and reports, and the history |
| planner | Start a plan, and cancel a plan or drift check |
| approver | Apply a plan someone else made, and cancel an apply |
| admin | Edit and delete the project, its credentials, its drift schedule and its roles, and apply any plan, their own included |

A **site admin** is admin on every project, creates projects, manages users and reads the audit log.

Four eyes on every apply, then: a plan made by a planner needs an approver or an admin to apply it, and an approver can't apply their own. Tick **Planners may apply their own plans** in a project's settings and planners and approvers can. An admin may always apply their own, so a lab with one admin still works.

The server checks the role on every page and button, not just the browser. A button you can't use isn't shown, and posting it anyway gets a 403 that says which role you'd need.

## Single sign-on with OIDC

Rather your people signed in with the accounts they already have? Point the UI at one OpenID Connect provider:

```sh
(umask 077; printf '%s' 'CLIENT_SECRET' > oidc-secret)
./conn3x-ui serve -listen 127.0.0.1:8080 -data ./data \
  -oidc-issuer https://sso.example.com/realms/ops \
  -oidc-client-id conn3x-ui \
  -oidc-client-secret-file oidc-secret \
  -oidc-redirect-url https://conn3x.example.com/login/oidc/callback
```

The sign-in page gets a **Sign in with single sign-on** button. The UI reads the provider's `/.well-known/openid-configuration` when it starts, so the provider has to be up then.

- `-oidc-redirect-url` is this UI's address plus `/login/oidc/callback`. Register exactly that with the provider.
- The client secret comes from `-oidc-client-secret-file`, or from `CONN3X_UI_OIDC_CLIENT_SECRET`, which the UI takes out of its environment once read, as it does the key. A public client, with no secret, works too: every sign-in uses PKCE.
- The UI asks for the scopes `openid email profile`.
- `-oidc-email-domain example.com` lets in only people whose email is in that domain and marked verified by the provider.

Each sign-in uses the authorization code flow with PKCE (S256), a `state` and a `nonce`, carried to the callback in a signed, HttpOnly cookie that lasts 10 minutes. The ID token's signature is checked against the provider's published keys, along with its issuer, audience, expiry and nonce. The UI keeps no token, and logs none.

The first time someone signs in, the UI makes them a user, named from their `preferred_username` or email, with no roles and no site admin. A site admin gives them roles as for anyone else; the user list marks them **OIDC**. The user is tied to the provider's issuer and subject, never their email or name, so a new account with an old colleague's email is a new user. If the name is taken, a short hash goes on the end.

### Keycloak

In your realm, create a client:

1. **Client ID** `conn3x-ui`, **Client authentication** on, **Standard flow** only.
2. **Valid redirect URIs**: `https://conn3x.example.com/login/oidc/callback`.
3. Copy the secret from **Credentials**.

The issuer is `https://KEYCLOAK/realms/REALM`. Set the client's **PKCE Method** to `S256` and Keycloak refuses any sign-in to it without PKCE.

### Entra ID

Under **App registrations**, register an app:

1. **Supported account types**: this organizational directory only.
2. **Redirect URI**: platform **Web**, `https://conn3x.example.com/login/oidc/callback`.
3. Under **Certificates & secrets**, make a client secret and copy its value.

The issuer is `https://login.microsoftonline.com/TENANT_ID/v2.0` and the client ID is the app's **Application (client) ID**. A single-tenant app already keeps out anyone outside your directory, and Entra doesn't say whether an email is verified, so leave `-oidc-email-domain` off.

### Roles from groups

Let your provider's groups decide who can do what, so joining or leaving a team in one place is enough:

```sh
./conn3x-ui serve ... \
  -oidc-admin-group conn3x-admins \
  -oidc-role 'platform=web:approver' \
  -oidc-role 'developers=web:planner' \
  -oidc-role 'developers=db:viewer'
```

`-oidc-admin-group` makes its members site admins. Each `-oidc-role GROUP=PROJECT:ROLE` gives the group's members that role on the project, by the project's name; a project that doesn't exist yet is skipped until it does. Both are checked at every OIDC sign-in, so somebody who leaves a group loses what it gave them the next time they sign in, not before.

- **The highest role wins.** In `platform` and `developers`, you're an approver on `web`.
- **A role set by hand stays yours.** Groups never change or remove a role an admin gave under the project's roles, and giving someone a role by hand takes it over from their groups. The project page marks the ones that came from groups.
- **The last site admin stays one.** If leaving the admin group would leave nobody who can sign in as a site admin, the UI keeps them one and says so in the audit log.

The groups come from the ID token's `groups` claim; `-oidc-groups-claim` names another. Your provider has to put it there. In Keycloak, add a **Group Membership** mapper to the client with the token claim name `groups`, and turn **Full group path** off so the names match. Entra ID puts group object IDs in the claim once you add a groups claim under **Token configuration**, so use those IDs as the group names. Every change a sign-in makes is in the audit log.

### Turning off passwords

Once single sign-on works, you can turn off password sign-in with `-no-password-sign-in`. It won't lock you out: the UI refuses to start with it until a site admin who isn't disabled signs in with OIDC. So sign in with OIDC once, make that user a site admin under **Users** while signed in as `admin`, then restart with the flag. Starting with it signs out every session that was opened with a password, and the audit log says how many. From then on every admin signs in with OIDC, and nobody can drop their own admin, so one is always left.

## Audit log

Who did what, and when. **Audit**, for site admins, lists it newest first, 50 to a page, filtered by user and project. It records:

- sign-in, sign-out, and failed sign-ins, with why: a wrong password, a disabled account, or a name nobody has. That last one doesn't keep the name, in case it was a password typed in the wrong box.
- sign-ins with OIDC and the issuer, and failed ones with why, such as a state or nonce that doesn't match or an expired ID token. Never a code or a token.
- users created, by an admin or at a first OIDC sign-in, passwords reset or changed, site admin and disabled changes, and roles given or taken away.
- projects created, edited and deleted; drift schedule changes, and webhook changes by host only.
- credentials set or deleted, by name, and the key rotated, by count.
- plans, applies and cancels, with the run, drift checks somebody started, and schedule mode changes.
- downloads of the log itself.

No password or credential value is ever in it. An entry keeps the user's and project's names as they were, so it still reads right after either is gone. The table is append-only: the database refuses to change or delete an entry.

To keep it somewhere else, such as a SIEM, download it from the page: **JSON lines** or **CSV**, every entry the filters match, oldest first. `GET /audit/export?format=jsonl&after=ID` returns only what's newer than entry `ID`, so a job can pull what's new each night. In the CSV, a cell that starts with `=`, `+`, `-` or `@` gets a `'` in front, so a spreadsheet doesn't run a name or detail as a formula.

## Not here yet

The rest of the design, in the order it's planned:

- More than one sign-in provider (GitHub, which isn't OIDC, among them): [#892](https://github.com/conn3xorg/conn3x/issues/892). Local accounts, OIDC sign-in, roles per person and per OIDC group, and the audit log and its export are in.
- apt, dnf, Homebrew and Scoop packages: [#894](https://github.com/conn3xorg/conn3x/issues/894). Release binaries, the image and a circuit are in.

Credentials are in, with the key from a file or a variable, a key check at start, and rotation; a KMS for the key (AWS KMS, Azure Key Vault, Google Cloud KMS) comes later, under [#920](https://github.com/conn3xorg/conn3x/issues/920).

Until then, treat it as a lab tool: runs on the UI's own host.

## Developing

```sh
go vet ./... && test -z "$(gofmt -l .)" && go test -race ./...
```

The tests use the test binary as a fake `conn3x` and serve a bare Git repository over HTTP, so they need only Go and `git`. Set `CONN3X_BIN` to a real `conn3x` to also plan and apply a real configuration against an in-memory `http` backend.

## License

[MPL-2.0](LICENSE), like Conn3x.
