#!/usr/bin/env bash
# Runs the sandbox / proxy / live test selection as an UNPRIVILEGED user, because root hides bugs that GitHub's runner shows (a test once
# depended on network-namespace support only root has). Opt-in: nothing in the default gate tiers calls it (CI already runs non-root).
#
#   sudo bash scripts/run_nonroot.sh [extra pytest args]          (as root: creates the user, makes a private copy, runs pytest there)
#   GATE_AS_USER=1 bash scripts/verify.sh                         (the same, as one extra stage of whatever tier you run; docs/TESTING_REALITY.md)
#   sudo NONROOT_CLEAN=1 bash scripts/run_nonroot.sh              (removes what this script made: the user with its home, and the work directory)
#
# It runs:  python -m pytest tests/proxy tests/server tests/live -m 'not research' -n 4 [extra args]
# (-m 'not research' replaces pytest.ini's marker filter on purpose: the `reality` live tests are included.)
#
# Run as root, so its reach is deliberately small:
#   * WORK (NONROOT_DIR, default /var/tmp/sentinel-nonroot-<user>) is the ONLY place it writes. It must be absent (the script creates it, mode 755), empty,
#     or carry the marker file this script wrote; a symlink, a directory owned by someone else or writable by others, a system directory (/, /tmp, /mnt,
#     /opt, /home, ...) and the repository itself are refused. Inside WORK: repo/ (the copy) and tmp/ (the test run's TMPDIR), both owned by the user.
#   * the user NONROOT_USER (default sentinel-nonroot) is created with `useradd -m` and a marker in its GECOS field; an existing account without that
#     marker, or with uid < 1000, is refused. No password.
#   * the copy leaves out .git, frontend/node_modules, caches, and every credential-looking file (.env, .env.*, *.pem, *.key, id_*, .netrc,
#     credentials*; .env.example is put back); .realdeps/tv has the repo path rewritten (a venv records the path it was made at).
#   * the root user's Hugging Face model cache is copied once into the user's home (the real MiniLM tests would otherwise skip) unless NONROOT_HF=0.
#   * pytest runs through `runuser` with an EMPTY environment: PATH, HOME, TMPDIR, LANG, HF_*, OMP_NUM_THREADS and, when it is exactly 1 in your
#     environment, SENTINEL_SANDBOX_REQUIRED (a missing sandbox is then a failure, not a skip). Your tokens and API keys never reach it.
# NONROOT_CLEAN=1: `userdel -r` the script-made user (its home, with the model copy, goes too) and `rm -rf` WORK, only if each carries the marker.
# Already non-root: runs pytest straight in this checkout. NONROOT_WORKERS (default 4) is pytest-xdist's -n. NONROOT_COPY=rsync|tar picks the copy
# tool. NONROOT_DRY_RUN=1 prints the plan (every state-changing step as a "plan:" line) and changes nothing. The exit code is pytest's.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
U="${NONROOT_USER:-sentinel-nonroot}"
WORK_RAW="${NONROOT_DIR:-/var/tmp/sentinel-nonroot-$U}"
N="${NONROOT_WORKERS:-4}"
DRY="${NONROOT_DRY_RUN:-0}"
MARKER_FILE=.sentinel-run-nonroot
MARKER_TEXT="sentinel run_nonroot.sh"
refuse() { echo "run_nonroot: refusing: $*" >&2; exit 2; }
do_() { if [ "$DRY" = 1 ]; then echo "plan: $*"; else "$@"; fi; }

[[ "$U" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || refuse "NONROOT_USER '$U' is not a plain user name"
[ "$U" != root ] || refuse "NONROOT_USER is root"
IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1

# --- the account: an existing one must be one this script made
ACCOUNT=new
if getent passwd "$U" >/dev/null; then
  ACCOUNT=existing
  IFS=: read -r _ _ UID_U _ GECOS _ < <(getent passwd "$U")
  [ "$UID_U" -ge 1000 ] || refuse "account $U (uid $UID_U) is a system account"
  [ "$GECOS" = "$MARKER_TEXT" ] || refuse "account $U exists and was not created by this script (its GECOS field lacks '$MARKER_TEXT')"
fi

# --- the work directory: absent, empty or marked; never a symlink, never a system directory
WORK_RAW="${WORK_RAW%/}"
[[ "$WORK_RAW" = /* ]] || refuse "NONROOT_DIR '$WORK_RAW' is not an absolute path"
[ ! -L "$WORK_RAW" ] || refuse "NONROOT_DIR '$WORK_RAW' is a symlink"
WORK="$(realpath -m -- "$WORK_RAW")"
case "$WORK" in
  /|/tmp|/home|/root|/usr|/usr/*|/etc|/var|/var/tmp|/opt|/mnt|/srv|/media|/bin|/sbin|/lib|/lib64|/boot|/dev|/proc|/sys|/run) refuse "NONROOT_DIR '$WORK' is a system directory" ;;
esac
case "$WORK/" in "$ROOT"/*) refuse "NONROOT_DIR '$WORK' is the repository or inside it" ;; esac
case "$ROOT/" in "$WORK"/*) refuse "NONROOT_DIR '$WORK' contains the repository" ;; esac
WORK_STATE=absent
if [ -e "$WORK" ]; then
  [ -d "$WORK" ] || refuse "NONROOT_DIR '$WORK' is not a directory"
  [ "$(stat -c %u "$WORK")" = "$(id -u)" ] || refuse "NONROOT_DIR '$WORK' is owned by someone else"
  [ -z "$(find "$WORK" -maxdepth 0 -perm /022 -print)" ] || refuse "NONROOT_DIR '$WORK' is writable by group or others"
  if [ -f "$WORK/$MARKER_FILE" ] && [ ! -L "$WORK/$MARKER_FILE" ] && [ "$(stat -c %u "$WORK/$MARKER_FILE")" = "$(id -u)" ] \
     && [ "$(cat "$WORK/$MARKER_FILE")" = "$MARKER_TEXT" ]; then
    WORK_STATE=marked
  elif [ -z "$(ls -A "$WORK")" ]; then
    WORK_STATE=empty
  else
    refuse "NONROOT_DIR '$WORK' is not empty and has no marker file ($MARKER_FILE) written by this script"
  fi
  for sub in repo tmp; do [ ! -L "$WORK/$sub" ] || refuse "$WORK/$sub is a symlink"; done
else
  [ -d "$(dirname "$WORK")" ] || refuse "the parent of '$WORK' does not exist"
fi
COPY="$WORK/repo"; TMP="$WORK/tmp"
HOME_U="$(getent passwd "$U" | cut -d: -f6 || true)"; HOME_U="${HOME_U:-/home/$U}"

# --- NONROOT_CLEAN=1
if [ "${NONROOT_CLEAN:-0}" = 1 ]; then
  [ "$IS_ROOT" = 1 ] || [ "$DRY" = 1 ] || refuse "NONROOT_CLEAN=1 needs root"
  if [ "$ACCOUNT" = existing ]; then
    do_ userdel -r "$U"
    [ ! -d "/tmp/torchinductor_$U" ] || do_ rm -rf "/tmp/torchinductor_$U"     # torch's cache, written outside TMPDIR
  fi
  [ "$WORK_STATE" = marked ] && do_ rm -rf "$WORK"
  echo "run_nonroot: cleaned (user $U: $([ "$ACCOUNT" = new ] && echo 'did not exist' || echo removed); $WORK: $([ "$WORK_STATE" = marked ] && echo removed || echo 'not made by this script, left alone'))"
  exit 0
fi

PYTEST=(python -m pytest tests/proxy tests/server tests/live -m 'not research' -n "$N" "$@")
ENVV=(PATH="$PATH" LANG="${LANG:-C.UTF-8}" OMP_NUM_THREADS=1 HF_HUB_OFFLINE=1)
[ "${SENTINEL_SANDBOX_REQUIRED:-}" = 1 ] && ENVV+=(SENTINEL_SANDBOX_REQUIRED=1)
EXCL=(--exclude=.git --exclude=frontend/node_modules --exclude=__pycache__ --exclude=.pytest_cache --exclude=.playwright-mcp
      --exclude=.env '--exclude=.env.*' '--exclude=*.pem' '--exclude=*.key' '--exclude=id_*' --exclude=.netrc '--exclude=credentials*')
TOOL="${NONROOT_COPY:-$(command -v rsync >/dev/null && echo rsync || echo tar)}"
HF_SRC="${HF_HOME:-${HOME:-/root}/.cache/huggingface}"

if [ "$DRY" = 1 ]; then
  echo "run_nonroot plan (nothing is changed)"
  echo "user: $U ($ACCOUNT)"
  echo "copy: $COPY"
  echo "work: $WORK ($WORK_STATE)"
  echo "as: $([ "$IS_ROOT" = 1 ] && echo "root -> runuser $U" || echo "already $(id -un): pytest runs in this checkout")"
  echo "env: ${ENVV[*]}"
  echo "cmd: $(printf '%q ' "${PYTEST[@]}" | sed "s/not\\\\ research/'not research'/")"
  [ "$ACCOUNT" = new ] && echo "plan: useradd -m -s /bin/bash -c '$MARKER_TEXT' $U"
  [ "$WORK_STATE" = absent ] && echo "plan: mkdir -m 755 $WORK"
  [ "$WORK_STATE" = marked ] || echo "plan: write $WORK/$MARKER_FILE"
  echo "plan: mkdir -p $COPY $TMP"
  if [ "$TOOL" = rsync ]; then echo "plan: rsync -a --delete ${EXCL[*]} $ROOT/ $COPY/"
  else echo "plan: tar -c ${EXCL[*]} -C $ROOT . | tar -x -C $COPY"; fi
  [ ! -f "$ROOT/.env.example" ] || echo "plan: cp $ROOT/.env.example $COPY/.env.example"
  [ ! -d "$ROOT/.realdeps/tv" ] || echo "plan: sed -i s#$ROOT#$COPY#g (text files under $COPY/.realdeps/tv)"
  [ ! -d "$HF_SRC/hub" ] || echo "plan: cp -a $HF_SRC/hub $HOME_U/.cache/huggingface/hub (once)"
  echo "plan: chown -hR $U: $COPY $TMP"
  echo "plan: chmod 700 $TMP"
  exit 0
fi

if [ "$IS_ROOT" != 1 ]; then
  echo "run_nonroot: already unprivileged ($(id -un)): running in this checkout"
  cd "$ROOT" && exec env "${ENVV[@]}" HOME="${HOME:-/}" "${PYTEST[@]}"
fi

command -v runuser >/dev/null || refuse "runuser is missing (util-linux); run this script as an unprivileged user instead"
if [ "$ACCOUNT" = new ]; then
  echo "run_nonroot: creating user $U"
  useradd -m -s /bin/bash -c "$MARKER_TEXT" "$U"
  HOME_U="$(getent passwd "$U" | cut -d: -f6)"
fi
[ "$WORK_STATE" = absent ] && mkdir -m 755 "$WORK"
[ -f "$WORK/$MARKER_FILE" ] || { umask 022; printf '%s\n' "$MARKER_TEXT" > "$WORK/$MARKER_FILE"; }
mkdir -p "$COPY" "$TMP"
if [ "$TOOL" = rsync ]; then
  rsync -a --delete "${EXCL[@]}" "$ROOT"/ "$COPY"/
else
  (cd "$ROOT" && tar -c "${EXCL[@]}" .) | tar -x -C "$COPY"
fi
[ ! -f "$ROOT/.env.example" ] || cp "$ROOT/.env.example" "$COPY/.env.example"
if [ -d "$COPY/.realdeps/tv" ]; then   # a venv's scripts record the path it was created at
  grep -rlI -F -- "$ROOT" "$COPY/.realdeps/tv" 2>/dev/null | xargs -r sed -i "s#$ROOT#$COPY#g" || true
fi
if [ "${NONROOT_HF:-1}" = 1 ] && [ -d "$HF_SRC/hub" ] && [ ! -d "$HOME_U/.cache/huggingface/hub" ]; then
  echo "run_nonroot: copying the model cache once ($(du -sh "$HF_SRC/hub" | cut -f1))"
  mkdir -p "$HOME_U/.cache/huggingface" && cp -a "$HF_SRC/hub" "$HOME_U/.cache/huggingface/hub"
  chown -hR "$U:" "$HOME_U/.cache"
fi
chown -hR "$U:" "$COPY" "$TMP"
chmod 700 "$TMP"
ENVV+=(HOME="$HOME_U" TMPDIR="$TMP")
[ -d "$HOME_U/.cache/huggingface" ] && ENVV+=(HF_HOME="$HOME_U/.cache/huggingface")
RUN=(runuser -u "$U" -- env -i "${ENVV[@]}")
"${RUN[@]}" python -c 'import pytest, xdist' 2>/dev/null \
  || refuse "$U cannot run this python ($(command -v python)): it must live outside /root and have pytest and pytest-xdist installed"
echo "run_nonroot: $U in $COPY: ${PYTEST[*]}"
set +e
"${RUN[@]}" bash -c 'cd "$1" && shift && exec "$@"' _ "$COPY" "${PYTEST[@]}"
rc=$?
echo "run_nonroot: pytest exit $rc (as $U, uid $(id -u "$U"))"
exit $rc
