# AutoGate Setup Guide

AutoGate is a permission management system for Claude Code. Instead of manually approving every tool call, AutoGate gives you three modes — manual approval, Opus safety screening, or full auto-approve — toggleable mid-session with a keyboard shortcut.

## How It Works

```
Permission Request
       |
       v
+------------------+     YES
| Read-only tool   |----------> Auto-approve (instant, no API call)
| or safe bash cmd?|
+--------+---------+
         | NO
         v
+------------------+     OFF
| Mode?            |----------> Fall through to manual approval prompt
|                  |
|                  |     YOLO
|                  |----------> Auto-approve (instant, no API call)
+--------+---------+
         | ON
         v
+------------------+   APPROVE
| Opus safety      |----------> Allow
| screening        |
+--------+---------+
         | DENY
         v
      Block (cached for 60s to prevent retries)
```

**Three modes** (cycle with keyboard shortcut: off > on > yolo > off):
- **off** — Normal Claude Code behavior. You approve each action manually.
- **on** — Opus screens every non-read tool call (~2s latency). Safe but slower.
- **yolo** — Everything auto-approved instantly. Equivalent to `--dangerously-skip-permissions` but toggleable mid-session.

**Always auto-approved regardless of mode:**
- Read-only tools: Read, Glob, Grep, WebSearch, WebFetch, TaskList, TaskGet, TaskOutput, TaskCreate, TaskUpdate, ListMcpResourcesTool, ReadMcpResourceTool, Skill, ToolSearch
- Safe bash commands: `ls`, `cat`, `head`, `tail`, `wc`, `file`, `stat`, `du`, `df`, `pwd`, `which`, `whoami`, `date`, `uname`, `hostname`, `id`, `realpath`, `dirname`, `basename`, `echo`, `printf`, `rg`, `tree`, `diff`, `md5sum`, `shasum`
- Safe git subcommands: `git status`, `git log`, `git diff`, `git show`, `git blame`, `git rev-parse`, `git describe`, `git ls-files`, `git ls-tree`, `git cat-file`, `git shortlog`

Bash commands are only auto-approved when they contain no shell metacharacters (`;`, `|`, `&`, `` ` ``, `>`, `<`, `$(`, newlines). This prevents chained or redirected commands from slipping through.

## Setup Instructions

> **For Claude Code:** Open this file in a Claude Code session and say "set this up for me." The instructions below are written for Claude to execute.

### Step 1: Create the Python virtual environment

Create a Python venv and install the Anthropic SDK. The venv ensures the `anthropic` package is available regardless of what's on the user's system Python.

```bash
python3 -m venv ~/.claude/permission-gate-venv
~/.claude/permission-gate-venv/bin/pip install anthropic
```

### Step 2: Write the permission gate script

Write the following to `~/.claude/safely-approve-permissions.py` and make it executable (`chmod +x`):

```python
#!/usr/bin/env python3
"""
Claude Code permission gate hook.
- Auto-approves read-only tools (no API call needed)
- Auto-approves safe bash commands (no metacharacters + known read-only cmd)
- Routes other tools to Opus for safety screening
- If Opus denies, falls through to ask_user
"""

import sys
import json
import os
import hashlib
import logging
import time
from pathlib import Path

# Log to ~/.claude/permission-gate.log for debugging
logging.basicConfig(
    filename=str(Path(__file__).parent / "permission-gate.log"),
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)

# Suppress httpx/anthropic SDK logging to stdout/stderr
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("anthropic").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# Load API key from ~/.claude/.env (always relative to this script, not cwd)
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SAFE_TOOLS — Read-only tools that can never cause destructive edits.
# These are auto-approved instantly with no Opus API call.
# Edit this set to add or remove tools from the auto-approve list.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SAFE_TOOLS = {
    "Read",
    "Glob",
    "Grep",
    "WebSearch",
    "WebFetch",
    "TaskList",
    "TaskGet",
    "TaskOutput",
    "TaskCreate",
    "TaskUpdate",
    "ListMcpResourcesTool",
    "ReadMcpResourceTool",
    "Skill",
    "ToolSearch",
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Safe Bash commands — auto-approved regardless of mode.
# Only commands where NO combination of flags can write to disk.
# Commands like sort (-o), find (-delete, -exec), curl (-o) are excluded.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_SHELL_DANGEROUS_CHARS = set(';|&`><')
_SHELL_DANGEROUS_PATTERNS = ['$(', '\n']

SAFE_BASH_CMDS = {
    'ls', 'cat', 'head', 'tail', 'wc', 'file', 'stat', 'du', 'df',
    'pwd', 'which', 'whoami', 'date', 'uname', 'hostname', 'id',
    'realpath', 'dirname', 'basename', 'echo', 'printf',
    'rg', 'tree', 'diff', 'md5sum', 'shasum',
}

SAFE_GIT_SUBCMDS = {
    'status', 'log', 'diff', 'show', 'blame',
    'rev-parse', 'describe', 'ls-files', 'ls-tree',
    'cat-file', 'shortlog',
}

# Git global flags that consume the next word as their argument
_GIT_FLAGS_WITH_ARG = {'-c', '-C', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env'}


def _git_subcommand(words):
    """Extract the git subcommand, skipping global flags and their arguments."""
    i = 1  # skip 'git'
    while i < len(words):
        w = words[i]
        if w in _GIT_FLAGS_WITH_ARG:
            i += 2  # skip flag + its argument
        elif w.startswith('-'):
            i += 1
        else:
            return w
    return None


def _is_safe_bash(command):
    """Check if a bash command is safe to auto-approve."""
    for ch in _SHELL_DANGEROUS_CHARS:
        if ch in command:
            return False
    for pat in _SHELL_DANGEROUS_PATTERNS:
        if pat in command:
            return False

    words = command.strip().split()
    if not words:
        return False

    # Handle full paths: /usr/bin/ls -> ls
    cmd = words[0].rsplit('/', 1)[-1]

    if cmd in SAFE_BASH_CMDS:
        return True

    if cmd == 'git':
        subcmd = _git_subcommand(words)
        return subcmd in SAFE_GIT_SUBCMDS

    return False


# File-based denial cache (survives across hook invocations within a session)
_CACHE_PATH = Path(__file__).parent / "permission-gate-deny-cache.json"
_CACHE_TTL = 60  # seconds — deny same call instantly for 60s


def _cache_key(tool: str, params: str) -> str:
    return hashlib.sha256(f"{tool}:{params}".encode()).hexdigest()


def _is_cached_denial(key: str) -> bool:
    if not _CACHE_PATH.exists():
        return False
    try:
        cache = json.loads(_CACHE_PATH.read_text())
        entry = cache.get(key)
        if entry and time.time() - entry["ts"] < _CACHE_TTL:
            return True
    except Exception:
        pass
    return False


def _cache_denial(key: str):
    try:
        cache = json.loads(_CACHE_PATH.read_text()) if _CACHE_PATH.exists() else {}
    except Exception:
        cache = {}
    # Prune expired entries
    now = time.time()
    cache = {k: v for k, v in cache.items() if now - v["ts"] < _CACHE_TTL}
    cache[key] = {"ts": now}
    _CACHE_PATH.write_text(json.dumps(cache))


def allow():
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"},
        }
    }))


def deny(message="Opus flagged as potentially risky"):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "deny", "message": message},
        }
    }))


def call_claude(model: str, tool: str, params: str) -> str:
    """Call Anthropic API and return the response text."""
    import anthropic
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=model,
        max_tokens=150,
        messages=[{
            "role": "user",
            "content": (
                "You are a security gate for a coding agent. "
                "Evaluate whether this tool call is safe. Consider: "
                "command injection, destructive file ops, secret exfiltration, "
                "network abuse, or anything suspicious.\n\n"
                f"Tool: {tool}\n"
                f"Input: {params}\n\n"
                "Reply with exactly one word: APPROVE or DENY"
            ),
        }],
    )
    return resp.content[0].text.strip().upper()


def main():
    data = json.load(sys.stdin)
    tool = data.get("tool_name", "")
    params = json.dumps(data.get("tool_input", {}), indent=2)

    logging.info(f"tool={tool}")

    # Auto-approve read-only tools (always, regardless of mode)
    if tool in SAFE_TOOLS:
        logging.info("auto-approve (safe tool)")
        allow()
        return

    # Auto-approve safe bash commands (always, regardless of mode)
    if tool == "Bash":
        command = data.get("tool_input", {}).get("command", "")
        if _is_safe_bash(command):
            logging.info(f"auto-approve (safe bash)")
            allow()
            return

    # Mode toggle — file contains "off", "on", or "yolo"
    # off:  fall through to normal permission prompt
    # on:   Opus safety screening
    # yolo: auto-approve everything instantly
    _gate_file = Path(__file__).parent / "autogate"
    mode = _gate_file.read_text().strip() if _gate_file.exists() else "off"

    if mode == "yolo":
        logging.info("auto-approve (yolo mode)")
        allow()
        return

    if mode != "on":
        return  # no output -> falls through to normal permission prompt

    cache_k = _cache_key(tool, params)

    # Instant deny if recently denied (prevents retry loops)
    if _is_cached_denial(cache_k):
        logging.info("cached denial — instant deny")
        deny("Previously denied — same tool call was recently flagged")
        return

    # Opus screening
    try:
        opus_answer = call_claude("claude-opus-4-5-20251101", tool, params)
        logging.info(f"opus said: {opus_answer}")
    except Exception as e:
        logging.info(f"opus error: {e}")
        deny("Opus API error — couldn't verify safety")
        return

    if "APPROVE" in opus_answer:
        allow()
        return

    # Opus denied -> cache and deny
    logging.info("opus denied -> deny")
    _cache_denial(cache_k)
    deny("Opus flagged as potentially risky")


if __name__ == "__main__":
    main()
```

### Step 3: Write the toggle script

Write the following to `~/.claude/toggle-autogate.sh` and make it executable:

```bash
#!/bin/bash
# Cycle: off -> on -> yolo -> off
f=~/.claude/autogate
current=$(cat "$f" 2>/dev/null)
case "$current" in
  off)  echo on   > "$f" ;;
  on)   echo yolo > "$f" ;;
  yolo) echo off  > "$f" ;;
  *)    echo off  > "$f" ;;
esac
```

### Step 4: Write the statusline script

Write the following to `~/.claude/statusline-command.sh` and make it executable:

```bash
#!/bin/bash

# Read JSON input from stdin
input=$(cat)

# Extract current directory
dir=$(echo "$input" | jq -r '.workspace.current_dir')
dir_name=$(basename "$dir")

# Extract context remaining percentage
remaining=$(echo "$input" | jq -r '.context_window.remaining_percentage // empty')

# Get git branch (skip locks to avoid issues)
cd "$dir" 2>/dev/null || exit 0
git_branch=$(git -c core.useBuiltinFSMonitor=false rev-parse --abbrev-ref HEAD 2>/dev/null)

# Get git status (skip locks)
git_status=""
if [ -n "$git_branch" ]; then
    if ! git -c core.useBuiltinFSMonitor=false diff-index --quiet HEAD -- 2>/dev/null; then
        git_status="*"
    fi
fi

# ANSI color codes
BOLD_BLUE="\033[1;94m"
BOLD_YELLOW="\033[1;93m"
GREY="\033[90m"
RESET="\033[0m"

# Build status line with colors
output="${BOLD_BLUE}${dir_name}${RESET}"

if [ -n "$git_branch" ]; then
    output="${output} ${GREY}on${RESET} ${BOLD_YELLOW}${git_branch}${git_status}${RESET}"
fi

# Read autogate status
autogate=$(cat ~/.claude/autogate 2>/dev/null)
case "$autogate" in
    on)
        AUTOGATE_COLOR="\033[1;92m"  # Bright green
        autogate_label="AG:on"
        ;;
    yolo)
        AUTOGATE_COLOR="\033[1;93m"  # Bright yellow — running hot
        autogate_label="AG:yolo"
        ;;
    *)
        AUTOGATE_COLOR="\033[90m"    # Grey
        autogate_label="AG:off"
        ;;
esac

if [ -n "$remaining" ]; then
    output="${output} ${GREY}|${RESET} ${AUTOGATE_COLOR}${autogate_label}${RESET} ${GREY}|${RESET} ${GREY}$(printf "%.0f" "$remaining")%${RESET}"
fi

printf "%b" "$output"
```

### Step 5: Create the autogate toggle file and keyboard shortcut

Write `on` to `~/.claude/autogate`.

**Recommended: Set up a global keyboard shortcut to toggle AutoGate.**

This lets you cycle through modes instantly from anywhere without leaving your current context.

1. Open **Automator** (search for it in Spotlight)
2. Create a new **Quick Action** (Service)
3. Set "Workflow receives" to **no input** in **any application**
4. Add a **Run Shell Script** action with shell set to `/bin/zsh` and paste:
   ```
   ~/.claude/toggle-autogate.sh
   ```
5. Save it as **"Toggle AutoGate"** (or similar)
6. Go to **System Settings > Keyboard > Keyboard Shortcuts > Services** (or **General > Services** on older macOS)
7. Find your new service under **General** and assign a shortcut — we use **Ctrl+Option+Shift+G**

Now you can cycle through modes with a single keystroke. The statusline updates immediately to reflect the change.

### Step 6: Set up the API key

Create `~/.claude/.env` (if it doesn't already exist) with this template:

```
ANTHROPIC_API_KEY=your-api-key-here
```

**Tell the user:** You need to replace `your-api-key-here` with your actual Anthropic API key. Get one at https://console.anthropic.com/settings/keys.

### Step 7: Update settings.json

Merge the following into `~/.claude/settings.json`, preserving any existing configuration (especially `enabledPlugins` and other settings).

**Important:** Tilde (`~`) is not expanded in hook command paths. You must use the user's full absolute home directory path (e.g., `/Users/username/.claude/...`). Resolve `$HOME` to get the correct path.

```json
{
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/permission-gate-venv/bin/python3 $HOME/.claude/safely-approve-permissions.py"
          }
        ]
      }
    ]
  },
  "statusLine": {
    "type": "command",
    "command": "/bin/bash $HOME/.claude/statusline-command.sh"
  }
}
```

Replace `$HOME` with the actual absolute path (e.g., `/Users/jane`). If `settings.json` already exists, merge these keys in — don't overwrite the file.

## Verify It's Working

1. **Check the statusline** — you should see `AG:on` in green in your Claude Code status bar.
2. **Try a read operation** — ask Claude to read a file. It should go through instantly with no approval prompt.
3. **Try `ls` or `git status`** — these safe bash commands should also go through instantly with no prompt, even in `off` mode.
4. **Try a write operation in `on` mode** — ask Claude to write something. There should be a brief pause (~2s) while Opus screens it, then it proceeds.
5. **Check the log** — run `tail ~/.claude/permission-gate.log` to see approval/denial decisions.
6. **Test the toggle** — run `bash ~/.claude/toggle-autogate.sh` three times and confirm the statusline cycles through `AG:on` (green) > `AG:yolo` (yellow) > `AG:off` (grey).

## Configuration

### Toggle AutoGate mode

```bash
# Cycle: off -> on -> yolo -> off
bash ~/.claude/toggle-autogate.sh

# Or set directly
echo off  > ~/.claude/autogate   # Manual approval
echo on   > ~/.claude/autogate   # Opus screening (~2s per write)
echo yolo > ~/.claude/autogate   # Auto-approve everything
```

Note: Read-only tools and safe bash commands are always auto-approved regardless of the mode.

### Edit the safe tools list

Open `~/.claude/safely-approve-permissions.py` and find the `SAFE_TOOLS` set (clearly marked with a comment banner). Add or remove tool names as needed.

To add or remove safe bash commands, edit `SAFE_BASH_CMDS` or `SAFE_GIT_SUBCMDS` in the same file. Only add commands where **no combination of flags can write to disk**. Commands like `sort` (has `-o`), `find` (has `-delete`, `-exec`), and `curl` (has `-o`) are intentionally excluded.

### Update your API key

Edit `~/.claude/.env` and replace the key value.

### Check Opus decisions

```bash
tail -50 ~/.claude/permission-gate.log
```

## Good to Know

- **Latency:** In `on` mode, non-read tool calls add ~2 seconds each while Opus screens them. In `yolo` mode, there is no added latency. Safe bash commands and read-only tools are always instant.
- **Cost:** Each Opus screening call uses a small number of tokens (~200 input, ~5 output). A heavy session with hundreds of writes might cost a dollar or two. `yolo` mode and safe bash commands cost nothing.
- **Errors:** If the Opus API call fails (network issue, bad key, rate limit), the tool call is denied by default. Check `permission-gate.log` to diagnose.
- **Denial cache:** If Opus denies a tool call, that exact same call is auto-denied for 60 seconds to prevent retry loops. The cache file is at `~/.claude/permission-gate-deny-cache.json`.
- **Safe bash security model:** Commands are only auto-approved when they contain no shell metacharacters (`;`, `|`, `&`, `` ` ``, `>`, `<`, `$(`, newlines) AND the command is in the allowlist. This prevents chaining (`ls; rm -rf /`), piping (`cat | evil`), redirection (`echo > file`), and command substitution (`` `evil` ``). Commands with write-capable flags (like `sort -o`, `find -delete`) are not on the allowlist.

## Improvement Opportunities

These are areas we've identified for future refinement:

1. **Add session context to the Opus prompt.** Currently Opus sees only the tool name and input with no context about what the session is doing or why. Passing a summary of the current task would let Opus make more nuanced decisions (e.g., `git push --force` might be fine during a rebase workflow but suspicious otherwise).

2. **Make SAFE_TOOLS configurable via a file.** Instead of editing the Python source, a `~/.claude/autogate-safe-tools.json` file would make it easier to customize and share configurations.

3. **Tune the denial cache.** The 60-second TTL is a reasonable default but could be made configurable. Some teams might want longer or shorter windows.

4. **Cost/usage tracking.** A simple counter in the log or a separate file tracking how many Opus calls are made per session would help with cost visibility.

5. **Better logging of deny reasons.** When Opus denies a call, it would be useful to understand why. One approach: make a second, separate API call after a denial specifically to get an explanation for the log, keeping the screening call itself as a strict single-word APPROVE/DENY (which is critical for reliability — richer screening responses risk parsing failures that would break the gate).
