#!/usr/bin/env python3
"""injectscan - look for hidden instructions aimed at an AI before you let it read a file.

When an AI assistant reads a web page, a README, a ticket or a rules file (CLAUDE.md, AGENTS.md, .cursorrules, a skill),
text planted in it can try to steer the assistant: "ignore your previous instructions", "do not tell the user", "send the
API keys to ...". Attackers hide such text where you will not see it: invisible Unicode characters (including the
'tag' block that spells out whole sentences), HTML comments, CSS-hidden elements, white-on-white text, text pushed far to
the right of a line. injectscan finds both the hiding places and instruction-like wording, and decodes what was hidden.
Offline, read-only, standard library only. It is a heuristic filter, not a guarantee.
Exit codes: 0 = nothing at MEDIUM or above, 1 = findings, 2 = usage error.
"""
import argparse
import base64
import binascii
import json
import os
import re
import sys
import unicodedata
from html.parser import HTMLParser

__version__ = "1.0.0"

MAX_FILE = 2 * 1024 * 1024
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
ESCALATE = {"INFO": "LOW", "LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "HIGH"}
IGNORE_LINE = "injectscan:ignore"
IGNORE_FILE = "injectscan:ignore-file"

TAG_CHARS = re.compile("[\U000e0000-\U000e007f]+")
BIDI = re.compile("[‪-‮⁦-⁩‎‏؜]")
ZERO_WIDTH = re.compile("[​‌‍⁠-⁤­᠎͏ᅟᅠㅤﾠ]")
VARIATION = re.compile("[︀-️\U000e0100-\U000e01ef]")
BOM_MID = re.compile("(?<!^)﻿")

PHRASES = (
    ("override-instructions", "HIGH", re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|the|these|those)\b[^.\n]{0,30}"
        r"\b(instructions?|rules?|prompts?|guidelines?|directions?|context|polic(?:y|ies)|safety)\b", re.I)),
    ("role-reassignment", "MEDIUM", re.compile(
        r"\byou are (now|no longer)\b|\bfrom now on,? you\b|\bnew (system )?instructions?\s*:|\byour (new|real|true) (task|goal|instructions?)\b|"
        r"\bdeveloper mode\b|\bjailbreak\b|\bact as (an? )?(unrestricted|unfiltered|evil)\b", re.I)),
    ("secrecy", "HIGH", re.compile(
        r"\b(do not|don't|never|without)\b[^.\n]{0,30}\b(tell|inform|mention|reveal|show|notify|alert|warn)\w*\b[^.\n]{0,30}\b(the )?(user|human|operator|owner)\b", re.I)),
    ("reveal-secrets", "HIGH", re.compile(
        r"\b(reveal|print|output|repeat|show|leak|send|share|read|cat)\b[^.\n]{0,40}(?<!\w)(system prompt|your instructions|hidden (prompt|instructions)|api[ _-]?keys?|"
        r"secrets?|credentials|environment variables|\.env\b|ssh keys?|private keys?|passwords?|access tokens?)\b", re.I)),
    ("addresses-the-ai", "MEDIUM", re.compile(
        r"\b(if you are|when you (read|see|process|summari[sz]e|parse)|attention|note to|dear)\b[^.\n]{0,30}\b(ai|llm|assistant|agent|model|chatbot|gpt|claude|copilot|language model)s?\b|"
        r"\b(ai|llm)\s+(assistants?|agents?|models?)\s+(must|should|shall|will)\b", re.I)),
    ("run-this", "MEDIUM", re.compile(
        r"\b(run|execute|call|invoke|use)\b[^.\n]{0,25}\b(the following|this|these)\b[^.\n]{0,15}\b(command|script|tool|code)s?\b|"
        r"\b(curl|wget)\b[^|\n]{0,120}\|\s*(sudo\s+)?(ba|z)?sh\b", re.I)),
    ("send-data-out", "HIGH", re.compile(
        r"\b(send|post|upload|forward|exfiltrate|transmit|email|leak)\b[^.\n]{0,60}\b(to|at)\b[^.\n]{0,20}(https?://\S+|\b[\w.+-]+@[\w-]+\.[a-z]{2,})", re.I)),
    ("fake-chat-markup", "MEDIUM", re.compile(
        r"<\|(im_start|im_end|endoftext|system|user|assistant)\|>|\[/?INST\]|<<SYS>>|</?(system|assistant)>|\\n\\nHuman:|\n\nHuman:|\n\nAssistant:")),
    ("weakens-safety", "MEDIUM", re.compile(
        r"--dangerously-skip-permissions|\bbypass\s*permissions\b|\byolo mode\b|\bnever (ask|prompt|wait)\b[^.\n]{0,30}\b(confirm\w*|permission|approval|user)\b|"
        r"\b(always|automatically)\b[^.\n]{0,20}\b(approve|accept|trust)\b|\bdisable (the )?(sandbox|safety|guardrails|confirmations?|permission prompts?)\b", re.I)),
    ("risky-command", "LOW", re.compile(
        r"\brm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$HOME)|\bchmod\s+(-R\s+)?777\b|cat\s+~?/?\.ssh/id_|\bnc\s+-e\b|/dev/tcp/|\bsudo\s+(rm|chmod|chown|sh|bash)\b", re.I)),
)
HIDING_STYLE = (
    (re.compile(r"display\s*:\s*none", re.I), "display:none"),
    (re.compile(r"visibility\s*:\s*hidden", re.I), "visibility:hidden"),
    (re.compile(r"font-size\s*:\s*0*\.?0*(px|pt|em|rem|%)?\s*(;|$|!)", re.I), "font-size:0"),
    (re.compile(r"opacity\s*:\s*0(\.0+)?\s*(;|$|!)", re.I), "opacity:0"),
    (re.compile(r"(left|top|right|bottom|text-indent|margin-left)\s*:\s*-\s*\d{3,}", re.I), "positioned far off screen"),
    (re.compile(r"(width|height)\s*:\s*0(px)?\s*;[^\"']*overflow\s*:\s*hidden|overflow\s*:\s*hidden[^\"']*(width|height)\s*:\s*0(px)?\b", re.I), "zero-size box"),
    (re.compile(r"clip(-path)?\s*:\s*(rect\(0[ ,]+0[ ,]+0[ ,]+0\)|inset\(50%\)|polygon\(0 0)", re.I), "clipped away"),
    (re.compile(r"color\s*:\s*transparent", re.I), "transparent text"),
)
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
AGENT_FILES = ("claude.md", "claude.local.md", "agents.md", "gemini.md", "copilot-instructions.md", ".cursorrules", ".windsurfrules",
               ".clinerules", "skill.md", ".mcp.json")
AGENT_DIRS = (".claude", ".cursor", ".windsurf", ".github/instructions", ".github/prompts", ".continue", ".aider")


# --------------------------------------------------------------------- helpers
def line_starts(text):
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    return starts


def locate(starts, index):
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= index:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1, index - starts[lo] + 1


def show(text, limit=100):
    """Printable, single-line excerpt: invisible and control characters become \\uXXXX escapes."""
    out = []
    for ch in text:
        cp = ord(ch)
        if ch in "\n\r\t":
            out.append(" ")
        elif cp < 32 or cp == 127 or unicodedata.category(ch) in ("Cf", "Cc", "Co", "Cn") or 0xE0000 <= cp <= 0xE007F:
            out.append("\\u%04x" % cp if cp <= 0xFFFF else "\\U%08x" % cp)
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= limit else s[:limit - 3] + "..."


def decode_tags(run):
    """The ASCII message spelled by a run of Unicode tag characters."""
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)


def phrase_hits(text):
    """[(rule, severity, match_text)] for instruction-like wording in ``text``."""
    hits = []
    for rule, sev, rx in PHRASES:
        m = rx.search(text)
        if m:
            hits.append((rule, sev, m.group(0)))
    return hits


class Collector:
    def __init__(self, path, text):
        self.path, self.text, self.starts = path, text, line_starts(text)
        self.findings = []
        self.ignored = set()
        for i, line in enumerate(text.split("\n"), 1):
            if IGNORE_LINE in line:
                self.ignored.add(i)

    def add(self, index, sev, rule, message, snippet="", hidden=None):
        line, col = locate(self.starts, index)
        if line in self.ignored:
            return False
        f = {"file": self.path, "line": line, "column": col, "severity": sev, "rule": rule, "message": message,
             "snippet": show(snippet) if snippet else ""}
        if hidden:
            f["hidden_text"] = show(hidden, 300)
        self.findings.append(f)
        return True

    def phrases(self, text, index, hidden_context="", base_hidden=None):
        """Report instruction-like phrases; those found inside hidden content are escalated one level."""
        for rule, sev, matched in phrase_hits(text):
            if hidden_context:
                sev = ESCALATE[sev]
            where = " (inside %s)" % hidden_context if hidden_context else ""
            self.add(index, sev, rule, "instruction-like text aimed at an AI%s" % where, matched, base_hidden if hidden_context else None)


# ------------------------------------------------------------------ HTML view
class _Visibility(HTMLParser):
    """Finds text that a browser would not show: hidden elements and comments."""

    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.text, self.stack, self.hidden_runs, self.comments = text, [], [], []
        self.starts = line_starts(text)

    def _offset(self):
        line, col = self.getpos()
        return self.starts[line - 1] + col if line - 1 < len(self.starts) else 0

    @staticmethod
    def _norm(color):
        c = color.strip().lower()
        names = {"white": "#ffffff", "black": "#000000"}
        c = names.get(c, c)
        if re.fullmatch(r"#[0-9a-f]{3}", c):
            c = "#" + "".join(ch * 2 for ch in c[1:])
        return c

    def _why_hidden(self, attrs):
        d = dict((k.lower(), (v or "")) for k, v in attrs)
        if "hidden" in d and d.get("hidden", "") != "false":
            return "the hidden attribute"
        if d.get("aria-hidden", "").lower() == "true":
            return "aria-hidden"
        style = d.get("style", "")
        for rx, label in HIDING_STYLE:
            if rx.search(style):
                return label
        fg = re.search(r"(?<![-\w])color\s*:\s*([#\w]+)", style, re.I)
        bg = re.search(r"background(?:-color)?\s*:\s*([#\w]+)", style, re.I)
        if fg and bg and self._norm(fg.group(1)) == self._norm(bg.group(1)):
            return "text the same colour as its background"
        return None

    def handle_starttag(self, tag, attrs):
        if tag in VOID:
            return
        parent = self.stack[-1][1] if self.stack else None
        why = parent or self._why_hidden(attrs)
        self.stack.append((tag, why))

    def handle_startendtag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        if self.stack and self.stack[-1][1] and data.strip():
            if self.stack[-1][0] in ("script", "style"):
                return
            self.hidden_runs.append((self._offset(), data, self.stack[-1][1]))

    def handle_comment(self, data):
        self.comments.append((self._offset(), data))


def looks_like_html(path, text):
    return path.lower().endswith((".html", ".htm", ".xhtml")) or bool(re.search(r"<(html|body|div|p|span|a)\b[^>]*>", text[:20000], re.I))


# ------------------------------------------------------------------- scanning
def scan_text(text, path="<text>", verbose=False):
    """All findings for one document: list of dicts, sorted by position."""
    c = Collector(path, text)
    head = "\n".join(text.split("\n")[:20])
    if IGNORE_FILE in head:
        return []

    # invisible Unicode
    for m in TAG_CHARS.finditer(text):
        message = decode_tags(m.group(0))
        c.add(m.start(), "HIGH", "unicode-tag-characters",
              "%d invisible 'tag' characters that spell out %s" % (len(m.group(0)), "a hidden message" if message else "data"),
              "", message or None)
        if message:
            c.phrases(message, m.start(), "invisible Unicode tag characters", message)
    for rx, rule, sev, label in ((BIDI, "bidi-control", "HIGH", "text-direction control characters (they can reorder what you read)"),
                                 (ZERO_WIDTH, "zero-width-characters", "MEDIUM", "zero-width or invisible characters")):
        found = list(rx.finditer(text))
        if found:
            joined = "".join(m.group(0) for m in found)
            c.add(found[0].start(), sev, rule, "%d %s" % (len(found), label), text[max(0, found[0].start() - 20):found[0].start() + 40])
            hidden_words = zero_width_payload(text) if rule == "zero-width-characters" else None
            if hidden_words:
                c.add(found[0].start(), "HIGH", "zero-width-encoded-data", "zero-width characters are used to encode hidden data", "", hidden_words)
    var = list(VARIATION.finditer(text))
    if len(var) >= 8:
        c.add(var[0].start(), "MEDIUM", "variation-selectors", "%d variation selectors (a way to smuggle data)" % len(var))
    mid = list(BOM_MID.finditer(text))
    if mid:
        c.add(mid[0].start(), "LOW", "stray-bom", "a byte order mark in the middle of the text")

    # text pushed out of sight on the same line
    for m in re.finditer(r"(?m)^(.*?\S)[ \t]{60,}(\S.*)$", text):
        tail = m.group(2)
        c.add(m.start(2), "MEDIUM", "hidden-after-padding", "text placed after a long run of spaces (off the right edge of the screen)", "", tail)
        c.phrases(tail, m.start(2), "text padded off-screen", tail)

    # HTML / Markdown hiding places
    comments_seen = set()
    if looks_like_html(path, text) or path.lower().endswith((".md", ".markdown", ".mdx")) or "<!--" in text:
        parser = _Visibility(text)
        try:
            parser.feed(text)
            parser.close()
        except Exception:  # malformed HTML must never stop the scan
            pass
        for off, data in parser.comments:
            comments_seen.add(off)
            words = len(data.split())
            hits = phrase_hits(data)
            if hits:
                for rule, sev, matched in hits:
                    c.add(off, ESCALATE[sev], rule, "instruction-like text aimed at an AI (inside an HTML comment, invisible when rendered)", matched, data.strip())
            elif words >= 12:
                c.add(off, "LOW", "long-hidden-comment", "a comment of %d words that is invisible when the page is rendered" % words, data.strip()[:80])
        for off, data, why in parser.hidden_runs:
            words = len(data.split())
            hits = phrase_hits(data)
            if hits:
                for rule, sev, matched in hits:
                    c.add(off, ESCALATE[sev], rule, "instruction-like text aimed at an AI (hidden by %s)" % why, matched, data.strip())
            elif words >= 20:
                c.add(off, "MEDIUM", "hidden-text", "%d words hidden by %s" % (words, why), data.strip()[:80], data.strip())

    # visible instruction-like text
    stripped = re.sub(r"<!--.*?-->", lambda m: " " * len(m.group(0)), text, flags=re.S)
    for rule, sev, rx in PHRASES:
        for m in rx.finditer(stripped):
            if c.add(m.start(), sev, rule, "instruction-like text aimed at an AI", m.group(0)):
                break  # one finding per rule per document is enough to review the file

    # image / link exfiltration channels
    for m in re.finditer(r"!\[[^\]]*\]\((https?://[^)\s]+\?[^)\s]{16,})[^)]*\)|<img\b[^>]*\bsrc=[\"'](https?://[^\"']+\?[^\"']{16,})[\"']", text, re.I):
        url = m.group(1) or m.group(2)
        if re.search(r"(?i)(secret|token|key|passw|data|q|text|content|msg|prompt|conversation|history)=|%7B|\$\{|\{\{|<", url):
            c.add(m.start(), "MEDIUM", "image-exfiltration", "an image whose address carries data in its query string (loading it sends that data to the server)", url)

    # encoded payloads
    for m in re.finditer(r"[A-Za-z0-9+/]{80,}={0,2}", text):
        decoded = try_base64(m.group(0))
        if decoded and phrase_hits(decoded):
            c.add(m.start(), "HIGH", "encoded-instructions", "a base64 block that decodes to instruction-like text", m.group(0)[:60], decoded)
        elif decoded and verbose:
            c.add(m.start(), "INFO", "base64-text", "a base64 block that decodes to text", m.group(0)[:60], decoded)

    best = {}
    for f in c.findings:  # the same rule on the same line is one finding: keep the most severe report of it
        key = (f["line"], f["rule"])
        if key not in best or SEV[f["severity"]] < SEV[best[key]["severity"]]:
            best[key] = f
    return sorted(best.values(), key=lambda f: (f["line"], f["column"], SEV[f["severity"]]))


def zero_width_payload(text):
    """If runs of zero-width characters look like binary (two alternating kinds), decode them to ASCII."""
    runs = re.findall("[​‌‍⁠]{16,}", text)
    out = []
    for run in runs:
        kinds = sorted(set(run))
        if len(kinds) < 2:
            continue
        zero, one = kinds[0], kinds[1]
        bits = "".join("1" if ch == one else "0" for ch in run if ch in (zero, one))
        chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8)]
        msg = "".join(chars)
        if msg and sum(ch.isprintable() for ch in msg) / len(msg) > 0.8:
            out.append(msg)
    return " | ".join(out) or None


def try_base64(blob):
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in text)
    return text if text and printable / len(text) > 0.9 else None


def sanitize(text):
    """The text with invisible characters removed. Returns (clean_text, removed_count)."""
    before = len(text)
    for rx in (TAG_CHARS, BIDI, ZERO_WIDTH, VARIATION, BOM_MID):
        text = rx.sub("", text)
    return text, before - len(text)


# ----------------------------------------------------------------- file level
def is_agent_file(rel):
    low = rel.lower().replace(os.sep, "/")
    base = low.rsplit("/", 1)[-1]
    return base in AGENT_FILES or any(low.startswith(d + "/") or ("/" + d + "/") in low for d in AGENT_DIRS) or base.endswith(".instructions.md")


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_FILE:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def collect(paths, recursive=False, project=False):
    files = []
    for p in paths:
        if os.path.isdir(p):
            if not (recursive or project):
                raise ValueError("%s is a folder; use --recursive (everything) or --project (agent instruction files only)" % p)
            for root, dirs, names in os.walk(p, followlinks=False):
                dirs[:] = sorted(d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__"))
                for n in sorted(names):
                    full = os.path.join(root, n)
                    if os.path.islink(full):
                        continue
                    if not project or is_agent_file(os.path.relpath(full, p)):
                        files.append(full)
        elif os.path.exists(p):
            files.append(p)
        else:
            raise ValueError("no such file or folder: %s" % p)
    return files


def main(argv=None, stdin=None):
    ap = argparse.ArgumentParser(description="Find hidden or instruction-like text aimed at AI assistants.")
    ap.add_argument("paths", nargs="*", help="files or folders; '-' or nothing reads stdin")
    ap.add_argument("-r", "--recursive", action="store_true", help="scan every text file in folders")
    ap.add_argument("--project", action="store_true", help="in folders, scan only AI instruction files (CLAUDE.md, AGENTS.md, .cursorrules, skills, .claude/ ...)")
    ap.add_argument("--min-severity", choices=("INFO", "LOW", "MEDIUM", "HIGH"), default="LOW")
    ap.add_argument("--sanitize", action="store_true", help="print the single input file with invisible characters removed")
    ap.add_argument("--verbose", action="store_true", help="also report harmless-looking base64 text")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    stdin = stdin or sys.stdin
    try:
        if args.paths in ([], ["-"]):
            documents = [("<stdin>", stdin.read(MAX_FILE))]
        else:
            documents = []
            for f in collect(args.paths, args.recursive, args.project):
                text = read_text(f)
                if text is not None:
                    documents.append((f, text))
    except ValueError as exc:
        print("injectscan: %s" % exc, file=sys.stderr)
        return 2
    if args.sanitize:
        if len(documents) != 1:
            print("injectscan: --sanitize needs exactly one file", file=sys.stderr)
            return 2
        clean, removed = sanitize(documents[0][1])
        sys.stdout.write(clean)
        print("injectscan: removed %d invisible character(s)" % removed, file=sys.stderr)
        return 0
    shown = SEV[args.min_severity]
    findings = []
    for path, text in documents:
        findings.extend(f for f in scan_text(text, path, args.verbose) if SEV[f["severity"]] <= shown)
    bad = any(f["severity"] in ("HIGH", "MEDIUM") for f in findings)
    if args.json:
        print(json.dumps({"files": len(documents), "findings": findings}, indent=2, ensure_ascii=True))
    else:
        for f in findings:
            print("%-6s %-24s %s:%d:%d  %s" % (f["severity"], f["rule"], f["file"], f["line"], f["column"], f["message"]))
            if f["snippet"]:
                print("         text: %s" % f["snippet"])
            if f.get("hidden_text"):
                print("         hidden text: %s" % f["hidden_text"])
        print("injectscan: %d finding(s) in %d file(s). A clean result means nothing suspicious was found, not that the content is safe."
              % (len(findings), len(documents)), file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
