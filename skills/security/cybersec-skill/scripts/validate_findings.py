#!/usr/bin/env python3
"""Validate findings.json against schemas/report-schema.json.

Usage: python validate_findings.py <path-to-findings.json>

A Python port of security-audit-skill's validate-findings.cjs (MIT, Cloudflare): a dependency-free
interpreter for the JSON Schema keywords the schema uses (including the custom "visibleContent"),
the same input limits and safe-read rules, and the same finding-specific checks (sorted unique
fingerprints, safe repository-relative paths, trace shape, verdict-specific fields, overall severity
not above demonstrated impact).

Checks added by this skill:
  - confirmed and needs_validation records cite `sources`; a confirmed record needs at least one
    tier-A "violated-requirement" source and one "weakness" (CWE) source;
  - every tier-A source names a file under references/ that exists and contains its identifier;
  - tier-B sources may only be "candidate-control" and must point at the tier-B cards or the inventory;
  - a `cvss` block must match scripts/cvss4.py exactly for its vector (never an estimated score);
  - a record with category "dependency" names its `package`.
"""
import json, os, pathlib, re, stat, sys, unicodedata

ROOT = pathlib.Path(__file__).resolve().parent
SKILL = ROOT.parent
SCHEMA = SKILL / "schemas" / "report-schema.json"

SUPPORTED_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}
SUPPORTED_KEYWORDS = {"$comment", "additionalProperties", "const", "description", "enum", "items", "minimum",
                      "minItems", "minLength", "oneOf", "pattern", "properties", "required", "type", "uniqueItems",
                      "visibleContent"}
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LIMITS = {"inputBytes": 5 * 1024 * 1024, "nestingDepth": 64, "arrayItems": 1000, "canonicalKeyBytes": 1024 * 1024,
          "uniqueSetBytes": 5 * 1024 * 1024, "validationErrors": 100}
MAX_DIAGNOSTIC_STRING_LENGTH = 256
# Unicode Default_Ignorable_Code_Point ranges (DerivedCoreProperties.txt).
_DEFAULT_IGNORABLE = [(0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
                      (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
                      (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
                      (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF)]
_WHITE_SPACE = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
                *range(0x2000, 0x200B)}
WINDOWS_RESERVED_COMPONENT = re.compile(r"^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9¹²³]|"
                                        r"lpt[1-9¹²³])(?:\.|$)", re.I)
TIER_B_FILES = {"references/standards/tier-b-cards.md", "references/standards/INVENTORY.md"}


class SafeInputError(Exception):
    pass


class JsonStructureError(Exception):
    pass


class LimitedErrors(list):
    """Error list that silently stops growing at the validation-error limit, like the original."""

    def push(self, *messages):
        remaining = LIMITS["validationErrors"] - len(self)
        if remaining > 0:
            self.extend(escape_unsafe(m) for m in messages[:remaining])
        return len(self)


def _ignorable(cp):
    return any(a <= cp <= b for a, b in _DEFAULT_IGNORABLE)


def _unsafe_char(ch):
    cp = ord(ch)
    return unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp") or _ignorable(cp)


def escape_unsafe(value):
    out = []
    for ch in str(value):
        if _unsafe_char(ch):
            cp = ord(ch)
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\u{{{cp:x}}}")
        else:
            out.append(ch)
    return "".join(out)


def _visible(ch):
    cp = ord(ch)
    return not (cp in _WHITE_SPACE or unicodedata.category(ch) in ("Cc", "Cf") or _ignorable(cp))


def valid_scalars(value):
    return not any(0xD800 <= ord(c) <= 0xDFFF for c in value)


def has_visible_prose(value):
    return isinstance(value, str) and valid_scalars(value) and any(_visible(c) for c in value)


def type_of(v):
    if isinstance(v, bool):
        return "boolean"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def is_integer(v):
    return type_of(v) == "number" and (isinstance(v, int) or float(v).is_integer())


def safe_quote(value):
    if isinstance(value, str):
        clipped = value[:MAX_DIAGNOSTIC_STRING_LENGTH] + "..." if len(value) > MAX_DIAGNOSTIC_STRING_LENGTH else value
        s = json.dumps(clipped, ensure_ascii=False)
    elif value is None or isinstance(value, bool):
        s = "null" if value is None else ("true" if value else "false")
    elif isinstance(value, (int, float)):
        s = _num(value)
    else:
        s = f'"<{type_of(value)}>"'
    return escape_unsafe(s)


def _num(v):
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def prop_path(base, key):
    return f"{base}.{key}" if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) else f"{base}[{safe_quote(key)}]"


def deep_equal(a, b):
    if type_of(a) != type_of(b):
        return False
    if isinstance(a, list):
        return len(a) == len(b) and all(deep_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(deep_equal(a[k], b[k]) for k in a)
    if type_of(a) == "number":
        return float(a) == float(b)
    return a == b


def canonical_key(value):
    chunks, size = [], [0]

    def append(chunk):
        size[0] += len(chunk.encode("utf-8", "surrogatepass"))
        if size[0] > LIMITS["canonicalKeyBytes"]:
            raise ValueError(f"canonical key exceeds {LIMITS['canonicalKeyBytes']} byte limit")
        chunks.append(chunk)

    def enc(item):
        t = type_of(item)
        if t == "null":
            append("null")
        elif t == "string":
            append("string:" + json.dumps(item))
        elif t == "number":
            append("number:" + _num(item))
        elif t == "boolean":
            append("boolean:" + ("true" if item else "false"))
        elif t == "array":
            append("array:[")
            for i, e in enumerate(item):
                if i:
                    append(",")
                enc(e)
            append("]")
        else:
            append("object:{")
            for i, k in enumerate(sorted(item)):
                if i:
                    append(",")
                append(json.dumps(k))
                append(":")
                enc(item[k])
            append("}")

    enc(value)
    return "".join(chunks), size[0]


def data_limit_errors(value, location="$data"):
    stack = [(value, location, 1 if isinstance(value, (list, dict)) else 0)]
    while stack:
        cur, loc, depth = stack.pop()
        if not isinstance(cur, (list, dict)):
            continue
        if depth > LIMITS["nestingDepth"]:
            return [escape_unsafe(f"{loc}: exceeds {LIMITS['nestingDepth']} level nesting depth limit")]
        if isinstance(cur, list):
            if len(cur) > LIMITS["arrayItems"]:
                return [escape_unsafe(f"{loc}: exceeds {LIMITS['arrayItems']} item array limit")]
            for i in range(len(cur) - 1, -1, -1):
                if isinstance(cur[i], (list, dict)):
                    stack.append((cur[i], f"{loc}[{i}]", depth + 1))
        else:
            for k in reversed(list(cur)):
                if isinstance(cur[k], (list, dict)):
                    stack.append((cur[k], prop_path(loc, k), depth + 1))
    return []


def schema_errors(schema, location="schema"):
    errors = LimitedErrors()

    def check(node, p):
        if not isinstance(node, dict):
            errors.push(f"{p}: schema must be an object")
            return
        for k in node:
            if k not in SUPPORTED_KEYWORDS:
                errors.push(f"{p}: unsupported schema keyword {safe_quote(k)}")
        if "$comment" in node and not isinstance(node["$comment"], str):
            errors.push(f"{p}.$comment: expected string")
        if "description" in node and not isinstance(node["description"], str):
            errors.push(f"{p}.description: expected string")
        if "type" in node and node["type"] not in SUPPORTED_TYPES:
            errors.push(f"{p}.type: unsupported type {safe_quote(node['type'])}")
        if "properties" in node:
            if not isinstance(node["properties"], dict):
                errors.push(f"{p}.properties: expected object")
            else:
                for k, sub in node["properties"].items():
                    check(sub, prop_path(f"{p}.properties", k))
        if "required" in node:
            req = node["required"]
            if not isinstance(req, list) or any(not isinstance(k, str) for k in req):
                errors.push(f"{p}.required: expected an array of strings")
            elif len(set(req)) != len(req):
                errors.push(f"{p}.required: entries must be unique")
        if "additionalProperties" in node and not isinstance(node["additionalProperties"], bool):
            errors.push(f"{p}.additionalProperties: only boolean values are supported")
        if "enum" in node:
            if not isinstance(node["enum"], list) or not node["enum"]:
                errors.push(f"{p}.enum: expected a non-empty array")
            else:
                seen = set()
                for v in node["enum"]:
                    k = canonical_key(v)[0]
                    if k in seen:
                        errors.push(f"{p}.enum: entries must be unique")
                        break
                    seen.add(k)
        if "items" in node:
            check(node["items"], f"{p}.items")
        for kw in ("minItems", "minLength"):
            if kw in node and (not is_integer(node[kw]) or node[kw] < 0):
                errors.push(f"{p}.{kw}: expected a non-negative integer")
        if "minimum" in node and type_of(node["minimum"]) != "number":
            errors.push(f"{p}.minimum: expected a finite number")
        if "pattern" in node:
            if not isinstance(node["pattern"], str):
                errors.push(f"{p}.pattern: expected string")
            else:
                try:
                    re.compile(node["pattern"])
                except re.error:
                    errors.push(f"{p}.pattern: invalid regular expression")
        if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
            errors.push(f"{p}.uniqueItems: expected boolean")
        if "visibleContent" in node:
            if not isinstance(node["visibleContent"], bool):
                errors.push(f"{p}.visibleContent: expected boolean")
            elif node["visibleContent"] and node.get("type") != "string":
                errors.push(f'{p}.visibleContent: requires type "string"')
        if "oneOf" in node:
            if not isinstance(node["oneOf"], list) or not node["oneOf"]:
                errors.push(f"{p}.oneOf: expected a non-empty array")
            else:
                for i, b in enumerate(node["oneOf"]):
                    check(b, f"{p}.oneOf[{i}]")

    check(schema, location)
    return errors


def discriminator(schema):
    for k, sub in (schema.get("properties") or {}).items():
        if isinstance(sub, dict) and "const" in sub:
            return k, sub["const"]
    return None


def validate(value, schema, p, errors):
    if len(errors) >= LIMITS["validationErrors"]:
        return
    if "oneOf" in schema:
        results = [collect_unchecked(value, b, p) for b in schema["oneOf"]]
        passing = [i for i, r in enumerate(results) if not r]
        if len(passing) != 1:
            errors.push(f"{p}: must match exactly one schema in oneOf; matched {len(passing)}")
            if not passing and isinstance(value, dict):
                hits = [i for i, b in enumerate(schema["oneOf"])
                        if (d := discriminator(b)) and d[0] in value and deep_equal(value[d[0]], d[1])]
                if len(hits) == 1:
                    errors.push(*results[hits[0]])
    if "const" in schema and not deep_equal(value, schema["const"]):
        errors.push(f"{p}: must equal {safe_quote(schema['const'])}, got {safe_quote(value)}")
    if "enum" in schema and not any(deep_equal(value, a) for a in schema["enum"]):
        allowed = ", ".join(safe_quote(a) for a in schema["enum"])
        errors.push(f"{p}: invalid value {safe_quote(value)} (expected one of {allowed})")
    if "type" in schema:
        t = type_of(value)
        ok = t == schema["type"] or (schema["type"] == "integer" and is_integer(value))
        if not ok:
            errors.push(f"{p}: expected {schema['type']}, got {t}")
            return
    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                errors.push(f"{p}: missing required field {safe_quote(req)}")
        for k, v in value.items():
            if k in (schema.get("properties") or {}):
                validate(v, schema["properties"][k], prop_path(p, k), errors)
            elif schema.get("additionalProperties") is False:
                errors.push(f"{p}: unexpected field {safe_quote(k)}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.push(f"{p}: must have at least {schema['minItems']} item(s), got {len(value)}")
        if schema.get("uniqueItems") is True:
            seen, total = set(), 0
            for i, item in enumerate(value):
                try:
                    k, size = canonical_key(item)
                except ValueError as e:
                    errors.push(f"{p}[{i}]: {e}")
                    break
                if k in seen:
                    errors.push(f"{p}: items must be unique; duplicate at index {i}")
                    continue
                total += size
                if total > LIMITS["uniqueSetBytes"]:
                    errors.push(f"{p}: canonical uniqueness set exceeds {LIMITS['uniqueSetBytes']} byte limit")
                    break
                seen.add(k)
        if "items" in schema:
            for i, item in enumerate(value):
                validate(item, schema["items"], f"{p}[{i}]", errors)
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.push(f"{p}: must have at least {schema['minLength']} character(s)")
        if schema.get("visibleContent") is True:
            if not valid_scalars(value):
                errors.push(f"{p}: must contain only valid Unicode scalar values")
            elif not any(_visible(c) for c in value):
                errors.push(f"{p}: must contain a visible character")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.push(f"{p}: must match pattern {json.dumps(schema['pattern'])}")
    if type_of(value) == "number" and "minimum" in schema and value < schema["minimum"]:
        errors.push(f"{p}: must be at least {_num(schema['minimum'])}, got {_num(value)}")


def collect_unchecked(value, schema, p):
    errors = LimitedErrors()
    validate(value, schema, p, errors)
    return errors


def is_safe_relative_source_path(value):
    if not isinstance(value, str) or not value or not valid_scalars(value) or value.strip() != value:
        return False
    if any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") or _ignorable(ord(c)) for c in value):
        return False
    if "\\" in value or ":" in value or value.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", value):
        return False
    return all(seg not in ("", ".", "..") and not re.search(r"[ .]$", seg) and not WINDOWS_RESERVED_COMPONENT.match(seg)
               for seg in value.split("/"))


def finding_semantic_errors(findings):
    errors = LimitedErrors()
    if not isinstance(findings, list):
        return errors
    fingerprints, previous = {}, None
    for index, f in enumerate(findings):
        if len(errors) >= LIMITS["validationErrors"]:
            break
        if not isinstance(f, dict):
            continue
        base = f"$[{index}]"
        fp = f.get("fingerprint")
        if isinstance(fp, str):
            if fp in fingerprints:
                errors.push(f"{base}.fingerprint: duplicate of $[{fingerprints[fp]}].fingerprint")
            else:
                fingerprints[fp] = index
            if previous is not None and previous > fp:
                errors.push(f"{base}.fingerprint: findings must be sorted lexicographically")
            previous = fp
        for field in ("trace", "evidence"):
            for i, e in enumerate(f.get(field) or [] if isinstance(f.get(field), list) else []):
                if not isinstance(e, dict):
                    continue
                if "line" in e and (not is_integer(e["line"]) or e["line"] < 1):
                    errors.push(f"{base}.{field}[{i}].line: must be a positive integer")
                if "file" in e and not is_safe_relative_source_path(e["file"]):
                    errors.push(f"{base}.{field}[{i}].file: must be a safe repository-relative source path")
        rem = f.get("remediation")
        if isinstance(rem, dict) and isinstance(rem.get("code_changes"), list):
            for i, ch in enumerate(rem["code_changes"]):
                if isinstance(ch, dict) and "file_name" in ch and not is_safe_relative_source_path(ch["file_name"]):
                    errors.push(f"{base}.remediation.code_changes[{i}].file_name: must be a safe repository-relative source path")
        trace = f.get("trace")
        if isinstance(trace, list) and len(trace) == 1:
            kind = trace[0].get("kind") if isinstance(trace[0], dict) else None
            if kind not in ("entrypoint", "sink"):
                errors.push(f'{base}.trace[0].kind: a one-line trace must be "entrypoint" or "sink"')
        elif isinstance(trace, list) and len(trace) > 1:
            last = len(trace) - 1
            kinds = [t.get("kind") if isinstance(t, dict) else None for t in trace]
            if kinds[0] != "entrypoint":
                errors.push(f'{base}.trace[0].kind: must be "entrypoint", got {safe_quote(kinds[0])}')
            if kinds[last] != "sink":
                errors.push(f'{base}.trace[{last}].kind: must be "sink", got {safe_quote(kinds[last])}')
            for i in range(1, last):
                if kinds[i] != "propagation":
                    errors.push(f'{base}.trace[{i}].kind: must be "propagation", got {safe_quote(kinds[i])}')
        verdict = f.get("verdict")
        if verdict == "confirmed":
            for forbidden in ("claimed_root_cause", "blockers", "validation_plan", "reason"):
                if forbidden in f:
                    errors.push(f"{base}: confirmed finding must not contain {safe_quote(forbidden)}")
            ex = f.get("execution")
            if not isinstance(ex, dict) or not has_visible_prose(ex.get("observed_result")):
                errors.push(f"{base}: confirmed finding requires a visible execution observed_result")
            if not isinstance(rem, dict) or not has_visible_prose(rem.get("strategy")):
                errors.push(f"{base}: confirmed finding requires visible remediation")
            sev = f.get("severity") if isinstance(f.get("severity"), dict) else {}
            overall = sev.get("overall_severity")
            impact = (sev.get("impact") or {}).get("score") if isinstance(sev.get("impact"), dict) else None
            if overall in SEVERITY_RANK and impact in SEVERITY_RANK and SEVERITY_RANK[overall] > SEVERITY_RANK[impact]:
                errors.push(f"{base}.severity.overall_severity: cannot exceed demonstrated impact {safe_quote(impact)}")
        elif verdict == "needs_validation":
            if "severity" in f:
                errors.push(f'{base}: needs_validation finding must not contain "severity"')
            for forbidden in ("execution", "remediation", "reason", "root_cause", "cvss"):
                if forbidden in f:
                    errors.push(f"{base}: needs_validation finding must not contain {safe_quote(forbidden)}")
            plan = f.get("validation_plan") if isinstance(f.get("validation_plan"), dict) else {}
            if not (has_visible_prose(plan.get("local")) or has_visible_prose(plan.get("deployment"))):
                errors.push(f"{base}.validation_plan: requires at least one visible local or deployment plan")
        elif verdict == "rejected":
            for forbidden in ("severity", "execution", "remediation", "blockers", "validation_plan", "root_cause"):
                if forbidden in f:
                    errors.push(f"{base}: rejected finding must not contain {safe_quote(forbidden)}")
        errors.push(*source_errors(f, base))
    return errors


# ---------------------------------------------------------------------------------------------------
# Checks added by this skill: every finding is justified by sources that really exist.

_FILE_CACHE = {}


def _text_of(rel):
    if rel not in _FILE_CACHE:
        target = (SKILL / rel).resolve()
        if SKILL.resolve() not in target.parents:
            _FILE_CACHE[rel] = None
        elif target.is_dir():
            _FILE_CACHE[rel] = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in sorted(target.rglob("*.md")))
        elif target.is_file():
            _FILE_CACHE[rel] = target.read_text(encoding="utf-8", errors="ignore")
        else:
            _FILE_CACHE[rel] = None
    return _FILE_CACHE[rel]


def id_in_text(ident, text):
    """True if every part of an identifier appears in the text (e.g. 'RS.MA-01 R2', 'PW.7.2.R1', '§3.1.1.2')."""
    parts = ident.replace("§", " ").split()
    expanded = []
    for part in parts:
        m = re.fullmatch(r"(.+?)\.([RCN]\d+)", part)
        expanded += [m.group(1), m.group(2)] if m else [part]
    for part in expanded:
        if not re.search(r"(?<![\w.-])" + re.escape(part) + r"(?![\w-])", text):
            return False
    return True


def source_errors(f, base):
    errors = []
    verdict = f.get("verdict")
    sources = f.get("sources")
    if verdict in ("confirmed", "needs_validation") and not isinstance(sources, list):
        return errors  # the schema already reports the missing field
    if not isinstance(sources, list):
        return errors
    rel = [(s.get("relation"), s.get("tier")) for s in sources if isinstance(s, dict)]
    if verdict == "confirmed":
        if ("violated-requirement", "A") not in rel:
            errors.append(f"{base}.sources: a confirmed finding needs a tier-A \"violated-requirement\" source "
                          "(the requirement whose failure it demonstrates)")
        if not any(r == "weakness" for r, _ in rel):
            errors.append(f"{base}.sources: a confirmed finding needs a \"weakness\" source (its CWE)")
    for i, s in enumerate(sources):
        if not isinstance(s, dict) or not isinstance(s.get("file"), str) or not isinstance(s.get("id"), str):
            continue
        p = f"{base}.sources[{i}]"
        if s.get("tier") == "B":
            if s.get("relation") != "candidate-control":
                errors.append(f"{p}.relation: a tier-B source can only be a \"candidate-control\" (no text to judge against)")
            if s["file"] not in TIER_B_FILES:
                errors.append(f"{p}.file: a tier-B source must point at {' or '.join(sorted(TIER_B_FILES))}")
            continue
        text = _text_of(s["file"])
        if text is None:
            errors.append(f"{p}.file: {safe_quote(s['file'])} does not exist in this skill")
        elif not id_in_text(s["id"], text):
            errors.append(f"{p}.id: {safe_quote(s['id'])} not found in {s['file']}")
    if f.get("category") == "dependency" and not isinstance(f.get("package"), dict):
        errors.append(f"{base}: a dependency finding requires \"package\"")
    cv = f.get("cvss")
    if isinstance(cv, dict) and isinstance(cv.get("vector"), str):
        sys.path.insert(0, str(ROOT))
        import cvss4  # noqa: E402  (same folder)
        try:
            ref = cvss4.evaluate(cv["vector"])
        except ValueError as e:
            errors.append(f"{base}.cvss.vector: {e}")
        else:
            for k in ("score", "severity", "nomenclature"):
                if k in cv and not deep_equal(cv[k], ref[k]):
                    errors.append(f"{base}.cvss.{k}: {safe_quote(cv[k])} does not match scripts/cvss4.py "
                                  f"({safe_quote(ref[k])}); compute it, never estimate it")
    return errors


# ---------------------------------------------------------------------------------------------------

def validate_document(findings, schema):
    errs = schema_errors(schema)
    if errs:
        return errs
    lim = data_limit_errors(findings, "$")
    if lim:
        return lim
    errors = collect_unchecked(findings, schema, "$")
    if len(errors) < LIMITS["validationErrors"]:
        errors.push(*finding_semantic_errors(findings))
    return errors


def load_schema(path=SCHEMA):
    schema = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    errs = schema_errors(schema)
    if errs:
        raise ValueError("unsupported or invalid report schema:\n" + "\n".join(errs))
    return schema


def read_file_within_limit(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_NONBLOCK", 0):
        raise SafeInputError("OS no-follow and nonblocking input protection is unavailable")
    try:
        fd = os.open(path, flags)
    except OSError as e:
        if e.errno in (40, 31):  # ELOOP, EMLINK
            raise SafeInputError("input must not be a symlink")
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SafeInputError("input must be a regular file")
        if st.st_size > LIMITS["inputBytes"]:
            raise SafeInputError(f"input exceeds {LIMITS['inputBytes']} byte limit")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > LIMITS["inputBytes"]:
                raise SafeInputError(f"input exceeds {LIMITS['inputBytes']} byte limit")
            chunks.append(chunk)
        try:
            data = b"".join(chunks)
            return data[3:].decode("utf-8") if data.startswith(b"\xef\xbb\xbf") else data.decode("utf-8")
        except UnicodeDecodeError:
            raise SafeInputError("input is not valid UTF-8")
    finally:
        os.close(fd)


def enforce_json_text_limits(contents):
    containers, in_string, escaped = [], False, False

    def mark():
        if containers and containers[-1]["type"] == "array" and containers[-1]["expects"]:
            containers[-1]["expects"] = False
            containers[-1]["items"] += 1
            if containers[-1]["items"] > LIMITS["arrayItems"]:
                raise JsonStructureError(f"input exceeds {LIMITS['arrayItems']} item array limit")

    for ch in contents:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            mark()
            in_string = True
        elif ch in "[{":
            mark()
            if len(containers) >= LIMITS["nestingDepth"]:
                raise JsonStructureError(f"input exceeds {LIMITS['nestingDepth']} level nesting depth limit")
            containers.append({"type": "array" if ch == "[" else "object", "expects": ch == "[", "items": 0})
        elif ch in "]}":
            if containers:
                containers.pop()
        elif ch == ",":
            if containers and containers[-1]["type"] == "array":
                containers[-1]["expects"] = True
        elif not ch.isspace():
            mark()


def run(path):
    if not path:
        print("Usage: python validate_findings.py <path-to-findings.json>", file=sys.stderr)
        return 1
    try:
        schema = load_schema()
    except (OSError, ValueError) as e:
        print("Failed to load report-schema.json:", e, file=sys.stderr)
        return 1
    try:
        contents = read_file_within_limit(path)
    except SafeInputError as e:
        print(f"Failed to read findings JSON: {e}", file=sys.stderr)
        return 1
    except OSError:
        print("Failed to read findings JSON: input could not be opened or read safely", file=sys.stderr)
        return 1
    try:
        enforce_json_text_limits(contents)
    except JsonStructureError as e:
        print(f"Failed to parse findings JSON: {e}", file=sys.stderr)
        return 1
    try:
        findings = json.loads(contents)
    except ValueError:
        print("Failed to parse findings JSON: invalid JSON syntax", file=sys.stderr)
        return 1
    try:
        errors = validate_document(findings, schema)
    except Exception:  # mirror the original: never crash on hostile input
        print("Failed to validate findings JSON: unexpected validation error", file=sys.stderr)
        return 1
    for m in errors:
        print("ERROR:", escape_unsafe(m), file=sys.stderr)
    if errors:
        cap = f"; output capped at {LIMITS['validationErrors']}" if len(errors) == LIMITS["validationErrors"] else ""
        print(f"FAIL: {len(errors)} validation error(s){cap}", file=sys.stderr)
        return 1
    print(f"PASS: {len(findings)} findings valid")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else None))
