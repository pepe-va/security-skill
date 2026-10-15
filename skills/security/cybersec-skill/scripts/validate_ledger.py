#!/usr/bin/env python3
"""Validate coverage-ledger.json and its canonical coverage IDs.

Usage: python validate_ledger.py <path-to-coverage-ledger.json>

A Python port of security-audit-skill's validate-coverage-ledger.cjs (MIT, Cloudflare). It shares the
safe-input, diagnostic-quoting, visible-prose and safe-path helpers with validate_findings.py, as the
original shares them with validate-findings.cjs.
"""
import json, re, sys, unicodedata
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from validate_findings import (SafeInputError, escape_unsafe, has_visible_prose, is_integer,  # noqa: E402
                               is_safe_relative_source_path as is_safe_relative_path, read_file_within_limit,
                               safe_quote, _ignorable)

LIMITS = {"inputBytes": 5 * 1024 * 1024, "units": 10000, "collectionItems": 1000, "objectFields": 1000,
          "nestingDepth": 64, "preflightValues": 500000, "validationErrors": 100}
MAX_TEXT_LENGTH = 4096
REQUIRED_FIELDS = ["coverage_id", "canonical_refs", "surface", "boundary", "subsystem", "attack_class", "starting_paths",
                   "ordinary_attack_class_block", "selected_companion_blocks", "excluded_blocks", "prior_status",
                   "attempts", "wave", "status", "agent_id", "reviewed_paths", "local_checks", "result_fingerprints",
                   "unresolved"]
REF_FIELDS = ["surface", "boundary", "subsystem", "attack_class"]
STATUSES = {"planned", "not_applicable", "out_of_scope", "in_progress", "covered", "candidate", "blocked", "deferred"}
ATTEMPT_STATUSES = {"covered", "candidate", "blocked"}
ATTEMPT_FIELDS = ["wave", "status", "agent_id", "reviewed_paths", "local_checks", "result_fingerprints", "unresolved",
                  "reassignment_reason"]
PRIOR_STATUSES = {"new", "prior_confirmed_same_source", "prior_confirmed_changed_source", "prior_needs_validation",
                  "prior_deferred", "prior_blocked", "prior_out_of_scope", "prior_covered_same_source",
                  "prior_covered_changed_source", "prior_rejected_claim_changed", "none"}
FINGERPRINT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
WINDOWS_RESERVED_AGENT_ID = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$")


class JsonStructureError(Exception):
    pass


class Errors(list):
    def push(self, *messages):
        remaining = LIMITS["validationErrors"] - len(self)
        if remaining > 0:
            self.extend(escape_unsafe(m) for m in messages[:remaining])
        return len(self)


def preflight_json_text(contents):
    """Structural pre-parse with the original's limits (units, items, fields, depth, total values)."""
    containers, root_state, in_string, escaped, total = [], "value", False, False, 0

    def fail(msg):
        raise JsonStructureError(f"input {msg}")

    def count():
        nonlocal total
        total += 1
        if total > LIMITS["preflightValues"]:
            fail(f"exceeds {LIMITS['preflightValues']} total value limit")

    def begin_value():
        nonlocal root_state
        c = containers[-1] if containers else None
        if c is None:
            if root_state != "value":
                fail("has malformed JSON structure")
            root_state = "end"
        elif c["type"] == "array":
            if c["state"] not in ("firstValueOrEnd", "value"):
                fail("has malformed JSON array structure")
            c["items"] += 1
            limit = LIMITS["units"] if c["top"] else LIMITS["collectionItems"]
            if c["items"] > limit:
                fail(f"exceeds {limit} top-level unit limit" if c["top"] else f"exceeds {limit} item array limit")
            c["state"] = "commaOrEnd"
        else:
            if c["state"] != "value":
                fail("has malformed JSON object structure")
            c["state"] = "commaOrEnd"
        count()

    i, n = 0, len(contents)
    while i < n:
        ch = contents[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch in " \t\r\n":
            i += 1
            continue
        if ch == '"':
            c = containers[-1] if containers else None
            if c and c["type"] == "object" and c["state"] in ("firstKeyOrEnd", "key"):
                c["fields"] += 1
                if c["fields"] > LIMITS["objectFields"]:
                    fail(f"exceeds {LIMITS['objectFields']} field object limit")
                c["state"] = "colon"
            else:
                begin_value()
            in_string = True
        elif ch in "[{":
            begin_value()
            if len(containers) >= LIMITS["nestingDepth"]:
                fail(f"exceeds nesting depth limit {LIMITS['nestingDepth']}")
            containers.append({"type": "array", "state": "firstValueOrEnd", "items": 0, "top": not containers}
                              if ch == "[" else {"type": "object", "state": "firstKeyOrEnd", "fields": 0})
        elif ch in "]}":
            t = "array" if ch == "]" else "object"
            c = containers[-1] if containers else None
            if not c or c["type"] != t:
                fail("has mismatched JSON containers")
            ok = c["state"] in (("firstValueOrEnd", "commaOrEnd") if t == "array" else ("firstKeyOrEnd", "commaOrEnd"))
            if not ok:
                fail(f"has malformed JSON {t} structure")
            containers.pop()
        elif ch == ":":
            c = containers[-1] if containers else None
            if not c or c["type"] != "object" or c["state"] != "colon":
                fail("has malformed JSON object structure")
            c["state"] = "value"
        elif ch == ",":
            c = containers[-1] if containers else None
            if not c or c["state"] != "commaOrEnd":
                fail("has malformed JSON collection structure")
            c["state"] = "value" if c["type"] == "array" else "key"
        else:
            begin_value()
            while i + 1 < n and contents[i + 1] not in ' \t\r\n,:[]{}"':
                i += 1
        i += 1
    if in_string:
        fail("has an unterminated JSON string")
    if containers:
        fail("has truncated JSON structure")
    if root_state != "end":
        fail("has no JSON value")


def preflight_document(root):
    errors = Errors()
    stack, visited = [(root, 0, "$")], 0
    while stack:
        value, depth, loc = stack.pop()
        visited += 1
        if visited > LIMITS["preflightValues"]:
            errors.push(f"$: exceeds {LIMITS['preflightValues']} total values")
            return errors
        if not isinstance(value, (list, dict)):
            continue
        if depth >= LIMITS["nestingDepth"]:
            errors.push(f"{loc}: exceeds nesting depth limit {LIMITS['nestingDepth']}")
            return errors
        if isinstance(value, list):
            limit = LIMITS["units"] if loc == "$" else LIMITS["collectionItems"]
            if len(value) > limit:
                errors.push(f"{loc}: exceeds {limit} entries")
                return errors
            for i in range(len(value) - 1, -1, -1):
                stack.append((value[i], depth + 1, f"{loc}[{i}]"))
            continue
        keys = list(value)
        if len(keys) > LIMITS["objectFields"]:
            errors.push(f"{loc}: exceeds {LIMITS['objectFields']} object fields")
            return errors
        for i in range(len(keys) - 1, -1, -1):
            stack.append((value[keys[i]], depth + 1, f"{loc}{{{i}}}"))
    return errors


def is_visible_text(value, max_length=MAX_TEXT_LENGTH):
    return isinstance(value, str) and 0 < len(value) <= max_length and value.strip() == value and has_visible_prose(value)


def _path_forbidden(value):
    return any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") or _ignorable(ord(c)) for c in value)


def is_canonical_ref(value):
    return is_visible_text(value, 1024) and not _path_forbidden(value) and unicodedata.normalize("NFC", value) == value


def encode_canonical_ref(value):
    if not is_canonical_ref(value):
        raise TypeError("invalid canonical reference")
    out = []
    for b in value.encode("utf-8"):
        unreserved = 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A or 0x30 <= b <= 0x39 or b in (0x2D, 0x2E, 0x5F, 0x7E)
        out.append(chr(b) if unreserved else f"%{b:02X}")
    return "".join(out)


def canonical_coverage_id(refs):
    if not isinstance(refs, dict):
        raise TypeError("canonical_refs must be an object")
    fields = REF_FIELDS + ["lifecycle"] if "lifecycle" in refs else REF_FIELDS
    if len(refs) != len(fields) or any(f not in refs for f in fields):
        raise TypeError("canonical_refs has missing or unexpected fields")
    return "::".join(encode_canonical_ref(refs[f]) for f in fields)


def is_safe_agent_id(value):
    return isinstance(value, str) and bool(AGENT_ID.match(value)) and not WINDOWS_RESERVED_AGENT_ID.match(value)


def is_owned_artifact_path(value, agent_id):
    if not is_safe_agent_id(agent_id) or not is_safe_relative_path(value):
        return False
    prefix = f"agents/{agent_id}/artifacts/"
    return value.startswith(prefix) and len(value) > len(prefix)


def validate_string_array(value, loc, errors, allow_empty=True, fingerprint=False, path_value=False):
    if not isinstance(value, list):
        errors.push(f"{loc}: expected array")
        return
    if not allow_empty and not value:
        errors.push(f"{loc}: must not be empty")
    if len(value) > LIMITS["collectionItems"]:
        errors.push(f"{loc}: exceeds {LIMITS['collectionItems']} entries")
    seen = set()
    for i, entry in enumerate(value[:LIMITS["collectionItems"]]):
        valid = is_safe_relative_path(entry) if path_value else is_visible_text(entry)
        if not valid:
            errors.push(f"{loc}[{i}]: invalid {'repository-relative path' if path_value else 'text'}")
        if fingerprint and isinstance(entry, str) and not FINGERPRINT.match(entry):
            errors.push(f"{loc}[{i}]: invalid fingerprint")
        if isinstance(entry, str) and entry in seen:
            errors.push(f"{loc}[{i}]: duplicate entry")
        if isinstance(entry, str):
            seen.add(entry)


def validate_checks(value, loc, errors):
    if not isinstance(value, list):
        errors.push(f"{loc}: expected array")
        return
    if len(value) > LIMITS["collectionItems"]:
        errors.push(f"{loc}: exceeds {LIMITS['collectionItems']} entries")
    for i, check in enumerate(value[:LIMITS["collectionItems"]]):
        base = f"{loc}[{i}]"
        if not isinstance(check, dict):
            errors.push(f"{base}: expected object")
            continue
        for field in ("agent_id", "reviewed_paths", "invariant", "method", "result", "artifact"):
            if field not in check:
                errors.push(f"{base}: missing required field {safe_quote(field)}")
        if not is_safe_agent_id(check.get("agent_id")):
            errors.push(f"{base}.agent_id: expected a canonical lowercase agent ID")
        validate_string_array(check.get("reviewed_paths"), f"{base}.reviewed_paths", errors, allow_empty=False, path_value=True)
        if not is_visible_text(check.get("invariant")):
            errors.push(f"{base}.invariant: invalid text")
        method = check.get("method")
        if method not in ("source", "local"):
            errors.push(f'{base}.method: expected "source" or "local"')
        if not is_visible_text(check.get("result")):
            errors.push(f"{base}.result: invalid text")
        if method == "source" and check.get("artifact") is not None:
            errors.push(f"{base}.artifact: source-only check must use null")
        elif method == "local":
            if not is_owned_artifact_path(check.get("artifact"), check.get("agent_id")):
                owner = check.get("agent_id") if is_safe_agent_id(check.get("agent_id")) else "<agent-id>"
                errors.push(f"{base}.artifact: local check requires an artifact owned by agent {safe_quote(owner)}")
        elif method not in ("source", "local") and check.get("artifact") is not None and not is_safe_relative_path(check.get("artifact")):
            errors.push(f"{base}.artifact: expected null or a safe output-relative path")


def validate_reviewed_path_ownership(unit, base, errors):
    if not isinstance(unit.get("reviewed_paths"), list) or not isinstance(unit.get("local_checks"), list):
        return
    aggregate = {v for v in unit["reviewed_paths"] if isinstance(v, str)}
    owned = {p for c in unit["local_checks"] if isinstance(c, dict) and isinstance(c.get("reviewed_paths"), list)
             for p in c["reviewed_paths"] if isinstance(p, str)}
    for p in sorted(aggregate - owned):
        errors.push(f"{base}.reviewed_paths: {safe_quote(p)} has no check owner")
    for p in sorted(owned - aggregate):
        errors.push(f"{base}.local_checks: owned path {safe_quote(p)} is absent from aggregate reviewed_paths")


def validate_excluded_blocks(value, loc, errors):
    if not isinstance(value, list):
        errors.push(f"{loc}: expected array")
        return
    if len(value) > LIMITS["collectionItems"]:
        errors.push(f"{loc}: exceeds {LIMITS['collectionItems']} entries")
    seen = set()
    for i, entry in enumerate(value[:LIMITS["collectionItems"]]):
        base = f"{loc}[{i}]"
        if not isinstance(entry, dict):
            errors.push(f"{base}: expected object")
            continue
        if not is_visible_text(entry.get("block")):
            errors.push(f"{base}.block: invalid text")
        if not is_visible_text(entry.get("reason")):
            errors.push(f"{base}.reason: invalid text")
        if isinstance(entry.get("block"), str) and entry["block"] in seen:
            errors.push(f"{base}.block: duplicate entry")
        if isinstance(entry.get("block"), str):
            seen.add(entry["block"])


def semantic_key(unit):
    return json.dumps([unit.get("surface"), unit.get("boundary"), unit.get("subsystem"), unit.get("attack_class"),
                       unit.get("lifecycle") if "lifecycle" in unit else None])


def has_valid_semantic_fields(unit):
    return all(is_visible_text(unit.get(f)) for f in REF_FIELDS) and ("lifecycle" not in unit or is_visible_text(unit["lifecycle"]))


def require_empty(unit, field, base, errors):
    if isinstance(unit.get(field), list) and unit[field]:
        errors.push(f"{base}.{field}: unit with status {safe_quote(unit.get('status'))} must keep this array empty")


def require_nonempty(unit, field, base, errors):
    if not isinstance(unit.get(field), list) or not unit[field]:
        errors.push(f"{base}.{field}: unit with status {safe_quote(unit.get('status'))} requires entries")


def validate_state_invariants(unit, base, errors):
    status = unit.get("status")

    def empty_evidence():
        require_empty(unit, "reviewed_paths", base, errors)
        require_empty(unit, "local_checks", base, errors)

    def require_owner():
        if not is_safe_agent_id(unit.get("agent_id")):
            errors.push(f"{base}.agent_id: unit with status {safe_quote(status)} requires a canonical lowercase agent ID")

    if status != "candidate":
        require_empty(unit, "result_fingerprints", base, errors)
    if status == "planned":
        if unit.get("agent_id") is not None:
            errors.push(f"{base}.agent_id: planned unit must be unassigned")
        empty_evidence()
        require_empty(unit, "unresolved", base, errors)
    elif status in ("not_applicable", "out_of_scope", "deferred"):
        if unit.get("agent_id") is not None:
            errors.push(f"{base}.agent_id: unit with status {safe_quote(status)} must be unassigned")
        empty_evidence()
        require_nonempty(unit, "unresolved", base, errors)
    elif status == "in_progress":
        require_owner()
        empty_evidence()
        require_empty(unit, "unresolved", base, errors)
    elif status == "blocked":
        require_owner()
        for f in ("reviewed_paths", "local_checks", "unresolved"):
            require_nonempty(unit, f, base, errors)
    elif status == "covered":
        require_owner()
        require_nonempty(unit, "reviewed_paths", base, errors)
        require_nonempty(unit, "local_checks", base, errors)
        require_empty(unit, "unresolved", base, errors)
    elif status == "candidate":
        require_owner()
        for f in ("reviewed_paths", "local_checks", "result_fingerprints"):
            require_nonempty(unit, f, base, errors)


def validate_attempts(value, unit, base, errors):
    if not isinstance(value, list):
        errors.push(f"{base}.attempts: expected array")
        return
    if len(value) > LIMITS["collectionItems"]:
        errors.push(f"{base}.attempts: exceeds {LIMITS['collectionItems']} entries")
    prior_owners, prior_artifacts, previous_wave = set(), set(), 0
    for i, attempt in enumerate(value[:LIMITS["collectionItems"]]):
        ab = f"{base}.attempts[{i}]"
        if not isinstance(attempt, dict):
            errors.push(f"{ab}: expected object")
            continue
        for field in ATTEMPT_FIELDS:
            if field not in attempt:
                errors.push(f"{ab}: missing required field {safe_quote(field)}")
        wave = attempt.get("wave")
        if not is_integer(wave) or wave < 1:
            errors.push(f"{ab}.wave: expected a positive integer")
        else:
            if wave <= previous_wave:
                errors.push(f"{ab}.wave: archived attempt waves must be strictly increasing")
            if is_integer(unit.get("wave")) and wave >= unit["wave"]:
                errors.push(f"{ab}.wave: archived attempt wave must precede current wave {safe_quote(unit['wave'])}")
            previous_wave = wave
        if attempt.get("status") not in ATTEMPT_STATUSES:
            errors.push(f'{ab}.status: expected "covered", "candidate", or "blocked"')
        fresh = False
        if not is_safe_agent_id(attempt.get("agent_id")):
            errors.push(f"{ab}.agent_id: archived attempt requires a canonical lowercase agent ID")
        elif attempt["agent_id"] in prior_owners:
            errors.push(f"{ab}.agent_id: assignment owner must be fresh for each attempt")
        else:
            fresh = True
        validate_string_array(attempt.get("reviewed_paths"), f"{ab}.reviewed_paths", errors, path_value=True)
        validate_checks(attempt.get("local_checks"), f"{ab}.local_checks", errors)
        validate_reviewed_path_ownership(attempt, ab, errors)
        validate_string_array(attempt.get("result_fingerprints"), f"{ab}.result_fingerprints", errors, fingerprint=True)
        validate_string_array(attempt.get("unresolved"), f"{ab}.unresolved", errors)
        if not is_visible_text(attempt.get("reassignment_reason")):
            errors.push(f"{ab}.reassignment_reason: invalid text")
        validate_state_invariants(attempt, ab, errors)
        for ci, check in enumerate(attempt.get("local_checks") if isinstance(attempt.get("local_checks"), list) else []):
            if not isinstance(check, dict):
                continue
            if check.get("agent_id") in prior_owners:
                errors.push(f"{ab}.local_checks[{ci}].agent_id: prior assignment owner evidence must remain in its earlier attempt")
            if isinstance(check.get("artifact"), str) and check["artifact"] in prior_artifacts:
                errors.push(f"{ab}.local_checks[{ci}].artifact: artifact from an earlier attempt cannot be reused")
            if check.get("method") == "local" and isinstance(check.get("artifact"), str):
                prior_artifacts.add(check["artifact"])
        if fresh:
            prior_owners.add(attempt["agent_id"])
    if is_safe_agent_id(unit.get("agent_id")) and unit["agent_id"] in prior_owners:
        errors.push(f"{base}.agent_id: current assignment owner must be fresh after reassignment")
    for ci, check in enumerate(unit.get("local_checks") if isinstance(unit.get("local_checks"), list) else []):
        if not isinstance(check, dict):
            continue
        if check.get("agent_id") in prior_owners:
            errors.push(f"{base}.local_checks[{ci}].agent_id: prior assignment owner evidence must remain in its archived attempt")
        if isinstance(check.get("artifact"), str) and check["artifact"] in prior_artifacts:
            errors.push(f"{base}.local_checks[{ci}].artifact: artifact from an archived attempt cannot be reused")


def unit_errors(unit, index):
    errors = Errors()
    base = f"$[{index}]"
    if not isinstance(unit, dict):
        return [f"{base}: expected object"]
    for field in REQUIRED_FIELDS:
        if field not in unit:
            errors.push(f"{base}: missing required field {safe_quote(field)}")
    for field in REF_FIELDS:
        if not is_visible_text(unit.get(field)):
            errors.push(f"{base}.{field}: invalid text")
    if "lifecycle" in unit and not is_visible_text(unit["lifecycle"]):
        errors.push(f"{base}.lifecycle: invalid text")
    expected = None
    refs = unit.get("canonical_refs")
    if not isinstance(refs, dict):
        errors.push(f"{base}.canonical_refs: expected object")
    else:
        fields = REF_FIELDS + ["lifecycle"] if "lifecycle" in refs else REF_FIELDS
        for f in fields:
            if f not in refs:
                errors.push(f"{base}.canonical_refs: missing required field {safe_quote(f)}")
            elif not is_canonical_ref(refs[f]):
                errors.push(f"{base}.canonical_refs.{f}: invalid canonical reference")
        if any(f not in fields for f in refs):
            errors.push(f"{base}.canonical_refs: contains unexpected fields")
        if ("lifecycle" in unit) != ("lifecycle" in refs):
            errors.push(f"{base}: lifecycle and canonical_refs.lifecycle must appear together")
        try:
            expected = canonical_coverage_id(refs)
        except TypeError:
            pass
    if not is_visible_text(unit.get("coverage_id"), 65536):
        errors.push(f"{base}.coverage_id: invalid text")
    elif expected is not None and unit["coverage_id"] != expected:
        errors.push(f"{base}.coverage_id: expected canonical ID {safe_quote(expected)}")
    validate_string_array(unit.get("starting_paths"), f"{base}.starting_paths", errors, allow_empty=False, path_value=True)
    if unit.get("ordinary_attack_class_block") is not None and not is_visible_text(unit.get("ordinary_attack_class_block")):
        errors.push(f"{base}.ordinary_attack_class_block: expected null or non-empty text")
    validate_string_array(unit.get("selected_companion_blocks"), f"{base}.selected_companion_blocks", errors)
    validate_excluded_blocks(unit.get("excluded_blocks"), f"{base}.excluded_blocks", errors)
    if isinstance(unit.get("selected_companion_blocks"), list) and isinstance(unit.get("excluded_blocks"), list):
        selected = {b for b in unit["selected_companion_blocks"] if isinstance(b, str)}
        for bi, entry in enumerate(unit["excluded_blocks"]):
            if isinstance(entry, dict) and entry.get("block") in selected:
                errors.push(f"{base}.excluded_blocks[{bi}].block: block is also selected")
    if unit.get("prior_status") not in PRIOR_STATUSES:
        errors.push(f"{base}.prior_status: invalid value {safe_quote(unit.get('prior_status'))}")
    if unit.get("status") not in STATUSES:
        errors.push(f"{base}.status: invalid value {safe_quote(unit.get('status'))}")
    if not is_integer(unit.get("wave")) or unit["wave"] < 1:
        errors.push(f"{base}.wave: expected a positive integer")
    if unit.get("agent_id") is not None and not is_safe_agent_id(unit.get("agent_id")):
        errors.push(f"{base}.agent_id: expected null or a safe agent ID")
    validate_attempts(unit.get("attempts"), unit, base, errors)
    validate_string_array(unit.get("reviewed_paths"), f"{base}.reviewed_paths", errors, path_value=True)
    validate_checks(unit.get("local_checks"), f"{base}.local_checks", errors)
    validate_reviewed_path_ownership(unit, base, errors)
    validate_string_array(unit.get("result_fingerprints"), f"{base}.result_fingerprints", errors, fingerprint=True)
    validate_string_array(unit.get("unresolved"), f"{base}.unresolved", errors)
    validate_state_invariants(unit, base, errors)
    return errors


def validate_document(ledger):
    errors = Errors()
    if not isinstance(ledger, list):
        errors.push("$: expected a top-level array")
        return errors
    if len(ledger) > LIMITS["units"]:
        errors.push(f"$: exceeds {LIMITS['units']} coverage units")
        return errors
    errors.push(*preflight_document(ledger))
    if errors:
        return errors
    ids, semantics, previous = {}, {}, None
    for index, unit in enumerate(ledger):
        if len(errors) >= LIMITS["validationErrors"]:
            break
        errors.push(*unit_errors(unit, index))
        if len(errors) >= LIMITS["validationErrors"]:
            break
        if not isinstance(unit, dict) or not isinstance(unit.get("coverage_id"), str):
            continue
        key = semantic_key(unit) if has_valid_semantic_fields(unit) else None
        cid = unit["coverage_id"]
        if cid in ids:
            prev = ids[cid]
            qualifier = ("canonical identity collision with different semantic fields"
                         if key is not None and prev[1] is not None and prev[1] != key else "duplicate coverage ID")
            errors.push(f"$[{index}].coverage_id: {qualifier} at $[{prev[0]}]")
        else:
            ids[cid] = (index, key)
        if key is not None and key in semantics and semantics[key][0] != cid:
            errors.push(f"$[{index}].canonical_refs: semantic tuple already uses coverage ID {safe_quote(semantics[key][0])} at $[{semantics[key][1]}]")
        elif key is not None:
            semantics[key] = (cid, index)
        if previous is not None and previous > cid:
            errors.push(f"$[{index}].coverage_id: units must be sorted lexicographically")
        previous = cid
    return errors


def run(path):
    if not path:
        print("Usage: python validate_ledger.py <path-to-coverage-ledger.json>", file=sys.stderr)
        return 1
    try:
        contents = read_file_within_limit(path)
    except SafeInputError as e:
        print(f"Failed to read coverage ledger: {e}", file=sys.stderr)
        return 1
    except OSError:
        print("Failed to read coverage ledger: input could not be opened or read safely", file=sys.stderr)
        return 1
    try:
        preflight_json_text(contents)
    except JsonStructureError as e:
        print(f"Failed to parse coverage ledger: {e}", file=sys.stderr)
        return 1
    try:
        ledger = json.loads(contents)
    except ValueError:
        print("Failed to parse coverage ledger: invalid JSON syntax", file=sys.stderr)
        return 1
    try:
        errors = validate_document(ledger)
    except Exception:
        print("Failed to validate coverage ledger: unexpected validation error", file=sys.stderr)
        return 1
    for m in errors:
        print("ERROR:", m, file=sys.stderr)
    if errors:
        cap = f"; output capped at {LIMITS['validationErrors']}" if len(errors) == LIMITS["validationErrors"] else ""
        print(f"FAIL: {len(errors)} validation error(s){cap}", file=sys.stderr)
        return 1
    print(f"PASS: {len(ledger)} coverage units valid")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else None))
