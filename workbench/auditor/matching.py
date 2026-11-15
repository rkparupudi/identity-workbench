"""Link each account to at most one person.

Every account ends in one of three bands:
  matched   - linked to a person (exact key, saved decision, or a very high fuzzy score)
  review    - a plausible person exists but a human should confirm
  unmatched - no plausible person

Order of evidence: saved decision, employee ID, email, custom keys, username
equal to the person's email local part, then fuzzy scoring within blocks.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from rapidfuzz import fuzz

from ..core.normalize import fold, local_part


@dataclass
class Match:
    account_key: str
    person_key: str | None
    band: str
    score: float
    method: str
    detail: dict = field(default_factory=dict)


def _person_name(p: dict) -> str:
    return fold(f"{p['first_name']} {p['last_name']}") or fold(p["display_name"])


def _account_name(a: dict) -> str:
    name = fold(a["display_name"]) or fold(f"{a['first_name']} {a['last_name']}")
    if name:
        return name
    return ""


def _user_tokens(a: dict) -> list[str]:
    local = re.sub(r"\d+$", "", local_part(a["username"]))
    return [t for t in re.split(r"[._\-\s]+", local) if t]


def _username_patterns(p: dict) -> list[str]:
    first, last = fold(p["first_name"]).replace(" ", ""), fold(p["last_name"]).replace(" ", "")
    if not first or not last:
        return [x for x in (first, last) if x]
    return [first + last, first[0] + last, first + last[0], last + first, last + first[0]]


def _block_keys_person(p: dict) -> set[str]:
    first, last = fold(p["first_name"]).split(" ")[0], fold(p["last_name"]).replace(" ", "")
    keys = set()
    if last:
        keys.add("l:" + last[:3])
    if first:
        keys.add("f:" + first[:4])
    return keys


def _block_keys_account(a: dict) -> set[str]:
    keys = set()
    name = _account_name(a).split()
    if name:
        keys.add("f:" + name[0][:4])
        keys.add("l:" + name[-1][:3])
    tokens = _user_tokens(a)
    if len(tokens) >= 2:
        keys.add("f:" + tokens[0][:4])
        keys.add("l:" + tokens[-1][:3])
        keys.add("l:" + tokens[0][:3])          # last.first conventions
    elif tokens:
        token = tokens[0]
        keys.add("l:" + token[1:4])             # jsmith
        keys.add("f:" + token[:4])              # johns / john
        keys.add("l:" + token[:3])              # smithj
    return keys


def _prep_person(p: dict) -> dict:
    """Cache the folded forms used in scoring (computed once per person)."""
    if "_name" not in p:
        p["_name"] = _person_name(p)
        p["_patterns"] = _username_patterns(p)
        p["_dept"] = fold(p["department"])
        p["_domain"] = p["email"].partition("@")[2]
    return p


def _prep_account(a: dict) -> dict:
    if "_name" not in a:
        a["_name"] = _account_name(a)
        a["_user"] = "".join(_user_tokens(a))
        a["_dept"] = fold(a["department"])
        a["_domain"] = (a["email"] or a.get("upn_email", "")).partition("@")[2]
    return a


def score_pair(a: dict, p: dict) -> tuple[float, dict]:
    """0-100 similarity between an account and a person, with the parts that made it."""
    _prep_account(a)
    _prep_person(p)
    a_name, p_name, user = a["_name"], p["_name"], a["_user"]
    name_score = fuzz.token_sort_ratio(a_name, p_name) if a_name and p_name else 0.0
    user_score = max((fuzz.ratio(user, pat) for pat in p["_patterns"]), default=0.0) if user else 0.0
    if a_name and user:
        score = 0.65 * name_score + 0.35 * user_score
    elif a_name:
        score = name_score * 0.95
    else:
        score = user_score * 0.9
    dept_bonus = 4.0 if a["_dept"] and a["_dept"] == p["_dept"] else 0.0
    # An email on another domain is evidence against the pair (typically a contractor
    # or guest whose name resembles an employee's).
    domain_penalty = 15.0 if a["_domain"] and p["_domain"] and a["_domain"] != p["_domain"] else 0.0
    score = max(0.0, min(100.0, score + dept_bonus) - domain_penalty)
    return score, {"name": round(name_score, 1), "username": round(user_score, 1),
                   "department_bonus": dept_bonus, "domain_penalty": domain_penalty}


def _pseudo(record: dict, name: str) -> str:
    if name == "username_local":
        return local_part(record.get("username", ""))
    if name == "email_local":
        return local_part(record.get("email", ""))
    return str(record.get(name, "") or "").strip().lower()


def match_accounts(people: list[dict], accounts: list[dict], upper: float = 90,
                   lower: float = 70, decisions: dict | None = None,
                   extra_keys: list[str] | None = None,
                   ambiguity_gap: float = 5.0) -> dict[str, Match]:
    """Returns account_key -> Match.

    extra_keys: custom exact rules written 'account_field:person_field', for example
    'username_local:email_local' or 'username:employee_id'.
    """
    decisions = decisions or {}
    by_key = {p["key"]: p for p in people}
    by_emp: dict[str, dict] = {}
    by_email: dict[str, dict] = {}
    by_local: dict[str, list[dict]] = defaultdict(list)
    blocks: dict[str, list[dict]] = defaultdict(list)
    for p in people:
        if p["employee_id"]:
            by_emp.setdefault(p["employee_id"].lower(), p)
        if p["email"]:
            by_email.setdefault(p["email"], p)
            by_local[local_part(p["email"])].append(p)
        for key in _block_keys_person(p):
            blocks[key].append(p)

    extra: list[tuple[str, dict[str, list[dict]]]] = []
    for rule in extra_keys or []:
        a_field, _, p_field = rule.partition(":")
        index: dict[str, list[dict]] = defaultdict(list)
        for p in people:
            value = _pseudo(p, p_field.strip())
            if value:
                index[value].append(p)
        extra.append((a_field.strip(), index))

    confirmed: dict[str, str] = {}
    rejected: dict[str, set[str]] = defaultdict(set)
    for (account_key, person_key), decision in decisions.items():
        if decision == "confirm":
            confirmed[account_key] = person_key
        else:
            rejected[account_key].add(person_key)

    out: dict[str, Match] = {}
    pending: list[dict] = []
    for a in accounts:
        key = a["key"]

        if key in confirmed and confirmed[key] in by_key:
            out[key] = Match(key, confirmed[key], "matched", 100.0, "saved_decision")
            continue
        if a["account_type"] != "human":
            out[key] = Match(key, None, "unmatched", 0.0, "non_human")
            continue

        emp = a["employee_id"].lower()
        if emp and emp in by_emp and by_emp[emp]["key"] not in rejected[key]:
            out[key] = Match(key, by_emp[emp]["key"], "matched", 100.0, "employee_id")
            continue

        hit = None
        for email in (a["email"], a["upn_email"]):
            if email and email in by_email and by_email[email]["key"] not in rejected[key]:
                hit = by_email[email]
                break
        if hit:
            out[key] = Match(key, hit["key"], "matched", 100.0, "email")
            continue

        for a_field, index in extra:
            value = _pseudo(a, a_field)
            candidates = [p for p in index.get(value, []) if p["key"] not in rejected[key]] if value else []
            if len(candidates) == 1:
                hit = candidates[0]
                break
        if hit:
            out[key] = Match(key, hit["key"], "matched", 100.0, "custom_key")
            continue

        # Same username as a person's mailbox name, e.g. AD sAMAccountName 'asha.rao'.
        local = local_part(a["username"])
        same_local = [p for p in by_local.get(local, []) if p["key"] not in rejected[key]] if local else []
        if len(same_local) == 1 and len(local) >= 5:
            p = same_local[0]
            a_domain = (a["email"] or a["upn_email"]).partition("@")[2]
            p_domain = p["email"].partition("@")[2]
            if not a_domain or a_domain == p_domain:
                out[key] = Match(key, p["key"], "matched", 96.0, "username_local")
                continue

        pending.append(a)

    # Who already holds an exactly matched account in each system. A person rarely has
    # two accounts in one system, so a fuzzy candidate who already has one is sent to
    # review, and a candidate with none gets a small bonus.
    holders: set[tuple[str, str]] = set()
    for a in accounts:
        m = out.get(a["key"])
        if m and m.band == "matched" and m.person_key:
            holders.add((a["system"], m.person_key))

    for a in pending:
        key = a["key"]
        seen: set[str] = set()
        best: tuple[float, dict, dict] | None = None
        second = 0.0
        for block in _block_keys_account(a):
            for p in blocks.get(block, ()):
                if p["key"] in seen or p["key"] in rejected[key]:
                    continue
                seen.add(p["key"])
                score, parts = score_pair(a, p)
                if (a["system"], p["key"]) not in holders:
                    score = min(100.0, score + 5.0)
                    parts["no_account_bonus"] = 5.0
                if best is None or score > best[0]:
                    if best is not None:
                        second = max(second, best[0])
                    best = (score, p, parts)
                elif score > second:
                    second = score

        if best is None or best[0] < lower:
            out[key] = Match(key, None, "unmatched", round(best[0], 1) if best else 0.0, "none")
            continue
        score, p, parts = best
        detail = {**parts, "runner_up": round(second, 1)}
        already_has_one = (a["system"], p["key"]) in holders
        if score >= upper and score - second >= ambiguity_gap and not already_has_one:
            out[key] = Match(key, p["key"], "matched", round(score, 1), "fuzzy", detail)
            holders.add((a["system"], p["key"]))
        else:
            out[key] = Match(key, p["key"], "review", round(score, 1), "fuzzy", detail)
    return out


def match_stats(matches: dict[str, Match]) -> dict:
    bands: dict[str, int] = defaultdict(int)
    methods: dict[str, int] = defaultdict(int)
    for m in matches.values():
        bands[m.band] += 1
        if m.band == "matched":
            methods[m.method] += 1
    return {"matched": bands["matched"], "review": bands["review"],
            "unmatched": bands["unmatched"], "matched_by": dict(methods)}
