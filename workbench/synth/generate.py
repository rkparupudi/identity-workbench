"""Synthetic HR and account exports with a known set of seeded problems.

Real identity data cannot be shared, so this generator serves three purposes:
a demo dataset, test fixtures, and ground truth for scoring the auditor
(`truth.json` lists every seeded problem and the true account-to-person links).
All names are invented and all domains are reserved example domains.
"""
from __future__ import annotations

import csv
import json
import random
import uuid
from datetime import date, datetime, time, timedelta
from pathlib import Path

FIRST_NAMES = [
    "Aarav", "Aditi", "Akash", "Ananya", "Arjun", "Asha", "Deepak", "Divya", "Gaurav", "Isha",
    "Karthik", "Kavya", "Lakshmi", "Manish", "Meera", "Naveen", "Neha", "Nikhil", "Pooja",
    "Pradeep", "Priya", "Rahul", "Rajesh", "Ramesh", "Rohan", "Sanjay", "Shreya", "Sneha",
    "Srinivas", "Suresh", "Swati", "Varun", "Venkatesh", "Vikram", "Vivek", "Yamini",
    "Alexander", "Amelia", "Benjamin", "Charlotte", "Christopher", "Daniel", "Elizabeth",
    "Emily", "Ethan", "Grace", "Hannah", "Isabella", "Jacob", "James", "Jennifer",
    "Katherine", "Liam", "Lucas", "Matthew", "Michael", "Nathan", "Olivia", "Patricia",
    "Rebecca", "Robert", "Samuel", "Sophia", "Thomas", "Victoria", "William",
    "Carlos", "Elena", "Fatima", "Hiroshi", "Ingrid", "Jamal", "Leila", "Mateo", "Mei",
    "Nadia", "Omar", "Sofia", "Tariq", "Yuki", "Zainab", "Chidi",
]
LAST_NAMES = [
    "Agarwal", "Bhat", "Chatterjee", "Chopra", "Das", "Desai", "Dutta", "Ghosh", "Gupta",
    "Hegde", "Iyer", "Jain", "Joshi", "Kapoor", "Khan", "Krishnan", "Kulkarni", "Kumar",
    "Malhotra", "Mehta", "Menon", "Mishra", "Mukherjee", "Nair", "Narayanan", "Pandey",
    "Patel", "Pillai", "Rao", "Reddy", "Saxena", "Shah", "Sharma", "Shetty", "Singh",
    "Sinha", "Subramanian", "Thakur", "Trivedi", "Varma", "Verma", "Yadav",
    "Anderson", "Bailey", "Bennett", "Brooks", "Campbell", "Carter", "Clarke", "Cooper",
    "Davies", "Edwards", "Evans", "Fisher", "Foster", "Graham", "Harris", "Hughes",
    "Jackson", "Johnson", "Kelly", "Lewis", "Martin", "Mitchell", "Morgan", "Murphy",
    "Parker", "Phillips", "Richards", "Roberts", "Robinson", "Stewart", "Taylor", "Turner",
    "Walker", "Watson", "Wilson", "Wright", "Young",
    "Alvarez", "Castillo", "Fernandez", "Garcia", "Haddad", "Hassan", "Ito", "Kowalski",
    "Lindqvist", "Nakamura", "Okafor", "Petrov", "Rahman", "Schmidt", "Tanaka", "Wang",
]
NICKNAMES = {
    "Alexander": "Alex", "Benjamin": "Ben", "Christopher": "Chris", "Daniel": "Dan",
    "Elizabeth": "Liz", "Jennifer": "Jen", "Katherine": "Kate", "Matthew": "Matt",
    "Michael": "Mike", "Nathan": "Nate", "Patricia": "Pat", "Rebecca": "Becky",
    "Robert": "Rob", "Samuel": "Sam", "Thomas": "Tom", "Victoria": "Vicky",
    "William": "Will", "Venkatesh": "Venky", "Srinivas": "Srini", "Lakshmi": "Laxmi",
    "Karthik": "Karthick", "Pradeep": "Pradip",
}
DEPARTMENTS = ["Engineering", "Sales", "Marketing", "Finance", "Human Resources",
               "Customer Support", "Operations", "Legal", "IT", "Product"]
SERVICE_APPS = ["backup", "jenkins", "monitoring", "etl", "crm-sync", "billing", "scanner",
                "reporting", "deploy", "mailrelay", "hr-feed", "sso-test", "datalake", "erp"]

DOMAIN = "corp.example"
PARTNER_DOMAIN = "partner.example"


def _dt(d: date, rng: random.Random) -> str:
    stamp = datetime.combine(d, time(rng.randint(6, 20), rng.randint(0, 59), rng.randint(0, 59)))
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


class _Names:
    """Hands out (first, last) pairs, unique for as long as the pools allow."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.used: set[tuple[str, str]] = set()
        self.locals: dict[str, int] = {}

    def new(self, first: str | None = None) -> tuple[str, str]:
        for _ in range(60):
            pair = (first or self.rng.choice(FIRST_NAMES), self.rng.choice(LAST_NAMES))
            if pair not in self.used:
                self.used.add(pair)
                return pair
        # Pools exhausted (large datasets): add a middle initial, as real directories do.
        while True:
            given = first or self.rng.choice(FIRST_NAMES)
            initial = self.rng.choice("ABCDEFGHJKLMNPRSTVW")
            pair = (f"{given} {initial}", self.rng.choice(LAST_NAMES))
            if pair not in self.used:
                self.used.add(pair)
                return pair

    def local(self, first: str, last: str) -> str:
        base = f"{first}.{last}".lower().replace(" ", ".")
        count = self.locals.get(base, 0) + 1
        self.locals[base] = count
        return base if count == 1 else f"{base}{count}"


def generate(out_dir: str | Path, employees: int = 2000, seed: int = 7,
             as_of: date | None = None) -> dict:
    """Writes hr.csv, okta_users.csv, entra_users.csv and truth.json into out_dir."""
    rng = random.Random(seed)
    as_of = as_of or date.today()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    names = _Names(rng)

    hr_rows, okta_rows, entra_rows = [], [], []
    truth: list[dict] = []
    links: dict[str, str | None] = {}     # 'system|account_id' -> employee id (or None)
    hard_links: list[str] = []            # links that need fuzzy matching

    def seed_truth(kind: str, system: str, account_id: str = "", employee_id: str = "") -> None:
        truth.append({"type": kind, "system": system, "account_id": account_id,
                      "employee_id": employee_id})

    def okta_row(emp_id, first, last, email, login, dept, enabled, last_login, created,
                 mfa, admin):
        oid = "00u" + uuid.UUID(int=rng.getrandbits(128)).hex[:17]
        okta_rows.append({
            "id": oid, "login": login, "email": email, "firstName": first, "lastName": last,
            "status": "ACTIVE" if enabled else rng.choice(["DEPROVISIONED", "SUSPENDED"]),
            "created": _dt(created, rng), "lastLogin": _dt(last_login, rng) if last_login else "",
            "employeeNumber": emp_id, "department": dept,
            "mfaEnrolled": "" if mfa is None else str(mfa).lower(),
            "isAdmin": str(admin).lower()})
        return oid

    def entra_row(emp_id, display, upn, mail, dept, enabled, last_login, created, mfa,
                  privileged, user_type="Member", owner=""):
        gid = str(uuid.UUID(int=rng.getrandbits(128)))
        entra_rows.append({
            "id": gid, "userPrincipalName": upn, "displayName": display, "mail": mail,
            "accountEnabled": str(enabled), "createdDateTime": _dt(created, rng),
            "lastSignInDateTime": _dt(last_login, rng) if last_login else "",
            "employeeId": emp_id, "department": dept, "userType": user_type,
            "isMfaRegistered": "" if mfa is None else str(mfa),
            "isPrivileged": str(privileged), "managedBy": owner})
        return gid

    def flags(system: str, allow_seed: bool):
        """Returns (last_login, mfa, privileged, seeded_dormant, seeded_no_mfa)."""
        dormant = allow_seed and rng.random() < 0.04
        last_login = as_of - timedelta(days=rng.randint(120, 400) if dormant else rng.randint(0, 30))
        privileged = rng.random() < 0.03
        if privileged:
            no_mfa = allow_seed and rng.random() < 0.25
            mfa = not no_mfa
        else:
            no_mfa = False
            mfa = rng.random() < 0.92
        return last_login, mfa, privileged, dormant, no_mfa

    people = []
    for i in range(employees):
        first, last = names.new()
        emp_id = f"E{100000 + i}"
        local = names.local(first, last)
        email = f"{local}@{DOMAIN}"
        dept = rng.choice(DEPARTMENTS)
        start = as_of - timedelta(days=rng.randint(200, 3000))
        terminated = rng.random() < 0.08
        end = as_of - timedelta(days=rng.randint(10, 190)) if terminated else None
        manager = rng.choice(people)["name"] if people else ""
        people.append({"emp_id": emp_id, "name": f"{first} {last}"})
        hr_rows.append({
            "Employee ID": emp_id, "First Name": first, "Last Name": last,
            "Work Email": email, "Status": "Terminated" if terminated else "Active",
            "Hire Date": start.isoformat(), "Termination Date": end.isoformat() if end else "",
            "Department": dept, "Manager": manager, "Worker Type": "Employee"})
        created = start + timedelta(days=rng.randint(0, 3))

        if terminated:
            for system, leak_rate in (("okta", 0.30), ("entra", 0.10)):
                leaked = rng.random() < leak_rate
                last_login = as_of - timedelta(days=rng.randint(0, 30)) if leaked \
                    else end - timedelta(days=rng.randint(0, 5))
                if system == "okta":
                    aid = okta_row(emp_id, first, last, email, email, dept, leaked, last_login,
                                   created, True, False)
                else:
                    aid = entra_row(emp_id, f"{first} {last}", email, email, dept, leaked,
                                    last_login, created, True, False)
                links[f"{system}|{aid}"] = emp_id
                if leaked:
                    seed_truth("leaver_active_account", system, aid, emp_id)
            continue

        # Okta account for an active person.
        if rng.random() < 0.01:
            seed_truth("missing_account", "okta", employee_id=emp_id)
        else:
            last_login, mfa, privileged, dormant, no_mfa = flags("okta", True)
            okta_dept = dept
            drift = rng.random() < 0.03
            if drift:
                okta_dept = rng.choice([d for d in DEPARTMENTS if d != dept])
            aid = okta_row(emp_id, first, last, email, email, okta_dept, True, last_login,
                           created, mfa, privileged)
            links[f"okta|{aid}"] = emp_id
            if dormant:
                seed_truth("dormant_account", "okta", aid, emp_id)
            if no_mfa:
                seed_truth("privileged_without_mfa", "okta", aid, emp_id)
            if drift:
                seed_truth("attribute_drift", "okta", aid, emp_id)
            if rng.random() < 0.01:
                adm_login = f"{local}.adm@{DOMAIN}"
                aid2 = okta_row(emp_id, first, last, adm_login, adm_login, dept, True,
                                as_of - timedelta(days=rng.randint(0, 20)), created, True, True)
                links[f"okta|{aid2}"] = emp_id
                seed_truth("duplicate_accounts", "okta", employee_id=emp_id)
                seed_truth("attribute_drift", "okta", aid2, emp_id)   # email differs from HR

        # Entra account for an active person.
        if rng.random() < 0.01:
            seed_truth("missing_account", "entra", employee_id=emp_id)
            continue
        last_login, mfa, privileged, dormant, no_mfa = flags("entra", True)
        if rng.random() < 0.03:
            # A name variant with no employee ID: only fuzzy matching can link it.
            roll = rng.random()
            if first in NICKNAMES and roll < 0.6:
                v_first, v_last = NICKNAMES[first], last            # nickname
            elif roll < 0.8 and len(last) > 4:
                cut = rng.randint(1, len(last) - 2)                 # spelling variant
                v_first, v_last = first, last[:cut] + last[cut + 1:]
            else:
                v_first, v_last = names.new(first)                  # surname change
            v_local = names.local(v_first, v_last)
            upn = f"{v_local}@{DOMAIN}"
            aid = entra_row("", f"{v_first} {v_last}", upn, upn, dept, True, last_login, created,
                            mfa, privileged)
            hard_links.append(f"entra|{aid}")
            # If the tool links this account, its name and email differ from HR.
            truth.append({"type": "attribute_drift", "system": "entra", "account_id": aid,
                          "employee_id": emp_id, "conditional": True})
        else:
            entra_emp = "" if rng.random() < 0.40 else emp_id
            aid = entra_row(entra_emp, f"{first} {last}", email, email, dept, True, last_login,
                            created, mfa, privileged)
        links[f"entra|{aid}"] = emp_id
        if dormant:
            seed_truth("dormant_account", "entra", aid, emp_id)
        if no_mfa:
            seed_truth("privileged_without_mfa", "entra", aid, emp_id)

    # Contractors who are not in HR: orphaned accounts.
    for _ in range(max(4, employees // 50)):
        first, last = names.new()
        local = names.local(first, last)
        email = f"{local}@{PARTNER_DOMAIN}"
        created = as_of - timedelta(days=rng.randint(60, 900))
        last_login = as_of - timedelta(days=rng.randint(0, 30))
        if rng.random() < 0.5:
            aid = okta_row("", first, last, email, email, "", True, last_login, created, True, False)
            system = "okta"
        else:
            aid = entra_row("", f"{first} {last}", f"{local}_{PARTNER_DOMAIN}#EXT#@{DOMAIN}",
                            email, "", True, last_login, created, True, False, user_type="Guest")
            system = "entra"
        links[f"{system}|{aid}"] = None
        seed_truth("orphaned_account", system, aid)

    # Service accounts, half of them with no owner.
    for n in range(max(6, employees // 100)):
        app = rng.choice(SERVICE_APPS)
        upn = f"svc-{app}-{n:02d}@{DOMAIN}"
        owner = rng.choice(people)["name"] if n % 2 == 0 else ""
        aid = entra_row("", f"Service {app} {n:02d}", upn, "", "", True,
                        as_of - timedelta(days=rng.randint(0, 5)),
                        as_of - timedelta(days=rng.randint(100, 1500)), None, False,
                        user_type="", owner=owner)
        links[f"entra|{aid}"] = None
        if not owner:
            seed_truth("unowned_service_account", "entra", aid)

    rng.shuffle(okta_rows)
    rng.shuffle(entra_rows)
    for name, rows in (("hr.csv", hr_rows), ("okta_users.csv", okta_rows),
                       ("entra_users.csv", entra_rows)):
        with open(out / name, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    counts: dict[str, int] = {}
    for item in truth:
        if not item.get("conditional"):
            counts[item["type"]] = counts.get(item["type"], 0) + 1
    (out / "truth.json").write_text(json.dumps({
        "as_of": as_of.isoformat(), "seed": seed, "employees": employees,
        "seeded_counts": counts, "findings": truth, "links": links,
        "hard_links": hard_links}, indent=1), encoding="utf-8")
    return {"out_dir": str(out), "as_of": as_of.isoformat(), "employees": employees,
            "okta_accounts": len(okta_rows), "entra_accounts": len(entra_rows),
            "seeded_counts": counts,
            "files": ["hr.csv", "okta_users.csv", "entra_users.csv", "truth.json"]}
