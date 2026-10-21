"""Demo data: a fictional NSW Senate election. All names are invented."""

GROUPS = [("A", "Harbour Alliance", 1), ("B", "Coastal Progress Party", 2),
          ("C", "Outback Independents", 3)]
CANDIDATES = [
    ("A1", "Mia Thornton", "Harbour Alliance", "A", 1, "NSW"),
    ("A2", "Liam Okafor", "Harbour Alliance", "A", 2, "NSW"),
    ("B1", "Sofia Nguyen", "Coastal Progress Party", "B", 1, "NSW"),
    ("B2", "Ethan Walsh", "Coastal Progress Party", "B", 2, "NSW"),
    ("C1", "Olivia Patel", "Outback Independents", "C", 1, "NSW"),
    ("C2", "Noah Fitzgerald", "Outback Independents", "C", 2, "NSW"),
    ("U1", "Grace Delaney", "Independent", None, 1, "NSW"),
    ("V1", "Jack Rossi", "Independent", None, 1, "VIC"),   # other state: RBAC scope demo
]
# enrolment id, name, address, dob, division, state, enrolled
VOTERS = [
    ("NSW1000001", "Aisha Rahman", "12 George St, Sydney NSW 2000", "1990-04-12", "Sydney", "NSW", 1),
    ("NSW1000002", "Ben Carter", "4 Crown St, Wollongong NSW 2500", "1985-09-30", "Cunningham", "NSW", 1),
    ("NSW1000003", "Chloe Martin", "88 Hunter St, Newcastle NSW 2300", "2001-01-15", "Newcastle", "NSW", 1),
    ("NSW1000004", "Daniel Kim", "7 Church St, Parramatta NSW 2150", "1978-06-02", "Parramatta", "NSW", 1),
    ("NSW1000005", "Emily Brown", "21 Bay Rd, Byron Bay NSW 2481", "1995-11-23", "Richmond", "NSW", 1),
    ("NSW1000006", "Farhan Ali", "3 Main St, Dubbo NSW 2830", "1969-03-08", "Parkes", "NSW", 1),
    ("NSW1000007", "Georgia Lee", "55 King St, Sydney NSW 2000", "2000-07-19", "Sydney", "NSW", 1),
    ("NSW1000008", "Hamish Doyle", "9 Beach Rd, Manly NSW 2095", "1988-12-01", "Warringah", "NSW", 1),
    ("NSW1000009", "Isla Young", "14 Park Ave, Penrith NSW 2750", "2011-05-05", "Lindsay", "NSW", 1),
    ("NSW1000010", "Jacob Hill", "2 Ridge Rd, Orange NSW 2800", "1992-02-14", "Calare", "NSW", 0),
    ("VIC2000001", "Kate Murphy", "1 Collins St, Melbourne VIC 3000", "1983-08-21", "Melbourne", "VIC", 1),
]
STAFF = [
    ("admin1", "admin", None), ("officer1", "employee", None),
    ("delegate_nsw1", "delegate", "NSW"), ("delegate_nsw2", "delegate", "NSW"),
    ("delegate_vic1", "delegate", "VIC"), ("auditor1", "auditor", None),
]
TERMINALS = [("PS-SYD-001", "Sydney Town Hall polling place"),
             ("MISSION-LON-01", "Australian High Commission, London")]


def seed(svc):
    """Populate an empty database."""
    with svc.dbs.connect("ballot") as conn:
        conn.executemany("INSERT OR IGNORE INTO groups VALUES (?,?,?)", GROUPS)
        conn.executemany("INSERT OR IGNORE INTO candidates (id, name, party, group_code, position,"
                         " state) VALUES (?,?,?,?,?,?)", CANDIDATES)
        conn.execute("INSERT OR IGNORE INTO election VALUES ('status', 'setup')")
