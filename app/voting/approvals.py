"""Dual authorisation (SR-17).

A manual candidate exclusion or a recount is only a *request* until two
different Commissioner's delegates - neither of them the requester, both
logged in with MFA - approve it. Only then is it executed. Every step is
audited, so the audit log always shows two distinct approvals.
"""

ACTIONS = {"exclude_candidate", "recount"}
REQUIRED_APPROVALS = 2
