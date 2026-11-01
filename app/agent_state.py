# -*- coding: utf-8 -*-
"""Agent 深挖任务的对外三态：pending（未接取）/ running（已接取）/ completed。"""
from datetime import datetime


def claim_state(run) -> str:
    if run is None:
        return "pending"
    if (run.status or "") == "completed":
        return "completed"
    # running / blocked / expired 都算“已接取未完成”，中断后仍可续领
    return "running"


def claim_info(run, now: datetime | None = None) -> dict:
    now = now or datetime.now()
    state = claim_state(run)
    if state != "running":
        return {"claim_state": state, "claimable": state == "pending",
                "lease_expired": False}
    active = bool(run.lease_until and run.lease_until > now)
    return {"claim_state": "running", "claimable": not active,
            "lease_expired": bool(run.lease_until and run.lease_until <= now)}
