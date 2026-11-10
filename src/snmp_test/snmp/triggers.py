"""Event trigger adapter.

Only in-memory mock events and passive listening are enabled.  Any trigger that
would change BMC state (SNMP SET on an event-generating OID, Redfish/IPMI command)
is refused unless it is explicitly enabled *and* the user has separately opted in
through ``--allow-guarded``.  The framework never sends such commands itself.
"""

from __future__ import annotations

import time
from typing import Any

from snmp_test.config import Config
from snmp_test.model.types import TestCase


class TriggerAdapter:
    def __init__(self, cfg: Config, mock_agent: Any = None, listener: Any = None) -> None:
        self.cfg = cfg
        self.mock_agent = mock_agent
        self.listener = listener
        self.history: list[dict[str, Any]] = []

    async def fire(self, case: TestCase) -> dict[str, Any]:
        trigger = dict(case.payload.get("trigger") or {})
        kind = str(trigger.get("type", "passive"))
        triggered_at = time.time()
        result: dict[str, Any] = {
            "case_id": case.case_id,
            "type": kind,
            "triggered_at": triggered_at,
            "ok": False,
            "reason": "",
        }

        if trigger.get("enabled") is False:
            result["reason"] = "trigger disabled in configuration"
        elif kind == "mock_event":
            if self.mock_agent is None:
                result["reason"] = "mock agent is not running (live mode: use passive triggers)"
            else:
                sent = await self.mock_agent.emit_event(case)
                result["ok"] = not sent.get("error_indication")
                result["reason"] = str(sent.get("error_indication") or "")
                result["detail"] = sent
        elif kind == "passive":
            result["ok"] = True
            result["reason"] = "passive listening only, no device action"
        elif kind in ("snmp_set", "external"):
            result["reason"] = (
                f"trigger type '{kind}' is disabled: it would change device state; "
                "set explicitly_enabled and use --allow-guarded to opt in"
            )
        else:
            result["reason"] = f"unsupported trigger type '{kind}'"

        self.history.append(result)
        return result
