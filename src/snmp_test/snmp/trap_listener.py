"""SNMP v1/v2c/v3 trap & inform receiver with bounded history and matching.

``NotificationReceiver`` automatically sends the response PDU for confirmed
notifications (inform), i.e. it implements the acknowledgement required by
IPMI 2.0 §30.8 / RFC 1905.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config as agent_config
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto import rfc3411
from pysnmp.proto.api import v2c

from snmp_test.config import Config
from snmp_test.model.types import TrapRecord, Varbind
from snmp_test.snmp.mock_agent import CORRELATION_OID, NOTIFY_ENGINE_ID
from snmp_test.snmp.transport import AUTH_PROTOCOLS, PRIV_PROTOCOLS, _oid_to_str, _to_varbind

SUBTREE = (1, 3, 6, 1)
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
SNMP_TRAP_ENTERPRISE = "1.3.6.1.6.3.1.1.4.3.0"
SNMP_TRAP_ADDRESS = "1.3.6.1.6.3.18.1.3.0"
SNMP_TRAP_COMMUNITY = "1.3.6.1.6.3.18.1.4.0"

MPM_TO_VERSION = {0: "v1", 1: "v2c", 3: "v3"}


class _MetadataReceiver(ntfrcv.NotificationReceiver):
    """Expose message metadata that the stock callback signature hides."""

    def __init__(self, snmpEngine: Any, cbFun: Any, listener: "TrapListener") -> None:
        self.listener = listener
        super().__init__(snmpEngine, cbFun)

    def process_pdu(
        self,
        snmpEngine: Any,
        messageProcessingModel: int,
        securityModel: int,
        securityName: str,
        securityLevel: str,
        contextEngineId: Any,
        contextName: Any,
        pduVersion: int,
        PDU: Any,
        maxSizeResponseScopedPDU: int,
        stateReference: Any,
    ) -> Any:
        confirmed = PDU.tagSet in rfc3411.CONFIRMED_CLASS_PDUS
        version = MPM_TO_VERSION.get(int(messageProcessingModel), f"mpm{messageProcessingModel}")
        self.listener._meta[stateReference] = {
            "version": version,
            "security_name": str(securityName),
            "security_level": str(securityLevel),
            "pdu_type": "inform" if confirmed else "trap",
            "ack_sent": bool(confirmed),
            "source": self.listener._last_source,
            # communityName is only reported for v1/v2c; do not leak a stale value
            # from an earlier message into a v3 record.
            "community": "" if version == "v3" else self.listener._last_community,
        }
        try:
            return super().process_pdu(
                snmpEngine, messageProcessingModel, securityModel, securityName,
                securityLevel, contextEngineId, contextName, pduVersion, PDU,
                maxSizeResponseScopedPDU, stateReference,
            )
        finally:
            self.listener._meta.pop(stateReference, None)


class TrapListener:
    """Loopback UDP trap receiver; records are correlated by a dedicated varbind."""

    def __init__(self, cfg: Config, *, capacity: int = 512) -> None:
        self.cfg = cfg
        trap = cfg.trap
        self.host = str(trap.get("listen_host", "127.0.0.1"))
        self.port = int(trap.get("listen_port", 11612))
        self.timeout = float(trap.get("receive_timeout_s", 5.0))
        self.records: deque[TrapRecord] = deque(maxlen=capacity)
        self.engine: Any = None
        self._meta: dict[Any, dict[str, Any]] = {}
        self._last_community = ""
        self._last_source = ""

    async def start(self) -> "TrapListener":
        self.engine = engine.SnmpEngine()
        agent_config.add_transport(
            self.engine,
            udp.DOMAIN_NAME,
            udp.UdpTransport().open_server_mode((self.host, self.port)),
        )
        mock = self.cfg.mock
        communities = dict(mock.get("communities") or {})
        for key, value in (("ro-area", communities.get("read_only")), ("rw-area", communities.get("read_write"))):
            if not value:
                continue
            agent_config.add_v1_system(self.engine, key, str(value))
            for model_id in (1, 2):
                agent_config.add_vacm_user(
                    self.engine, model_id, key, "noAuthNoPriv",
                    readSubTree=SUBTREE, notifySubTree=SUBTREE,
                )
        v3 = dict(mock.get("v3") or {})
        if v3.get("user"):
            auth_proto = AUTH_PROTOCOLS.get(str(v3.get("auth_protocol", "SHA")).upper())
            priv_proto = PRIV_PROTOCOLS.get(str(v3.get("priv_protocol", "AES128")).upper())
            # Default engine ID covers informs (receiver is authoritative); the
            # fixed originator ID covers v3 traps (originator is authoritative).
            agent_config.add_v3_user(
                self.engine, str(v3["user"]), auth_proto, v3.get("auth_key"),
                priv_proto, v3.get("priv_key"),
            )
            agent_config.add_v3_user(
                self.engine, str(v3["user"]), auth_proto, v3.get("auth_key"),
                priv_proto, v3.get("priv_key"), securityEngineId=NOTIFY_ENGINE_ID,
            )
            for level in ("noAuthNoPriv", "authNoPriv", "authPriv"):
                agent_config.add_vacm_user(
                    self.engine, 3, str(v3["user"]), level,
                    readSubTree=SUBTREE, notifySubTree=SUBTREE,
                )

        def capture_community(snmpEngine: Any, execpoint: str, variables: dict[str, Any], cbCtx: Any) -> None:
            self._last_community = str(variables.get("communityName", "") or "")

        def capture_source(snmpEngine: Any, execpoint: str, variables: dict[str, Any], cbCtx: Any) -> None:
            addr = variables.get("transportAddress") or variables.get("transport_address")
            if addr:
                self._last_source = str(addr)

        self.engine.observer.register_observer(capture_community, "rfc2576.processIncomingMsg")
        self.engine.observer.register_observer(capture_source, "rfc3412.receiveMessage")
        _MetadataReceiver(self.engine, self._on_notification, self)
        self.engine.transport_dispatcher.job_started(1)
        await asyncio.sleep(0)
        return self

    async def stop(self) -> None:
        try:
            dispatcher = getattr(self.engine, "transport_dispatcher", None)
            if dispatcher is not None:
                dispatcher.job_finished(1)
                dispatcher.close_dispatcher()
        except Exception:
            pass

    def _on_notification(
        self,
        snmpEngine: Any,
        stateReference: Any,
        contextEngineId: Any,
        contextName: Any,
        varBinds: Any,
        cbCtx: Any,
    ) -> None:
        meta = dict(self._meta.get(stateReference) or {})
        record = TrapRecord(
            pdu_type=str(meta.get("pdu_type", "trap")),
            version=str(meta.get("version", "v2c")),
            source=str(meta.get("source", "")),
            community=str(meta.get("community", "")),
            security_name=str(meta.get("security_name", "")),
            security_level=str(meta.get("security_level", "")),
            received_at=time.time(),
            ack_sent=bool(meta.get("ack_sent", False)),
        )
        for vb in varBinds:
            oid = _oid_to_str(vb[0])
            converted: Varbind = _to_varbind(vb)
            if oid == SYS_UPTIME:
                try:
                    record.uptime = int(vb[1])
                except Exception:
                    record.uptime = None
            elif oid == SNMP_TRAP_OID:
                record.trap_oid = str(converted.value)
            elif oid == SNMP_TRAP_ENTERPRISE:
                record.enterprise_oid = str(converted.value)
            elif oid == SNMP_TRAP_ADDRESS:
                record.agent_address = str(converted.value)
            elif oid == SNMP_TRAP_COMMUNITY:
                record.community = str(converted.value)
            elif oid == CORRELATION_OID:
                record.correlation_id = str(converted.value)
            record.varbinds.append(converted)
        self.records.append(record)

    def find(self, correlation_id: str, pdu_type: str | None = None, version: str | None = None) -> TrapRecord | None:
        for record in reversed(self.records):
            if record.correlation_id != correlation_id:
                continue
            if pdu_type and record.pdu_type != pdu_type:
                continue
            if version and record.version != version:
                continue
            return record
        return None

    async def wait_for(
        self,
        correlation_id: str,
        *,
        pdu_type: str | None = None,
        version: str | None = None,
        after: float = 0.0,
        timeout: float | None = None,
    ) -> TrapRecord | None:
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        while time.time() < deadline:
            record = self.find(correlation_id, pdu_type, version)
            if record is not None and record.received_at >= after:
                return record
            await asyncio.sleep(0.02)
        return self.find(correlation_id, pdu_type, version)

    def snapshot(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.records]
