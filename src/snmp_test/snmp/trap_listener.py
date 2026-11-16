"""SNMP v1/v2c/v3 trap & inform receiver with bounded history and matching.

``NotificationReceiver`` automatically sends the response PDU for confirmed
notifications (inform), i.e. it implements the acknowledgement required by
IPMI 2.0 §30.8 / RFC 1905.

Two matching modes are supported:

* **correlated** – the mock agent injects ``CORRELATION_OID`` with the case id;
* **live** – a real BMC cannot know the case id, so records are matched by
  ``version + pdu_type + trap OID + source + time window`` instead.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any, Sequence

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config as agent_config
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto import rfc3411
from pysnmp.proto.api import v2c
from pysnmp.proto.rfc1902 import OctetString

from snmp_test.config import Config, TargetConfig
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

NOTIFY_ENGINE_ID_HEX = "800000000102030405"


def engine_id_hex(value: Any) -> str:
    """Normalise an ``snmpEngineID`` value (hex text or bytes) to hex."""
    text = str(value).strip()
    hex_digits = "0123456789abcdefABCDEF"
    if text.lower().startswith("0x"):
        candidate = text[2:]
    elif len(text) >= 10 and len(text) % 2 == 0 and all(ch in hex_digits for ch in text):
        # ``targets[].v3.trap_engine_id`` may be written without the 0x prefix.
        candidate = text
    else:
        try:
            candidate = bytes(value).hex()
        except Exception:
            candidate = text.encode("utf-8", "replace").hex()
    candidate = "".join(ch for ch in candidate if ch in hex_digits)
    # RFC 3411 requires 5..32 octets; anything shorter is not an engine id.
    return candidate if 10 <= len(candidate) <= 64 and len(candidate) % 2 == 0 else ""


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
    """Loopback UDP trap receiver; records are correlated or matched by content."""

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
        self._communities: dict[str, str] = {}
        self._v3_users: set[tuple[str, str]] = set()

    async def start(self) -> "TrapListener":
        self.engine = engine.SnmpEngine()
        agent_config.add_transport(
            self.engine,
            udp.DOMAIN_NAME,
            udp.UdpTransport().open_server_mode((self.host, self.port)),
        )
        mock = self.cfg.mock
        if self.cfg.mode == "mock":
            # Mock-only credentials; in live mode targets[] is authoritative and
            # must not be shadowed by a same-named mock user.
            communities = dict(mock.get("communities") or {})
            self._add_community("ro-area", str(communities.get("read_only") or ""))
            self._add_community("rw-area", str(communities.get("read_write") or ""))
            v3 = dict(mock.get("v3") or {})
            if v3.get("user"):
                # The mock agent uses a fixed originator engine id, so both the
                # receiver-authoritative (inform) and originator-authoritative
                # (trap) USM entries can be pre-provisioned.
                self._add_v3_user(str(v3["user"]), v3, NOTIFY_ENGINE_ID_HEX)
        # Live devices send traps with their own credentials; register every
        # target so a real BMC does not need to be duplicated in the mock block.
        for target in self.cfg.targets:
            self.register_target(target)

        def capture_community(snmpEngine: Any, execpoint: str, variables: dict[str, Any], cbCtx: Any) -> None:
            self._last_community = str(variables.get("communityName", "") or "")

        def capture_source(snmpEngine: Any, execpoint: str, variables: dict[str, Any], cbCtx: Any) -> None:
            addr = variables.get("transportAddress") or variables.get("transport_address")
            if addr:
                self._last_source = str(addr)

        self.engine.observer.register_observer(capture_community, "rfc2576.processIncomingMsg")
        self.engine.observer.register_observer(capture_source, "rfc3412.receiveMessage:request")
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
                await asyncio.sleep(0)
        except Exception:
            pass

    # ------------------------------------------------------------ credentials
    def _add_community(self, index: str, community: str) -> None:
        if self.engine is None or not community or community in self._communities:
            return
        self._communities[community] = index
        agent_config.add_v1_system(self.engine, index, community)
        for model_id in (1, 2):
            agent_config.add_vacm_user(
                self.engine, model_id, index, "noAuthNoPriv",
                readSubTree=SUBTREE, notifySubTree=SUBTREE,
            )

    def _add_v3_user(self, user: str, v3: dict[str, Any], engine_hex: str = "") -> None:
        if self.engine is None or not user:
            return
        level = str(v3.get("security_level", "authPriv")).lower()
        auth_key = v3.get("auth_key")
        priv_key = v3.get("priv_key")
        auth_proto = AUTH_PROTOCOLS.get(str(v3.get("auth_protocol", "SHA")).upper())
        priv_proto = PRIV_PROTOCOLS.get(str(v3.get("priv_protocol", "AES128")).upper())
        if level == "noauthnopriv":
            auth_key, priv_key = None, None
            auth_proto, priv_proto = AUTH_PROTOCOLS["NONE"], PRIV_PROTOCOLS["NONE"]
        elif level == "authnopriv":
            priv_key = None
            priv_proto = PRIV_PROTOCOLS["NONE"]
        if auth_proto is None or priv_proto is None:
            return
        engine_ids: list[OctetString | None] = [None]
        if engine_hex:
            engine_ids.append(OctetString(hexValue=engine_hex))
        for engine_id in engine_ids:
            key = (user, engine_hex if engine_id is not None else "")
            if key in self._v3_users:
                continue
            self._v3_users.add(key)
            agent_config.add_v3_user(
                self.engine, user, auth_proto, auth_key, priv_proto, priv_key,
                securityEngineId=engine_id,
            )
        for vacm_level in ("noAuthNoPriv", "authNoPriv", "authPriv"):
            agent_config.add_vacm_user(
                self.engine, 3, user, vacm_level,
                readSubTree=SUBTREE, notifySubTree=SUBTREE,
            )

    def register_target(self, target: TargetConfig, engine_hex: str = "") -> None:
        """Accept traps sent with this target's own credentials.

        ``engine_hex`` is only needed for v3 traps (the originator is the
        authoritative engine).  v3 informs use the listener's engine id and
        work with the default registration alone.
        """
        for suffix, community in (
            ("v1", target.community("v1")),
            ("v1-ro", target.read_only_community("v1")),
            ("v2c", target.community("v2c")),
            ("v2c-ro", target.read_only_community("v2c")),
        ):
            self._add_community(f"target-{target.name}-{suffix}", community)
        v3 = dict(target.v3 or {})
        if v3.get("user"):
            self._add_v3_user(str(v3["user"]), v3, engine_hex)

    # ------------------------------------------------------------- receiving
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

    @staticmethod
    def _from_source(record: TrapRecord, source: str) -> bool:
        if not source:
            return True
        needle = source.lower()
        return needle in f"{record.source} {record.agent_address}".lower()

    def match(
        self,
        *,
        correlation_id: str = "",
        pdu_type: str | None = None,
        version: str | None = None,
        trap_oids: Sequence[str] = (),
        source: str = "",
        after: float = 0.0,
        claimant: str = "",
        claim: bool = False,
    ) -> TrapRecord | None:
        """Return the newest unconsumed record satisfying every given criterion."""
        allowed = {str(oid).strip() for oid in trap_oids if oid}
        for record in reversed(self.records):
            if claim and record.claimed_by:
                continue
            if correlation_id and record.correlation_id != correlation_id:
                continue
            if record.received_at < after:
                continue
            if pdu_type and record.pdu_type != pdu_type:
                continue
            if version and record.version != version:
                continue
            if allowed and record.trap_oid not in allowed:
                continue
            if not self._from_source(record, source):
                continue
            if claim:
                record.claimed_by = claimant or "matched"
            return record
        return None

    async def wait_for_match(self, *, timeout: float | None = None, **criteria: Any) -> TrapRecord | None:
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        while time.time() < deadline:
            record = self.match(**criteria)
            if record is not None:
                return record
            await asyncio.sleep(0.02)
        return self.match(**criteria)

    def find(self, correlation_id: str, pdu_type: str | None = None, version: str | None = None) -> TrapRecord | None:
        return self.match(correlation_id=correlation_id, pdu_type=pdu_type, version=version)

    async def wait_for(
        self,
        correlation_id: str,
        *,
        pdu_type: str | None = None,
        version: str | None = None,
        after: float = 0.0,
        timeout: float | None = None,
        claim: bool = False,
    ) -> TrapRecord | None:
        return await self.wait_for_match(
            correlation_id=correlation_id,
            pdu_type=pdu_type,
            version=version,
            after=after,
            claimant=correlation_id,
            claim=claim,
            timeout=timeout,
        )

    def snapshot(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.records]
