"""Local, in-memory SNMP agent used for fully offline end-to-end self tests.

It is a real UDP SNMP responder built on PySNMP's low-level entity API, so the
PySNMP client adapter, VACM access control, all three message processing models
and trap/inform delivery are exercised over the wire — but the datastore lives in
memory and the process only binds to a loopback address.

No real BMC is contacted and no state-changing command is ever emitted.
"""

from __future__ import annotations

import asyncio
import bisect
import time
from typing import Any

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config as agent_config
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    send_notification,
)
from pysnmp.proto.api import v2c
from pysnmp.proto.rfc1902 import Integer32, IpAddress, ObjectIdentifier, ObjectName, OctetString, TimeTicks
from pysnmp.smi import error as smi_error
from pysnmp.smi import instrum

from snmp_test.config import Config
from snmp_test.generator.value_factory import seed_value
from snmp_test.model.types import MibModel, MibNode
from snmp_test.snmp.transport import AUTH_PROTOCOLS, PRIV_PROTOCOLS

SUBTREE = (1, 3, 6, 1)
CORRELATION_OID = "1.3.6.1.4.1.52305.9.1.0"
SYS_UPTIME_LOCAL = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID_LOCAL = "1.3.6.1.6.3.1.1.4.1.0"
SNMP_TRAP_ENTERPRISE_LOCAL = "1.3.6.1.6.3.1.1.4.3.0"
# SNMP v3 traps use the originator as authoritative engine; a fixed ID lets the
# listener pre-provision the USM user without an out-of-band discovery step.
NOTIFY_ENGINE_ID = OctetString(hexValue="800000000102030405")

STANDARD_OBJECTS: list[tuple[str, Any, str]] = [
    ("1.3.6.1.2.1.1.1.0", OctetString(b"Mock BMC SNMP Agent"), "read-only"),
    ("1.3.6.1.2.1.1.2.0", ObjectIdentifier("1.3.6.1.4.1.52305"), "read-only"),
    ("1.3.6.1.2.1.1.3.0", TimeTicks(0), "read-only"),
]


def _oid_tuple(oid: str) -> tuple[int, ...]:
    return tuple(int(x) for x in oid.strip(".").split("."))


def _asn1(spec: Any) -> Any:
    if spec.asn1 == "Integer32":
        return Integer32(int(spec.value))
    if spec.asn1 == "IpAddress":
        try:
            return IpAddress(str(spec.value))
        except Exception:
            return IpAddress("192.0.2.10")
    if spec.asn1 == "ObjectIdentifier":
        return ObjectIdentifier(str(spec.value))
    return OctetString(str(spec.value).encode("latin-1", "replace"))


class _InMemoryController(instrum.AbstractMibInstrumController):
    """SMI instrumentation on top of a sorted, in-memory OID dictionary."""

    def __init__(self, agent: "MockAgent") -> None:
        self.agent = agent

    def read_variables(self, *varBinds: Any, **ctx: Any) -> list[Any]:
        out: list[Any] = []
        for name, _ in varBinds:
            key = tuple(int(x) for x in name)
            node = self.agent.meta.get(key)
            allowed = node is None or node.access in ("read-only", "read-write")
            if key in self.agent.datastore and allowed:
                out.append((name, self.agent.datastore[key]))
            else:
                out.append((name, v2c.NoSuchInstance("")))
        return out

    def read_next_variables(self, *varBinds: Any, **ctx: Any) -> list[Any]:
        out: list[Any] = []
        for name, value in varBinds:
            if isinstance(value, v2c.EndOfMibView):
                out.append((ObjectName(tuple(int(x) for x in name)), v2c.EndOfMibView("")))
                continue
            key = tuple(int(x) for x in name)
            idx = bisect.bisect_right(self.agent.readable_oids, key)
            if idx < len(self.agent.readable_oids):
                nxt = self.agent.readable_oids[idx]
                out.append((ObjectName(nxt), self.agent.datastore[nxt]))
            else:
                out.append((ObjectName(key), v2c.EndOfMibView("")))
        return out

    def write_variables(self, *varBinds: Any, **ctx: Any) -> list[Any]:
        out: list[Any] = []
        for idx, (name, value) in enumerate(varBinds):
            key = tuple(int(x) for x in name)
            node = self.agent.meta.get(key)
            if key not in self.agent.datastore or node is None or node.access not in ("read-write", "write-only"):
                raise smi_error.NotWritableError(idx=idx)
            self._verify_vacm("write", name, value, idx, ctx)
            self._validate(node, value, idx)
            self.agent.datastore[key] = value
            out.append((name, value))
        return out

    def _verify_vacm(self, view: str, name: Any, value: Any, idx: int, ctx: dict[str, Any]) -> None:
        """Enforce VACM: PySNMP delegates it to the MIB instrumentation.

        ``acFun`` returns a truthy value when access is denied and raises
        ``AuthorizationError`` for missing views.  Without this call a
        read-only community could still write to the in-memory datastore.
        """
        engine = ctx.get("snmpEngine")
        exec_ctx = {}
        if engine is not None:
            try:
                exec_ctx = engine.observer.get_execution_context("rfc3412.receiveMessage:request")
            except Exception:
                exec_ctx = {}
        security_name = str(exec_ctx.get("securityName", ""))
        # PySNMP's VACM treats a view with zero configured subtrees as "allow";
        # emulate a real BMC's read-only community explicitly instead.
        if view == "write" and security_name in self.agent.read_only_security_names:
            raise smi_error.NoAccessError(name=name, idx=idx)
        ac_fun = ctx.get("acFun")
        if ac_fun is None:
            return
        context = dict(ctx)
        context["idx"] = idx
        try:
            denied = ac_fun(view, (name, value), **context)
        except Exception:
            raise smi_error.NoAccessError(name=name, idx=idx)
        if denied:
            raise smi_error.NoAccessError(name=name, idx=idx)

    @staticmethod
    def _validate(node: MibNode, value: Any, idx: int) -> None:
        syntax = node.syntax
        cls = value.__class__.__name__
        if syntax is None:
            return
        # Wire decoding may produce Integer / Integer32 / Unsigned32 depending on
        # the message processing model; all are valid SMI integer encodings.
        if syntax.is_integer and cls not in {
            "Integer32", "Integer", "Unsigned32", "Gauge32", "Counter32", "Counter64", "TimeTicks"
        }:
            raise smi_error.WrongTypeError(idx=idx)
        if not syntax.is_integer and syntax.base_type != "IpAddress" and cls not in (
            "OctetString", "DisplayString", "Opaque", "Bits"
        ):
            raise smi_error.WrongTypeError(idx=idx)
        if syntax.is_integer:
            try:
                number = int(value)
            except Exception:
                raise smi_error.WrongValueError(idx=idx)
            if syntax.enum and number not in set(syntax.enum.values()):
                raise smi_error.WrongValueError(idx=idx)
            for lo, hi in syntax.ranges:
                if not (lo <= number <= hi):
                    raise smi_error.WrongValueError(idx=idx)
        elif syntax.size and hasattr(value, "__len__"):
            if len(value) > syntax.size[1]:
                raise smi_error.WrongLengthError(idx=idx)


class MockAgent:
    """Loopback-only SNMP agent whose datastore is derived from the parsed MIB."""

    def __init__(self, model: MibModel, cfg: Config) -> None:
        self.model = model
        self.cfg = cfg
        mock = cfg.mock
        self.host = str(mock.get("bind_host", "127.0.0.1"))
        self.port = int(mock.get("port", 11611))
        self.trap_host = str(mock.get("bind_host", "127.0.0.1"))
        self.trap_port = int(mock.get("trap_port", 11612))
        self.rows = int(mock.get("rows_per_table", 2))
        self.communities = dict(mock.get("communities") or {})
        self.v3 = dict(mock.get("v3") or {})
        self.read_only_security_names = {"ro-area"}
        self.datastore: dict[tuple[int, ...], Any] = {}
        self.meta: dict[tuple[int, ...], MibNode] = {}
        self.readable_oids: list[tuple[int, ...]] = []
        self.engine: Any = None
        self.snmp_context: Any = None
        self.notify_engines: list[Any] = []
        self.started_at = time.time()
        self.emitted: list[dict[str, Any]] = []
        self._seed()

    # ------------------------------------------------------------- datastore
    def _seed(self) -> None:
        for oid, value, access in STANDARD_OBJECTS:
            key = _oid_tuple(oid)
            self.datastore[key] = value
        for inst in self.model.instances(rows_per_table=self.rows):
            key = _oid_tuple(inst.oid)
            node = self.model.node_by_name(inst.node_name)
            self.datastore[key] = _asn1(seed_value(inst.syntax, inst.node_name, inst.row_index))
            if node is not None:
                self.meta[key] = node
        self.readable_oids = sorted(
            key for key in self.datastore
            if key not in self.meta or self.meta[key].access in ("read-only", "read-write")
        )

    # ------------------------------------------------------------------ setup
    async def start(self) -> "MockAgent":
        self.engine = engine.SnmpEngine()
        agent_config.add_transport(
            self.engine,
            udp.DOMAIN_NAME,
            udp.UdpTransport().open_server_mode((self.host, self.port)),
        )
        ro = str(self.communities.get("read_only", "public"))
        rw = str(self.communities.get("read_write", "private"))
        v3_user = str(self.v3.get("user", "bmcuser"))

        agent_config.add_v1_system(self.engine, "ro-area", ro)
        agent_config.add_v1_system(self.engine, "rw-area", rw)
        for model_id in (1, 2):
            agent_config.add_vacm_user(
                self.engine, model_id, "ro-area", "noAuthNoPriv",
                readSubTree=SUBTREE, notifySubTree=SUBTREE,
            )
            agent_config.add_vacm_user(
                self.engine, model_id, "rw-area", "noAuthNoPriv",
                readSubTree=SUBTREE, writeSubTree=SUBTREE, notifySubTree=SUBTREE,
            )
        agent_config.add_v3_user(
            self.engine,
            v3_user,
            AUTH_PROTOCOLS.get(str(self.v3.get("auth_protocol", "SHA")).upper()),
            self.v3.get("auth_key"),
            PRIV_PROTOCOLS.get(str(self.v3.get("priv_protocol", "AES128")).upper()),
            self.v3.get("priv_key"),
        )
        for level in ("noAuthNoPriv", "authNoPriv", "authPriv"):
            agent_config.add_vacm_user(
                self.engine, 3, v3_user, level,
                readSubTree=SUBTREE, writeSubTree=SUBTREE, notifySubTree=SUBTREE,
            )

        self.snmp_context = context.SnmpContext(self.engine)
        self.snmp_context.unregister_context_name(v2c.OctetString(b""))
        self.snmp_context.register_context_name(v2c.OctetString(b""), _InMemoryController(self))
        for responder in (
            cmdrsp.GetCommandResponder,
            cmdrsp.NextCommandResponder,
            cmdrsp.BulkCommandResponder,
            cmdrsp.SetCommandResponder,
        ):
            responder(self.engine, self.snmp_context)
        self.engine.transport_dispatcher.job_started(1)

        await asyncio.sleep(0)  # let the UDP server socket register with the loop
        return self

    async def stop(self) -> None:
        engines = [self.engine, *self.notify_engines]
        for eng in engines:
            try:
                dispatcher = getattr(eng, "transport_dispatcher", None)
                if dispatcher is not None:
                    dispatcher.job_finished(1)
                    dispatcher.close_dispatcher()
            except Exception:
                pass

    # -------------------------------------------------------- notifications
    def _notification_auth(self, version: str, community: str) -> Any:
        if version == "v3":
            return UsmUserData(
                str(self.v3.get("user", "bmcuser")),
                authKey=self.v3.get("auth_key"),
                privKey=self.v3.get("priv_key"),
                authProtocol=AUTH_PROTOCOLS.get(str(self.v3.get("auth_protocol", "SHA")).upper()),
                privProtocol=PRIV_PROTOCOLS.get(str(self.v3.get("priv_protocol", "AES128")).upper()),
                securityEngineId=NOTIFY_ENGINE_ID,
            )
        return CommunityData(community, mpModel=0 if version == "v1" else 1)

    def _varbinds_for(self, case: Any) -> list[ObjectType]:
        exp = case.payload.get("trap_expectation", {})
        expected = exp.get("expected_trap_oids") or ["1.3.6.1.4.1.52305.0.1"]
        trap_oid = str(expected[0])
        enterprise = str(exp.get("enterprise_oid") or self.model.root_oid)
        severity = int(exp.get("severity") or 1)
        event = (case.payload.get("trigger") or {}).get("ipmi_event") or {}
        sensor_name = "CPU0 Temp" if event.get("sensor_type") else "BMC"
        sensor_type = "Temperature" if event.get("sensor_type") else "System"
        event_type = "Critical" if severity >= 3 else ("Warning" if severity == 2 else "Information")

        varbinds: list[ObjectType] = [
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.3.0"), TimeTicks(int((time.time() - self.started_at) * 100))),
            ObjectType(ObjectIdentity("1.3.6.1.6.3.1.1.4.1.0"), ObjectIdentifier(trap_oid)),
            ObjectType(ObjectIdentity("1.3.6.1.6.3.1.1.4.3.0"), ObjectIdentifier(enterprise)),
        ]
        values: dict[str, Any] = {
            "1.3.6.1.4.1.52305.2.11.1.2.1": Integer32(1),
            "1.3.6.1.4.1.52305.2.11.1.3.1": OctetString(b"2026-01-01 00:00:00"),
            "1.3.6.1.4.1.52305.2.11.1.4.1": OctetString(sensor_name.encode("ascii")),
            "1.3.6.1.4.1.52305.2.11.1.5.1": OctetString(sensor_type.encode("ascii")),
            "1.3.6.1.4.1.52305.2.11.1.6.1": OctetString(b"Threshold exceeded"),
            "1.3.6.1.4.1.52305.2.11.1.7.1": OctetString(event_type.encode("ascii")),
            CORRELATION_OID: OctetString(case.case_id.encode("ascii")),
        }
        mandatory = {SYS_UPTIME_LOCAL, SNMP_TRAP_OID_LOCAL, SNMP_TRAP_ENTERPRISE_LOCAL}
        for spec in exp.get("varbinds") or []:
            oid = str(spec.get("oid", ""))
            if oid in mandatory or oid not in values:
                continue
            varbinds.append(ObjectType(ObjectIdentity(oid), values[oid]))
        # Correlation id is always appended so concurrent trap cases can be matched.
        if CORRELATION_OID not in mandatory:
            varbinds.append(ObjectType(ObjectIdentity(CORRELATION_OID), values[CORRELATION_OID]))
        return varbinds

    async def emit_event(self, case: Any) -> dict[str, Any]:
        """Send a synthetic in-memory event as a trap/inform (no device changes)."""
        trigger = case.payload.get("trigger") or {}
        if trigger.get("enabled") is False:
            return {"ok": False, "reason": "trigger disabled"}
        exp = case.payload.get("trap_expectation", {})
        version = str(exp.get("version", case.version))
        pdu_type = str(exp.get("pdu_type", "trap"))
        community = str(exp.get("community") or self.communities.get("read_write", "private"))
        auth = self._notification_auth(version, community)
        varbinds = self._varbinds_for(case)
        sent_at = time.time()
        # A fresh engine + transport per notification avoids LCD tag/target reuse:
        # reusing one engine makes v3 notifications fall back to a community target
        # and makes inform PDUs get converted with the v1 message model.
        notify_engine = SnmpEngine(snmpEngineID=NOTIFY_ENGINE_ID) if version == "v3" else SnmpEngine()
        self.notify_engines.append(notify_engine)
        try:
            notify_target = await UdpTransportTarget.create(
                (self.trap_host, self.trap_port), timeout=2.0, retries=1
            )
            result = await send_notification(
                notify_engine, auth, notify_target, ContextData(), pdu_type, *varbinds
            )
            error_indication = str(result[0]) if result and result[0] is not None else None
        except Exception as exc:
            error_indication = f"{type(exc).__name__}: {exc}"
        record = {
            "case_id": case.case_id,
            "name": exp.get("name"),
            "version": version,
            "pdu_type": pdu_type,
            "sent_at": sent_at,
            "error_indication": error_indication,
            "varbind_count": len(varbinds),
        }
        self.emitted.append(record)
        return record


def build_mock_agent(model: MibModel, cfg: Config) -> MockAgent:
    return MockAgent(model, cfg)
