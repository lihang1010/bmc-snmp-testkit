"""PySNMP 7 asyncio adapter.

All PySNMP calls are confined to this module.  One ``SnmpEngine`` + transport target
is created per ``(target, version, credential-override)`` and reused for the whole
run, which avoids per-case USM engine discovery and UDP socket churn.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    USM_AUTH_HMAC128_SHA224,
    USM_AUTH_HMAC192_SHA256,
    USM_AUTH_HMAC256_SHA384,
    USM_AUTH_HMAC384_SHA512,
    USM_AUTH_HMAC96_MD5,
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_NONE,
    USM_PRIV_CBC168_3DES,
    USM_PRIV_CBC56_DES,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB192_AES,
    USM_PRIV_CFB256_AES,
    USM_PRIV_NONE,
    CommunityData,
    ContextData,
    Integer32,
    IpAddress,
    ObjectIdentifier,
    ObjectIdentity,
    ObjectType,
    OctetString,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    get_cmd,
    next_cmd,
    set_cmd,
)

from snmp_test.config import Config, TargetConfig
from snmp_test.model.types import SnmpResponse, Varbind
from snmp_test.snmp.errors import (
    EXCEPTION_TYPES,
    normalize_error_indication,
    normalize_error_status,
)

AUTH_PROTOCOLS: dict[str, Any] = {
    "NONE": USM_AUTH_NONE,
    "MD5": USM_AUTH_HMAC96_MD5,
    "SHA": USM_AUTH_HMAC96_SHA,
    "SHA1": USM_AUTH_HMAC96_SHA,
    "SHA224": USM_AUTH_HMAC128_SHA224,
    "SHA256": USM_AUTH_HMAC192_SHA256,
    "SHA384": USM_AUTH_HMAC256_SHA384,
    "SHA512": USM_AUTH_HMAC384_SHA512,
}

PRIV_PROTOCOLS: dict[str, Any] = {
    "NONE": USM_PRIV_NONE,
    "DES": USM_PRIV_CBC56_DES,
    "3DES": USM_PRIV_CBC168_3DES,
    "AES": USM_PRIV_CFB128_AES,
    "AES128": USM_PRIV_CFB128_AES,
    "AES192": USM_PRIV_CFB192_AES,
    "AES256": USM_PRIV_CFB256_AES,
}

INTEGER_CLASSES = {
    "Integer32", "Integer", "Unsigned32", "Gauge32", "Counter32", "Counter64",
    "TimeTicks", "Counter64", "Unsigned64",
}


def _oid_to_str(obj: Any) -> str:
    try:
        return ".".join(str(int(x)) for x in tuple(obj))
    except Exception:
        try:
            return str(obj.get_oid())
        except Exception:
            return str(obj)


def _asn1_value(spec: dict[str, Any]) -> Any | None:
    kind = str(spec.get("asn1", "Null"))
    value = spec.get("value")
    if kind in ("Null", "None", "") or value is None:
        return None
    if kind == "Integer32":
        return Integer32(int(value))
    if kind in ("OctetString", "DisplayString", "Opaque", "Bits"):
        return OctetString(str(value).encode("latin-1", "replace"))
    if kind == "IpAddress":
        return IpAddress(str(value))
    if kind in ("ObjectIdentifier", "ObjectName"):
        return ObjectIdentifier(str(value))
    return OctetString(str(value).encode("latin-1", "replace"))


def _object_types(varbinds: list[dict[str, Any]]) -> list[ObjectType]:
    out: list[ObjectType] = []
    for spec in varbinds:
        oid = str(spec["oid"])
        value = _asn1_value(spec)
        out.append(ObjectType(ObjectIdentity(oid)) if value is None else ObjectType(ObjectIdentity(oid), value))
    return out


def _to_varbind(vb: Any) -> Varbind:
    oid = _oid_to_str(vb[0])
    value = vb[1]
    cls = value.__class__.__name__
    exception = cls if cls in EXCEPTION_TYPES else None
    if exception:
        return Varbind(oid=oid, type=cls, value=exception, exception=exception)
    try:
        pretty = value.prettyPrint()
    except Exception:
        pretty = str(value)
    if cls in INTEGER_CLASSES:
        try:
            return Varbind(oid=oid, type=cls, value=int(value))
        except Exception:
            return Varbind(oid=oid, type=cls, value=pretty)
    if cls in ("IpAddress", "ObjectIdentifier", "ObjectName"):
        return Varbind(oid=oid, type=cls, value=pretty)
    return Varbind(oid=oid, type=cls, value=pretty)


def _brief(response: SnmpResponse, limit: int = 1200) -> str:
    text = json.dumps(
        {
            "error_indication": response.error_indication,
            "error_status": response.error_status,
            "error_index": response.error_index,
            "varbinds": [v.to_dict() for v in response.varbinds[:12]],
        },
        ensure_ascii=False,
        default=str,
    )
    return text[:limit]


class SnmpSession:
    """One reusable SNMP client session."""

    def __init__(
        self,
        cfg: Config,
        target: TargetConfig,
        version: str,
        override: dict[str, Any] | None = None,
    ) -> None:
        self.cfg = cfg
        self.target = target
        self.version = version
        self.override = dict(override or {})
        self.engine: Any = None
        self.transport: Any = None
        self.auth: Any = None
        self.context = ContextData()
        self._key = (target.name, version, tuple(sorted((k, str(v)) for k, v in self.override.items())))

    @property
    def key(self) -> tuple[Any, ...]:
        return self._key

    async def open(self) -> "SnmpSession":
        ex = self.cfg.execution
        self.engine = SnmpEngine()
        self.transport = await UdpTransportTarget.create(
            (self.target.host, self.target.port),
            timeout=float(ex.get("timeout_s", 2.0)),
            retries=int(ex.get("retries", 1)),
        )
        self.auth = self._make_auth()
        return self

    def _make_auth(self) -> Any:
        if self.version in ("v1", "v2c"):
            community = self.override.get("community") or self.target.community(self.version)
            return CommunityData(community, mpModel=0 if self.version == "v1" else 1)
        v3 = dict(self.target.v3)
        user = str(self.override.get("v3_user") or v3.get("user", ""))
        auth_key = self.override.get("auth_key") or v3.get("auth_key")
        priv_key = self.override.get("priv_key") or v3.get("priv_key")
        level = str(v3.get("security_level", "authPriv")).lower()
        if level == "noauthnopriv":
            auth_key, priv_key = None, None
        elif level == "authnopriv":
            priv_key = None
        auth_proto = AUTH_PROTOCOLS.get(str(v3.get("auth_protocol", "SHA")).upper(), USM_AUTH_HMAC96_SHA)
        priv_proto = PRIV_PROTOCOLS.get(str(v3.get("priv_protocol", "AES128")).upper(), USM_PRIV_CFB128_AES)
        return UsmUserData(
            user,
            authKey=auth_key,
            privKey=priv_key,
            authProtocol=USM_AUTH_NONE if level == "noauthnopriv" else auth_proto,
            privProtocol=USM_PRIV_NONE if level in ("noauthnopriv", "authnopriv") else priv_proto,
        )

    async def close(self) -> None:
        try:
            dispatcher = getattr(self.engine, "transport_dispatcher", None)
            if dispatcher is not None:
                dispatcher.close_dispatcher()
        except Exception:
            pass

    async def _execute(self, cmd: Any, *args: Any, operation: str) -> SnmpResponse:
        started = time.perf_counter()
        try:
            result = await cmd(self.engine, self.auth, self.transport, self.context, *args)
        except Exception as exc:  # malformed OID / unsupported value construction
            response = SnmpResponse(
                error_indication=f"clientError: {type(exc).__name__}: {exc}",
                error_status="clientError",
                error_index=0,
                varbinds=[],
                version=self.version,
                operation=operation,
                target=self.target.name,
                elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            response.raw = "client-side error, no PDU sent"
            return response

        err_ind, err_status, err_index, varbinds = result
        try:
            parsed = [_to_varbind(vb) for vb in varbinds]
        except Exception as exc:
            parsed = []
            err_ind = err_ind or f"parseError: {exc}"
        response = SnmpResponse(
            error_indication=normalize_error_indication(err_ind),
            error_status=normalize_error_status(err_status),
            error_index=int(err_index or 0),
            varbinds=parsed,
            version=self.version,
            operation=operation,
            target=self.target.name,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        response.raw = _brief(response)
        return response

    async def get(self, oids: list[str] | None = None, *, varbinds: list[dict[str, Any]] | None = None) -> SnmpResponse:
        specs = varbinds if varbinds is not None else [{"oid": o, "asn1": "Null", "value": None} for o in (oids or [])]
        return await self._execute(get_cmd, *_object_types(specs), operation="GET")

    async def get_next(self, oids: list[str] | None = None, *, varbinds: list[dict[str, Any]] | None = None) -> SnmpResponse:
        specs = varbinds if varbinds is not None else [{"oid": o, "asn1": "Null", "value": None} for o in (oids or [])]
        return await self._execute(next_cmd, *_object_types(specs), operation="GETNEXT")

    async def get_bulk(
        self,
        oids: list[str] | None = None,
        *,
        varbinds: list[dict[str, Any]] | None = None,
        non_repeaters: int = 0,
        max_repetitions: int = 6,
    ) -> SnmpResponse:
        specs = varbinds if varbinds is not None else [{"oid": o, "asn1": "Null", "value": None} for o in (oids or [])]
        return await self._execute(
            bulk_cmd,
            int(non_repeaters),
            int(max_repetitions),
            *_object_types(specs),
            operation="GETBULK",
        )

    async def set(self, varbinds: list[dict[str, Any]]) -> SnmpResponse:
        return await self._execute(set_cmd, *_object_types(varbinds), operation="SET")


class TransportPool:
    """Lazily create and reuse sessions; ``close()`` must be called at run end."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._sessions: dict[tuple[Any, ...], SnmpSession] = {}
        self._lock = asyncio.Lock()

    async def session(
        self,
        target: TargetConfig,
        version: str,
        override: dict[str, Any] | None = None,
    ) -> SnmpSession:
        probe = SnmpSession(self.cfg, target, version, override)
        key = probe.key
        async with self._lock:
            existing = self._sessions.get(key)
            if existing is not None:
                return existing
            await probe.open()
            self._sessions[key] = probe
            return probe

    async def close(self) -> None:
        for session in self._sessions.values():
            await session.close()
        self._sessions.clear()
