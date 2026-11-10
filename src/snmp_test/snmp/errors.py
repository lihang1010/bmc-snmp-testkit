"""Normalisation of SNMP error statuses and PySNMP error indications.

SNMP v1 reports errors as a PDU ``error-status`` (noSuchName/badValue/...), while
v2c/v3 also use exception varbind values (noSuchObject/noSuchInstance/endOfMibView).
The runner must assert both forms through one vocabulary.
"""

from __future__ import annotations

ERROR_STATUS_BY_INT: dict[int, str] = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}

V1_ERROR_ALIASES: dict[str, tuple[str, ...]] = {
    "noSuchName": ("noSuchName", "noAccess", "notWritable", "authorizationError", "inconsistentName"),
    "badValue": ("badValue", "wrongType", "wrongLength", "wrongValue", "wrongEncoding", "notWritable"),
    "readOnly": ("readOnly", "noAccess", "notWritable"),
}

REJECTION_STATUSES = {
    "tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess",
    "wrongType", "wrongLength", "wrongEncoding", "wrongValue", "noCreation",
    "inconsistentValue", "resourceUnavailable", "commitFailed", "undoFailed",
    "authorizationError", "notWritable", "inconsistentName",
}

EXCEPTION_TYPES = {"NoSuchObject", "NoSuchInstance", "EndOfMibView"}


def normalize_error_status(value: object) -> str:
    """Convert a PySNMP errorStatus (named Integer or plain int) to a name."""
    if value is None:
        return "noError"
    text = str(value).strip()
    if text.lstrip("-").isdigit():
        return ERROR_STATUS_BY_INT.get(int(text), f"unknown({text})")
    return text


def normalize_error_indication(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    mapping = [
        ("No SNMP response received before timeout", "requestTimeout"),
        ("Unknown SNMP community name", "unknownCommunityName"),
        ("Unknown SNMP security name", "unknownSecurityName"),
        ("Unknown SNMP user name", "unknownUserName"),
        ("Authentication failure", "authenticationFailure"),
        ("Wrong SNMP PDU digest", "wrongDigest"),
        ("SNMP decryption error", "decryptionError"),
        ("Not in time window", "notInTimeWindow"),
        ("Unknown engine ID", "unknownEngineID"),
    ]
    for needle, token in mapping:
        if needle.lower() in text.lower():
            return token
    return text


def is_timeout(indication: str | None) -> bool:
    return bool(indication and ("timeout" in indication.lower() or "timedout" in indication.lower()))


def is_auth_error(indication: str | None) -> bool:
    if not indication:
        return False
    text = indication.lower()
    return any(
        token in text
        for token in ("auth", "unknowncommunity", "unknownsecurity", "unknownuser", "decrypt", "digest", "engineid")
    )


def is_rejection_status(status: str, version: str) -> bool:
    if status in REJECTION_STATUSES:
        return True
    if version == "v1":
        # v1 agents commonly map v2c exception statuses onto these five values
        return status in V1_ERROR_ALIASES
    return False
