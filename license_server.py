# path: EVENT_manager/license_server.py
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


APP_TITLE = "EventManagerPro License Server"
DB_PATH = Path("data") / "license_server.db"
SETTINGS_PATH = Path("data") / "license_server_settings.json"
DEFAULT_PRODUCT_CODE = "EventManagerPro"
DEFAULT_API_TOKEN = "CHANGE_ME"
ENV_API_TOKEN_NAME = "LICENSE_SERVER_API_TOKEN"
DEFAULT_MAX_DEVICES = 2
DEFAULT_LICENSE_DURATION_DAYS = 365

# ── Plans, du plus bas au plus haut ─────────────────────────────────────────
# ⚠️ DOIT RESTER SYNCHRONISÉ avec EVENT_manager/core/entitlements.py
#    (PLAN_ORDER et _ALIASES). Le logiciel client décide de ce que chaque plan
#    débloque ; le serveur, lui, n'a besoin que de l'ORDRE, pour interdire les
#    rétrogradations et savoir si l'on part d'une démo.
PLAN_ORDER = ["demo", "basic", "pro", "expert"]
PLAN_ALIASES = {
    "demo": "demo", "démo": "demo", "trial": "demo", "essai": "demo", "test": "demo",
    "basic": "basic", "base": "basic", "standard": "basic",
    "pro": "pro", "professionnel": "pro", "premium": "pro", "plus": "pro",
    "expert": "expert", "entreprise": "expert", "ultimate": "expert",
}


def normalize_plan(value: str | None) -> str:
    """Ramène un libellé de plan à sa forme canonique. `plan_name` est du
    texte libre en base (« Pro » par défaut) : sans normalisation, comparer
    des rangs serait faux dès qu'un libellé diffère d'une majuscule."""
    p = str(value or "").strip().lower()
    p = PLAN_ALIASES.get(p, p)
    return p if p in PLAN_ORDER else "demo"


# Tarifs annuels par plan, en euros. Servent UNIQUEMENT à proposer un montant
# au prorata lors d'une mise à niveau — le serveur n'encaisse rien. Modifiables
# sans redéploiement via data/license_server_settings.json (clé "plan_prices").
DEFAULT_PLAN_PRICES = {"demo": 0.0, "basic": 29.0, "pro": 49.0, "expert": 79.0}


def plan_price(plan: str | None) -> float:
    prices = SETTINGS.get("plan_prices") or {}
    if not isinstance(prices, dict):
        prices = {}
    key = normalize_plan(plan)
    try:
        return float(prices.get(key, DEFAULT_PLAN_PRICES.get(key, 0.0)))
    except Exception:
        return float(DEFAULT_PLAN_PRICES.get(key, 0.0))


def plan_rank(value: str | None) -> int:
    try:
        return PLAN_ORDER.index(normalize_plan(value))
    except Exception:
        return 0
DEFAULT_OFFLINE_GRACE_DAYS = 7


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse_iso(value: str | None) -> Optional[datetime]:
    if not value:
        return None
    try:
        txt = str(value).strip()
        if not txt:
            return None
        if txt.endswith("Z"):
            txt = txt[:-1] + "+00:00"
        return datetime.fromisoformat(txt)
    except Exception:
        return None


def _normalize_license_key(value: str) -> str:
    return str(value or "").strip().upper()


def _normalize_token(value: str | None) -> str:
    return str(value or "").strip()


def _machine_fingerprint(machine_id: str) -> str:
    raw = str(machine_id or "").strip().encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _random_license_key() -> str:
    chunks = [secrets.token_hex(2).upper() for _ in range(4)]
    return "-".join(chunks)


def _random_activation_id() -> str:
    return "ACT-" + secrets.token_hex(8).upper()


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _load_settings() -> dict[str, Any]:
    _ensure_parent(SETTINGS_PATH)
    if SETTINGS_PATH.exists():
        try:
            data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    data = {
        "api_token": DEFAULT_API_TOKEN,
        "product_code": DEFAULT_PRODUCT_CODE,
        "default_max_devices": DEFAULT_MAX_DEVICES,
        "plan_prices": dict(DEFAULT_PLAN_PRICES),
        "default_license_duration_days": DEFAULT_LICENSE_DURATION_DAYS,
        "default_offline_grace_days": DEFAULT_OFFLINE_GRACE_DAYS,
    }
    SETTINGS_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


SETTINGS = _load_settings()


@contextmanager
def _db() -> sqlite3.Connection:
    _ensure_parent(DB_PATH)
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _ensure_schema() -> None:
    with _db() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT NOT NULL UNIQUE,
                product_code TEXT NOT NULL,
                customer_name TEXT NOT NULL DEFAULT '',
                plan_name TEXT NOT NULL DEFAULT 'Pro',
                status TEXT NOT NULL DEFAULT 'active',
                max_devices INTEGER NOT NULL DEFAULT 2,
                offline_grace_days INTEGER NOT NULL DEFAULT 7,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT ''
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                activation_id TEXT NOT NULL UNIQUE,
                license_id INTEGER NOT NULL,
                machine_hash TEXT NOT NULL,
                machine_id TEXT NOT NULL DEFAULT '',
                machine_name TEXT NOT NULL DEFAULT '',
                hostname TEXT NOT NULL DEFAULT '',
                platform TEXT NOT NULL DEFAULT '',
                platform_release TEXT NOT NULL DEFAULT '',
                app_name TEXT NOT NULL DEFAULT '',
                app_version TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                last_validated_at TEXT NOT NULL,
                last_ip TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE,
                UNIQUE(license_id, machine_hash)
            )
            """
        )
        # Historique des mises à niveau : utile en comptabilité et en cas de
        # contestation (quand, de quel plan vers quel plan, combien de jours
        # restaient, et quel montant a été facturé au prorata).
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS plan_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT NOT NULL,
                old_plan TEXT NOT NULL,
                new_plan TEXT NOT NULL,
                days_remaining INTEGER NOT NULL DEFAULT 0,
                expires_at_before TEXT NOT NULL DEFAULT '',
                expires_at_after TEXT NOT NULL DEFAULT '',
                amount_charged TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                license_key TEXT NOT NULL DEFAULT '',
                activation_id TEXT NOT NULL DEFAULT '',
                machine_hash TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )


def _seed_demo_license() -> None:
    now = _utc_now()
    with _db() as con:
        row = con.execute("SELECT 1 FROM licenses LIMIT 1").fetchone()
        if row:
            return
        expires_at = now + timedelta(days=int(SETTINGS.get("default_license_duration_days", DEFAULT_LICENSE_DURATION_DAYS)))
        con.execute(
            """
            INSERT INTO licenses(
                license_key, product_code, customer_name, plan_name, status,
                max_devices, offline_grace_days, expires_at, created_at, updated_at, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            ,
            (
                "DEMO-EVENT-0001",
                str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE),
                "Client Démo",
                "Pro",
                "active",
                int(SETTINGS.get("default_max_devices", DEFAULT_MAX_DEVICES)),
                int(SETTINGS.get("default_offline_grace_days", DEFAULT_OFFLINE_GRACE_DAYS)),
                _iso(expires_at),
                _iso(now),
                _iso(now),
                "Licence de démonstration créée automatiquement.",
            ),
        )


def _log_event(
    event_type: str,
    *,
    license_key: str = "",
    activation_id: str = "",
    machine_hash: str = "",
    details: Optional[dict[str, Any]] = None,
    con: sqlite3.Connection | None = None,
) -> None:
    sql = """
        INSERT INTO audit_log(event_type, license_key, activation_id, machine_hash, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    params = (
        event_type,
        _normalize_license_key(license_key),
        str(activation_id or "").strip(),
        str(machine_hash or "").strip(),
        json.dumps(details or {}, ensure_ascii=False),
        _iso(_utc_now()),
    )
    if con is not None:
        con.execute(sql, params)
        return
    with _db() as local_con:
        local_con.execute(sql, params)


def _require_api_token(x_api_token: str | None) -> None:
    expected = _normalize_token(os.getenv(ENV_API_TOKEN_NAME)) or _normalize_token(SETTINGS.get("api_token"))
    got = _normalize_token(x_api_token)
    if not expected or expected == DEFAULT_API_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="api_token non configuré côté serveur. Définis LICENSE_SERVER_API_TOKEN sur Render ou modifie data/license_server_settings.json.",
        )
    if not secrets.compare_digest(got, expected):
        raise HTTPException(status_code=401, detail="Token API invalide.")


def _row_to_license_payload(
    license_row: sqlite3.Row,
    *,
    activation_id: str = "",
    used_devices: int = 0,
    validated_at: Optional[datetime] = None,
    next_check_at: Optional[datetime] = None,
    message: str = "",
) -> dict[str, Any]:
    return {
        "ok": True,
        "status": str(license_row["status"]),
        "message": message or "Licence valide.",
        "activation_id": str(activation_id or ""),
        "license_key": str(license_row["license_key"]),
        "product_code": str(license_row["product_code"]),
        "customer_name": str(license_row["customer_name"] or ""),
        "plan_name": str(license_row["plan_name"] or ""),
        "max_devices": int(license_row["max_devices"] or 0),
        "used_devices": int(used_devices),
        "expires_at": str(license_row["expires_at"] or ""),
        "validated_at": _iso(validated_at),
        "next_check_at": _iso(next_check_at),
        "offline_grace_days": int(license_row["offline_grace_days"] or 0),
    }


def _license_status_error(license_row: sqlite3.Row) -> Optional[str]:
    status = str(license_row["status"] or "").strip().lower()
    if status not in {"active", "trial"}:
        return status or "blocked"
    expires_at = _parse_iso(license_row["expires_at"])
    if expires_at is not None and expires_at < _utc_now():
        return "expired"
    return None


def _get_license_row(con: sqlite3.Connection, license_key: str) -> sqlite3.Row:
    row = con.execute(
        "SELECT * FROM licenses WHERE license_key=?",
        (_normalize_license_key(license_key),),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Licence introuvable.")
    return row


def _count_active_activations(con: sqlite3.Connection, license_id: int) -> int:
    row = con.execute(
        "SELECT COUNT(*) AS n FROM activations WHERE license_id=? AND status='active'",
        (int(license_id),),
    ).fetchone()
    return int(row["n"] if row else 0)


def _find_activation(
    con: sqlite3.Connection,
    *,
    license_id: int,
    machine_hash: str,
    activation_id: str = "",
) -> sqlite3.Row | None:
    if activation_id:
        row = con.execute(
            """
            SELECT * FROM activations
            WHERE license_id=? AND activation_id=?
            """
            ,
            (int(license_id), str(activation_id).strip()),
        ).fetchone()
        if row is not None:
            return row
    return con.execute(
        """
        SELECT * FROM activations
        WHERE license_id=? AND machine_hash=?
        """
        ,
        (int(license_id), str(machine_hash).strip()),
    ).fetchone()


class ActivationRequest(BaseModel):
    product_code: str = Field(default=DEFAULT_PRODUCT_CODE)
    app_name: str = Field(default=DEFAULT_PRODUCT_CODE)
    app_version: str = Field(default="1.0.0")
    license_key: str
    machine_id: str
    machine_name: str = Field(default="")
    platform: str = Field(default="")
    platform_release: str = Field(default="")
    hostname: str = Field(default="")
    activation_id: str = Field(default="")


class ValidationRequest(BaseModel):
    product_code: str = Field(default=DEFAULT_PRODUCT_CODE)
    app_name: str = Field(default=DEFAULT_PRODUCT_CODE)
    app_version: str = Field(default="1.0.0")
    license_key: str
    machine_id: str
    machine_name: str = Field(default="")
    platform: str = Field(default="")
    platform_release: str = Field(default="")
    hostname: str = Field(default="")
    activation_id: str = Field(default="")


class DeactivationRequest(BaseModel):
    product_code: str = Field(default=DEFAULT_PRODUCT_CODE)
    license_key: str
    machine_id: str
    activation_id: str = Field(default="")


class CreateLicenseRequest(BaseModel):
    customer_name: str = Field(default="")
    plan_name: str = Field(default="Pro")
    max_devices: int = Field(default=DEFAULT_MAX_DEVICES, ge=1, le=100)
    offline_grace_days: int = Field(default=DEFAULT_OFFLINE_GRACE_DAYS, ge=1, le=365)
    duration_days: int = Field(default=DEFAULT_LICENSE_DURATION_DAYS, ge=1, le=3650)
    notes: str = Field(default="")
    product_code: str = Field(default=DEFAULT_PRODUCT_CODE)
    license_key: str = Field(default="")


class UpdateLicenseStatusRequest(BaseModel):
    status: str
    notes: str = Field(default="")


class UpgradePlanRequest(BaseModel):
    """Mise à niveau d'une licence existante vers un plan SUPÉRIEUR."""
    plan_name: str
    # Montant réellement encaissé (au prorata), pour l'historique. Texte libre :
    # le serveur ne fait pas de comptabilité, il conserve la trace.
    amount_charged: str = Field(default="")
    notes: str = Field(default="")
    # Durée appliquée UNIQUEMENT lors d'une sortie de démo (voir endpoint).
    duration_days: int = Field(default=DEFAULT_LICENSE_DURATION_DAYS, ge=1, le=3650)


_ensure_schema()
_seed_demo_license()

app = FastAPI(title=APP_TITLE)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": APP_TITLE,
        "product_code": str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE),
        "server_time": _iso(_utc_now()),
    }


@app.post("/activate")
def activate(payload: ActivationRequest) -> dict[str, Any]:
    if _normalize_license_key(payload.product_code) != _normalize_license_key(str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE)):
        raise HTTPException(status_code=400, detail="product_code invalide.")

    license_key = _normalize_license_key(payload.license_key)
    machine_hash = _machine_fingerprint(payload.machine_id)
    now = _utc_now()

    with _db() as con:
        license_row = _get_license_row(con, license_key)
        status_error = _license_status_error(license_row)
        if status_error:
            _log_event(
                "activate_denied",
                license_key=license_key,
                machine_hash=machine_hash,
                details={"reason": status_error},
                con=con,
            )
            raise HTTPException(status_code=403, detail=f"Licence {status_error}.")

        existing = _find_activation(
            con,
            license_id=int(license_row["id"]),
            machine_hash=machine_hash,
            activation_id=payload.activation_id,
        )
        if existing is not None:
            con.execute(
                """
                UPDATE activations
                SET machine_id=?, machine_name=?, hostname=?, platform=?, platform_release=?,
                    app_name=?, app_version=?, status='active', last_validated_at=?
                WHERE id=?
                """
                ,
                (
                    payload.machine_id.strip(),
                    payload.machine_name.strip(),
                    payload.hostname.strip(),
                    payload.platform.strip(),
                    payload.platform_release.strip(),
                    payload.app_name.strip(),
                    payload.app_version.strip(),
                    _iso(now),
                    int(existing["id"]),
                ),
            )
            used_devices = _count_active_activations(con, int(license_row["id"]))
            next_check_at = now + timedelta(days=int(license_row["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS))
            _log_event(
                "activate_existing",
                license_key=license_key,
                activation_id=str(existing["activation_id"]),
                machine_hash=machine_hash,
                con=con,
            )
            return _row_to_license_payload(
                license_row,
                activation_id=str(existing["activation_id"]),
                used_devices=used_devices,
                validated_at=now,
                next_check_at=next_check_at,
                message="Licence déjà activée sur ce poste.",
            )

        used_devices = _count_active_activations(con, int(license_row["id"]))
        max_devices = int(license_row["max_devices"] or 0)
        if used_devices >= max_devices:
            _log_event(
                "activate_denied",
                license_key=license_key,
                machine_hash=machine_hash,
                details={"reason": "max_devices_reached", "used_devices": used_devices, "max_devices": max_devices},
                con=con,
            )
            raise HTTPException(status_code=403, detail="Nombre maximal d'appareils atteint.")

        activation_id = _random_activation_id()
        con.execute(
            """
            INSERT INTO activations(
                activation_id, license_id, machine_hash, machine_id, machine_name, hostname,
                platform, platform_release, app_name, app_version, status,
                created_at, last_validated_at, last_ip
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, '')
            """
            ,
            (
                activation_id,
                int(license_row["id"]),
                machine_hash,
                payload.machine_id.strip(),
                payload.machine_name.strip(),
                payload.hostname.strip(),
                payload.platform.strip(),
                payload.platform_release.strip(),
                payload.app_name.strip(),
                payload.app_version.strip(),
                _iso(now),
                _iso(now),
            ),
        )
        con.execute(
            "UPDATE licenses SET updated_at=? WHERE id=?",
            (_iso(now), int(license_row["id"])),
        )
        used_devices = _count_active_activations(con, int(license_row["id"]))
        next_check_at = now + timedelta(days=int(license_row["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS))
        _log_event(
            "activate_ok",
            license_key=license_key,
            activation_id=activation_id,
            machine_hash=machine_hash,
            con=con,
        )
        return _row_to_license_payload(
            license_row,
            activation_id=activation_id,
            used_devices=used_devices,
            validated_at=now,
            next_check_at=next_check_at,
            message="Licence activée.",
        )


@app.post("/validate")
def validate(payload: ValidationRequest) -> dict[str, Any]:
    if _normalize_license_key(payload.product_code) != _normalize_license_key(str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE)):
        raise HTTPException(status_code=400, detail="product_code invalide.")

    license_key = _normalize_license_key(payload.license_key)
    machine_hash = _machine_fingerprint(payload.machine_id)
    now = _utc_now()

    with _db() as con:
        license_row = _get_license_row(con, license_key)
        status_error = _license_status_error(license_row)
        if status_error:
            _log_event(
                "validate_denied",
                license_key=license_key,
                machine_hash=machine_hash,
                details={"reason": status_error},
                con=con,
            )
            raise HTTPException(status_code=403, detail=f"Licence {status_error}.")

        activation = _find_activation(
            con,
            license_id=int(license_row["id"]),
            machine_hash=machine_hash,
            activation_id=payload.activation_id,
        )
        if activation is None:
            _log_event(
                "validate_denied",
                license_key=license_key,
                machine_hash=machine_hash,
                details={"reason": "activation_not_found"},
                con=con,
            )
            raise HTTPException(status_code=403, detail="Activation introuvable pour ce poste.")
        if str(activation["status"]).strip().lower() != "active":
            _log_event(
                "validate_denied",
                license_key=license_key,
                activation_id=str(activation["activation_id"]),
                machine_hash=machine_hash,
                details={"reason": "activation_inactive"},
                con=con,
            )
            raise HTTPException(status_code=403, detail="Activation inactive.")

        con.execute(
            """
            UPDATE activations
            SET machine_id=?, machine_name=?, hostname=?, platform=?, platform_release=?,
                app_name=?, app_version=?, last_validated_at=?
            WHERE id=?
            """
            ,
            (
                payload.machine_id.strip(),
                payload.machine_name.strip(),
                payload.hostname.strip(),
                payload.platform.strip(),
                payload.platform_release.strip(),
                payload.app_name.strip(),
                payload.app_version.strip(),
                _iso(now),
                int(activation["id"]),
            ),
        )
        con.execute(
            "UPDATE licenses SET updated_at=? WHERE id=?",
            (_iso(now), int(license_row["id"])),
        )
        used_devices = _count_active_activations(con, int(license_row["id"]))
        next_check_at = now + timedelta(days=int(license_row["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS))
        _log_event(
            "validate_ok",
            license_key=license_key,
            activation_id=str(activation["activation_id"]),
            machine_hash=machine_hash,
            con=con,
        )
        return _row_to_license_payload(
            license_row,
            activation_id=str(activation["activation_id"]),
            used_devices=used_devices,
            validated_at=now,
            next_check_at=next_check_at,
            message="Licence valide.",
        )


@app.post("/deactivate")
def deactivate(payload: DeactivationRequest) -> dict[str, Any]:
    if _normalize_license_key(payload.product_code) != _normalize_license_key(str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE)):
        raise HTTPException(status_code=400, detail="product_code invalide.")

    license_key = _normalize_license_key(payload.license_key)
    machine_hash = _machine_fingerprint(payload.machine_id)
    now = _utc_now()

    with _db() as con:
        license_row = _get_license_row(con, license_key)
        activation = _find_activation(
            con,
            license_id=int(license_row["id"]),
            machine_hash=machine_hash,
            activation_id=payload.activation_id,
        )
        if activation is None:
            _log_event(
                "deactivate_missing",
                license_key=license_key,
                machine_hash=machine_hash,
                con=con,
            )
            return {
                "ok": True,
                "status": "deactivated",
                "message": "Aucune activation active à supprimer pour ce poste.",
                "activation_id": str(payload.activation_id or ""),
            }

        con.execute(
            """
            UPDATE activations
            SET status='deactivated', last_validated_at=?
            WHERE id=?
            """
            ,
            (_iso(now), int(activation["id"])),
        )
        con.execute(
            "UPDATE licenses SET updated_at=? WHERE id=?",
            (_iso(now), int(license_row["id"])),
        )
        used_devices = _count_active_activations(con, int(license_row["id"]))
        _log_event(
            "deactivate_ok",
            license_key=license_key,
            activation_id=str(activation["activation_id"]),
            machine_hash=machine_hash,
            con=con,
        )
        return {
            "ok": True,
            "status": "deactivated",
            "message": "Activation supprimée.",
            "activation_id": str(activation["activation_id"]),
            "used_devices": used_devices,
            "max_devices": int(license_row["max_devices"] or 0),
        }


@app.post("/admin/licenses")
def create_license(payload: CreateLicenseRequest, x_api_token: str | None = Header(default=None)) -> dict[str, Any]:
    _require_api_token(x_api_token)
    now = _utc_now()
    license_key = _normalize_license_key(payload.license_key) or _random_license_key()
    expires_at = now + timedelta(days=int(payload.duration_days))

    with _db() as con:
        existing = con.execute(
            "SELECT 1 FROM licenses WHERE license_key=?",
            (license_key,),
        ).fetchone()
        if existing is not None:
            raise HTTPException(status_code=409, detail="La clé de licence existe déjà.")
        con.execute(
            """
            INSERT INTO licenses(
                license_key, product_code, customer_name, plan_name, status,
                max_devices, offline_grace_days, expires_at, created_at, updated_at, notes
            ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
            """
            ,
            (
                license_key,
                _normalize_license_key(payload.product_code) or DEFAULT_PRODUCT_CODE,
                payload.customer_name.strip(),
                payload.plan_name.strip() or "Pro",
                int(payload.max_devices),
                int(payload.offline_grace_days),
                _iso(expires_at),
                _iso(now),
                _iso(now),
                payload.notes.strip(),
            ),
        )
        row = _get_license_row(con, license_key)
        _log_event("admin_create_license", license_key=license_key, con=con)
        return _row_to_license_payload(
            row,
            used_devices=0,
            validated_at=now,
            next_check_at=now + timedelta(days=int(row["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS)),
            message="Licence créée.",
        )


@app.get("/admin/licenses")
def list_licenses(x_api_token: str | None = Header(default=None)) -> dict[str, Any]:
    _require_api_token(x_api_token)
    with _db() as con:
        rows = con.execute(
            """
            SELECT l.*,
                   (SELECT COUNT(*) FROM activations a WHERE a.license_id=l.id AND a.status='active') AS used_devices
            FROM licenses l
            ORDER BY l.id DESC
            """
        ).fetchall()
        items = []
        for row in rows:
            items.append(
                {
                    "license_key": str(row["license_key"]),
                    "product_code": str(row["product_code"]),
                    "customer_name": str(row["customer_name"] or ""),
                    "plan_name": str(row["plan_name"] or ""),
                    "status": str(row["status"]),
                    "max_devices": int(row["max_devices"] or 0),
                    "used_devices": int(row["used_devices"] or 0),
                    "offline_grace_days": int(row["offline_grace_days"] or 0),
                    "expires_at": str(row["expires_at"] or ""),
                    "created_at": str(row["created_at"] or ""),
                    "updated_at": str(row["updated_at"] or ""),
                    "notes": str(row["notes"] or ""),
                }
            )
        return {"ok": True, "items": items}


@app.patch("/admin/licenses/{license_key}/status")
def update_license_status(
    license_key: str,
    payload: UpdateLicenseStatusRequest,
    x_api_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_api_token(x_api_token)
    new_status = str(payload.status or "").strip().lower()
    if new_status not in {"active", "blocked", "revoked", "expired", "trial"}:
        raise HTTPException(status_code=400, detail="Statut invalide.")

    now = _utc_now()
    with _db() as con:
        row = _get_license_row(con, license_key)
        con.execute(
            "UPDATE licenses SET status=?, notes=?, updated_at=? WHERE id=?",
            (
                new_status,
                payload.notes.strip(),
                _iso(now),
                int(row["id"]),
            ),
        )
        updated = _get_license_row(con, license_key)
        used_devices = _count_active_activations(con, int(updated["id"]))
        _log_event(
            "admin_update_status",
            license_key=_normalize_license_key(license_key),
            details={"status": new_status},
            con=con,
        )
        return _row_to_license_payload(
            updated,
            used_devices=used_devices,
            validated_at=now,
            next_check_at=now + timedelta(days=int(updated["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS)),
            message="Statut mis à jour.",
        )


def _check_upgrade_allowed(old_plan: str, new_plan: str) -> None:
    """Règles communes au devis et à l'application. Aucune rétrogradation :
    sans cette barrière, un client souscrirait Expert, exploiterait tout en
    quelques jours puis redescendrait en réclamant un remboursement."""
    if plan_rank(new_plan) < plan_rank(old_plan):
        raise HTTPException(
            status_code=409,
            detail=(f"Rétrogradation refusée : la licence est en « {old_plan} », "
                    f"passage en « {new_plan} » impossible."),
        )
    if plan_rank(new_plan) == plan_rank(old_plan):
        raise HTTPException(status_code=409, detail=f"La licence est déjà en « {old_plan} ».")


def _compute_upgrade(row: sqlite3.Row, new_plan: str, duration_days: int,
                     now: datetime) -> dict[str, Any]:
    """Calcule le montant au prorata et la date d'expiration résultante,
    SANS RIEN MODIFIER. Utilisé tel quel par le devis (lecture seule) et par
    l'application, pour que le montant annoncé avant paiement soit exactement
    celui appliqué ensuite."""
    old_plan = normalize_plan(row["plan_name"])
    expires_before = _parse_iso(row["expires_at"])
    days_remaining = max(0, (expires_before - now).days) if expires_before else 0

    if old_plan == "demo":
        # Sortie de démo : la démo n'est pas une période payée, une vraie
        # période démarre aujourd'hui.
        expires_after = now + timedelta(days=int(duration_days))
    else:
        # Plan payant → plan payant supérieur : la date ne bouge pas. C'est
        # tout l'objet de la mise à niveau.
        expires_after = expires_before

    created = _parse_iso(row["created_at"])
    total_days = None
    if created is not None and expires_before is not None:
        total_days = max(1, (expires_before - created).days)
    if not total_days:
        total_days = DEFAULT_LICENSE_DURATION_DAYS

    if old_plan == "demo":
        suggested = plan_price(new_plan)          # plein tarif
    else:
        diff = max(0.0, plan_price(new_plan) - plan_price(old_plan))
        suggested = round(diff * days_remaining / total_days, 2)

    return {
        "old_plan": old_plan,
        "new_plan": new_plan,
        "days_remaining": days_remaining,
        "total_days": total_days,
        "price_old": plan_price(old_plan),
        "price_new": plan_price(new_plan),
        "price_difference": round(plan_price(new_plan) - plan_price(old_plan), 2),
        "suggested_amount": suggested,
        "expiry_reset": bool(old_plan == "demo"),
        "expires_at_before": _iso(expires_before) if expires_before else "",
        "expires_at_after": _iso(expires_after) if expires_after else "",
        "_expires_before": expires_before,
        "_expires_after": expires_after,
    }


@app.get("/admin/licenses/{license_key}/upgrade-quote")
def upgrade_quote(
    license_key: str,
    plan_name: str,
    duration_days: int = DEFAULT_LICENSE_DURATION_DAYS,
    x_api_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """DEVIS : montant à facturer pour une mise à niveau, **sans rien changer**.

    Permet d'annoncer le prix, d'encaisser, PUIS seulement d'appliquer le
    changement. Les mêmes règles qu'à l'application sont vérifiées ici, pour
    qu'un devis affiché ne puisse pas être refusé au moment de valider.
    """
    _require_api_token(x_api_token)
    if str(plan_name or "").strip().lower() not in PLAN_ALIASES:
        raise HTTPException(
            status_code=400,
            detail=f"Plan inconnu : « {plan_name} ». Attendu : {', '.join(PLAN_ORDER)}.",
        )
    new_plan = normalize_plan(plan_name)
    with _db() as con:
        row = _get_license_row(con, license_key)
        _check_upgrade_allowed(normalize_plan(row["plan_name"]), new_plan)
        calc = _compute_upgrade(row, new_plan, int(duration_days), _utc_now())
        quote = {k: v for k, v in calc.items() if not k.startswith("_")}
        quote["license_key"] = _normalize_license_key(license_key)
        quote["customer_name"] = str(row["customer_name"] or "")
        return {"ok": True, "quote": quote}


@app.patch("/admin/licenses/{license_key}/plan")
def upgrade_license_plan(
    license_key: str,
    payload: UpgradePlanRequest,
    x_api_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Mise à niveau d'une licence EXISTANTE vers un plan supérieur.

    Règle centrale : la date d'expiration n'est PAS réinitialisée. Sans cet
    endpoint, faire passer un client de Pro à Expert imposait de créer une
    nouvelle licence — donc de lui offrir une année entière à partir du jour
    de la mise à niveau. Un client passant à Expert au bout de six mois
    repartait pour douze.

    Deux exceptions et une interdiction :
      • Sortie de DÉMO : la démo n'est pas une période payée. Passer de démo à
        un plan payant démarre bien une nouvelle période (expires_at recalculé).
      • Entre deux plans PAYANTS : expires_at strictement conservé.
      • RÉTROGRADATION INTERDITE : sinon un client souscrit Expert, exploite
        tout en quelques jours, puis redescend en réclamant un remboursement.
        Le nombre d'appareils n'est pas modifié non plus — cela relève d'une
        demande de licence distincte.
    """
    _require_api_token(x_api_token)

    new_plan = normalize_plan(payload.plan_name)
    if str(payload.plan_name or "").strip().lower() not in PLAN_ALIASES:
        raise HTTPException(
            status_code=400,
            detail=f"Plan inconnu : « {payload.plan_name} ». Attendu : {', '.join(PLAN_ORDER)}.",
        )

    now = _utc_now()
    with _db() as con:
        row = _get_license_row(con, license_key)
        old_plan = normalize_plan(row["plan_name"])

        _check_upgrade_allowed(old_plan, new_plan)

        calc = _compute_upgrade(row, new_plan, int(payload.duration_days), now)
        expires_before = calc["_expires_before"]
        expires_after = calc["_expires_after"]
        days_remaining = calc["days_remaining"]
        total_days = calc["total_days"]
        suggested = calc["suggested_amount"]

        con.execute(
            "UPDATE licenses SET plan_name=?, expires_at=?, updated_at=? WHERE id=?",
            (new_plan, _iso(expires_after) if expires_after else "", _iso(now), int(row["id"])),
        )
        con.execute(
            """
            INSERT INTO plan_changes(license_key, old_plan, new_plan, days_remaining,
                                     expires_at_before, expires_at_after,
                                     amount_charged, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _normalize_license_key(license_key), old_plan, new_plan, int(days_remaining),
                _iso(expires_before) if expires_before else "",
                _iso(expires_after) if expires_after else "",
                str(payload.amount_charged or "").strip(),
                str(payload.notes or "").strip(),
                _iso(now),
            ),
        )
        _log_event(
            "admin_upgrade_plan",
            license_key=_normalize_license_key(license_key),
            details={
                "old_plan": old_plan, "new_plan": new_plan,
                "days_remaining": days_remaining,
                "expiry_reset": bool(old_plan == "demo"),
                "suggested_amount": suggested,
                "amount_charged": str(payload.amount_charged or "").strip(),
            },
            con=con,
        )

        updated = _get_license_row(con, license_key)
        used_devices = _count_active_activations(con, int(updated["id"]))
        result = _row_to_license_payload(
            updated,
            used_devices=used_devices,
            validated_at=now,
            next_check_at=now + timedelta(days=int(updated["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS)),
            message=f"Licence mise à niveau : {old_plan} → {new_plan}.",
        )
        # Informations de facturation, à l'usage de l'outil d'administration.
        result["upgrade"] = {k: v for k, v in calc.items() if not k.startswith("_")}
        return result


@app.get("/admin/licenses/{license_key}/plan-changes")
def list_plan_changes(license_key: str, x_api_token: str | None = Header(default=None)) -> dict[str, Any]:
    """Historique des mises à niveau d'une licence (comptabilité, litiges)."""
    _require_api_token(x_api_token)
    with _db() as con:
        _get_license_row(con, license_key)   # 404 si la licence n'existe pas
        rows = con.execute(
            """
            SELECT old_plan, new_plan, days_remaining, expires_at_before,
                   expires_at_after, amount_charged, notes, created_at
            FROM plan_changes WHERE license_key=? ORDER BY id DESC
            """,
            (_normalize_license_key(license_key),),
        ).fetchall()
        return {"ok": True, "items": [dict(r) for r in rows]}


@app.get("/admin/licenses/{license_key}/activations")
def list_activations(license_key: str, x_api_token: str | None = Header(default=None)) -> dict[str, Any]:
    _require_api_token(x_api_token)
    with _db() as con:
        row = _get_license_row(con, license_key)
        acts = con.execute(
            """
            SELECT activation_id, machine_id, machine_name, hostname, platform, platform_release,
                   app_name, app_version, status, created_at, last_validated_at
            FROM activations
            WHERE license_id=?
            ORDER BY id DESC
            """
            ,
            (int(row["id"]),),
        ).fetchall()
        return {
            "ok": True,
            "license_key": _normalize_license_key(license_key),
            "items": [
                {
                    "activation_id": str(a["activation_id"]),
                    "machine_id": str(a["machine_id"] or ""),
                    "machine_name": str(a["machine_name"] or ""),
                    "hostname": str(a["hostname"] or ""),
                    "platform": str(a["platform"] or ""),
                    "platform_release": str(a["platform_release"] or ""),
                    "app_name": str(a["app_name"] or ""),
                    "app_version": str(a["app_version"] or ""),
                    "status": str(a["status"] or ""),
                    "created_at": str(a["created_at"] or ""),
                    "last_validated_at": str(a["last_validated_at"] or ""),
                }
                for a in acts
            ],
        }


@app.delete("/admin/licenses/{license_key}")
def delete_license(license_key: str, x_api_token: str | None = Header(default=None)) -> dict[str, Any]:
    _require_api_token(x_api_token)
    now = _utc_now()
    normalized_license_key = _normalize_license_key(license_key)

    with _db() as con:
        row = _get_license_row(con, normalized_license_key)
        activation_row = con.execute(
            "SELECT COUNT(*) AS n FROM activations WHERE license_id=?",
            (int(row["id"]),),
        ).fetchone()
        deleted_activations = int(activation_row["n"] if activation_row else 0)

        _log_event(
            "admin_delete_license",
            license_key=normalized_license_key,
            details={"deleted_activations": deleted_activations},
            con=con,
        )

        con.execute(
            "DELETE FROM activations WHERE license_id=?",
            (int(row["id"]),),
        )
        con.execute(
            "DELETE FROM licenses WHERE id=?",
            (int(row["id"]),),
        )

        return {
            "ok": True,
            "license_key": normalized_license_key,
            "deleted": True,
            "deleted_activations": deleted_activations,
            "deleted_at": _iso(now),
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "license_server:app",
        host="0.0.0.0",
        port=8010,
        reload=False,
    )
