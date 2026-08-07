# path: EVENT_manager/license_server.py
from __future__ import annotations

import hashlib
import html as _html
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Form, Header, HTTPException
from fastapi.responses import HTMLResponse
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


def _random_relay_id() -> str:
    """Identifiant opaque de « boîte aux lettres » RSVP — jamais la clé de
    licence elle-même, pour ne rien exposer de sensible dans les liens
    envoyés aux invités (mêmes principes que activation_id)."""
    return "RLY-" + secrets.token_hex(8).upper()


def _random_relay_secret() -> str:
    return secrets.token_urlsafe(32)


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
        # ── Boîte aux lettres RSVP ──────────────────────────────────────────
        # Permet aux invités de répondre même quand le PC du client (qui sert
        # normalement /rsvp en Wi-Fi local ou via tunnel ngrok) est éteint. Le
        # serveur ne connaît jamais les invités eux-mêmes : seulement un
        # identifiant d'installation opaque (relay_id, jamais la clé de
        # licence) et le jeton RSVP par invité déjà généré côté client.
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS rsvp_installations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                relay_id TEXT NOT NULL UNIQUE,
                relay_secret TEXT NOT NULL,
                license_key TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                last_sync_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS rsvp_pending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                relay_id TEXT NOT NULL,
                guest_token TEXT NOT NULL,
                answer TEXT NOT NULL DEFAULT '',
                comment TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(relay_id, guest_token)
            )
            """
        )
        # Détails complets d'une réponse « Oui » (accompagnants, menu,
        # régime) — même chose que ce que demande déjà le portail RSVP en
        # direct. Migration pour les installations qui avaient déjà
        # rsvp_pending sans ces colonnes.
        cols = {r["name"] for r in con.execute("PRAGMA table_info(rsvp_pending)")}
        for col, ddl in (
            ("plus_ones", "INTEGER NOT NULL DEFAULT 0"),
            ("children", "INTEGER NOT NULL DEFAULT 0"),
            ("meal", "TEXT NOT NULL DEFAULT ''"),
            ("diet", "TEXT NOT NULL DEFAULT ''"),
            ("companions_json", "TEXT NOT NULL DEFAULT ''"),
        ):
            if col not in cols:
                try:
                    con.execute(f"ALTER TABLE rsvp_pending ADD COLUMN {col} {ddl}")
                except Exception:
                    pass


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


def _require_relay_installation(con: sqlite3.Connection, relay_id: str, x_relay_secret: str | None) -> sqlite3.Row:
    row = con.execute(
        "SELECT * FROM rsvp_installations WHERE relay_id=?",
        (str(relay_id or "").strip(),),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Installation RSVP inconnue.")
    if not secrets.compare_digest(_normalize_token(x_relay_secret), str(row["relay_secret"])):
        raise HTTPException(status_code=401, detail="Secret RSVP invalide.")
    return row


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


def _key_compact(value: str) -> str:
    """Clé réduite à ses seuls caractères significatifs (sans tirets, espaces
    ni points), en majuscules."""
    txt = _normalize_license_key(value)
    for sep in ("-", " ", "\t", "."):
        txt = txt.replace(sep, "")
    return txt


def _get_license_row(con: sqlite3.Connection, license_key: str) -> sqlite3.Row:
    row = con.execute(
        "SELECT * FROM licenses WHERE license_key=?",
        (_normalize_license_key(license_key),),
    ).fetchone()
    if row is not None:
        return row
    # Repli tolérant à la mise en forme : une clé saisie ou transmise SANS ses
    # tirets (« 4C1216B555B205CF » au lieu de « 4C12-16B5-55B2-05CF ») était
    # jusqu'ici déclarée « Licence introuvable », alors qu'il s'agit de la même
    # licence. Le client ne voyait qu'un masque « 4C12-****-****-05CF »,
    # identique dans les deux cas — le problème était donc invisible.
    # On compare ici sans les séparateurs, sans rien changer au stockage.
    row = con.execute(
        "SELECT * FROM licenses "
        "WHERE REPLACE(REPLACE(REPLACE(UPPER(license_key), '-', ''), ' ', ''), '.', '') = ?",
        (_key_compact(license_key),),
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


def _license_row_from_activation(con: sqlite3.Connection, activation_id: str,
                                 machine_hash: str) -> sqlite3.Row:
    """Retrouve la licence à partir de l'ACTIVATION, quand la clé n'est pas
    transmise.

    Le logiciel client ne conserve JAMAIS la clé en clair sur le poste (par
    sécurité : seuls un masque et une empreinte sont stockés). Il valide donc
    avec son `activation_id`, la clé partant vide. Le serveur exigeait
    pourtant la clé et répondait « Licence introuvable » — un message d'autant
    plus trompeur que la licence existait bel et bien, et que l'utilisateur
    voyait sa clé masquée affichée correctement dans le logiciel.
    """
    row = None
    aid = str(activation_id or "").strip()
    if aid:
        row = con.execute(
            "SELECT l.* FROM licenses l JOIN activations a ON a.license_id = l.id "
            "WHERE a.activation_id = ?",
            (aid,),
        ).fetchone()
    if row is None and machine_hash:
        # Repli : ce poste est peut-être activé sous un autre identifiant.
        row = con.execute(
            "SELECT l.* FROM licenses l JOIN activations a ON a.license_id = l.id "
            "WHERE a.machine_hash = ? AND a.status = 'active' "
            "ORDER BY a.last_validated_at DESC LIMIT 1",
            (str(machine_hash).strip(),),
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Aucune licence activée pour ce poste (activation inconnue).",
        )
    return row


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


class RsvpRegisterRequest(BaseModel):
    """Un seul enregistrement par installation cliente, au premier besoin —
    le relay_id + relay_secret renvoyés sont ensuite conservés localement.

    S'authentifie par activation_id, PAS par license_key : le logiciel
    client ne conserve jamais la clé en clair sur le poste après activation
    (voir _license_row_from_activation). machine_id sert de repli si
    l'activation_id fourni ne correspond à rien (même logique que /validate)."""
    product_code: str = Field(default=DEFAULT_PRODUCT_CODE)
    activation_id: str = Field(default="")
    machine_id: str = Field(default="")


class RsvpAnswerRequest(BaseModel):
    """Soumise par le NAVIGATEUR de l'invité — aucune donnée personnelle,
    juste sa réponse. Le serveur ne connaît ni son nom ni son e-mail."""
    answer: str
    comment: str = Field(default="")


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
        # Clé absente (cas normal : le client ne la stocke pas en clair) →
        # on identifie la licence par l'activation de ce poste.
        if license_key:
            license_row = _get_license_row(con, license_key)
        else:
            license_row = _license_row_from_activation(
                con, payload.activation_id, machine_hash)
            license_key = _normalize_license_key(str(license_row["license_key"] or ""))
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


# ═══════════════════════════════════════════════════════════════════════════
# Boîte aux lettres RSVP
#
# Objectif : un invité peut répondre même quand le PC du client est éteint
# (jusqu'ici, /rsvp n'était servi que par le PC du client lui-même, en Wi-Fi
# local ou via un tunnel ngrok qu'il faut laisser actif). Ce service ne
# remplace pas ça — il donne un filet toujours disponible.
#
# Confidentialité : ce serveur ne connaît JAMAIS l'invité (ni son nom, ni son
# e-mail). Seul le jeton RSVP par invité — déjà généré côté client, déjà
# imprévisible — transite ici, avec sa réponse. Le logiciel du client vient
# récupérer les réponses en attente puis les efface d'ici (accusé de
# réception explicite : GET renvoie ce qui est en attente SANS l'effacer,
# pour ne rien perdre si le client plante avant d'avoir traité la réponse).
# ═══════════════════════════════════════════════════════════════════════════

_RSVP_ANSWER_LABELS = {"oui": "Présent(e)", "non": "Absent(e)", "peut-être": "Incertain(e)"}


def _rsvp_html_page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#0b1224; color:#f4f7fb;
         display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:20px; }}
  .card {{ background:#131b2e; border:1px solid #2a3550; border-radius:14px; padding:28px 24px; max-width:420px; width:100%; }}
  h1 {{ font-size:20px; margin:0 0 16px; }}
  label {{ display:block; margin:14px 0 6px; font-size:14px; color:#c7d0e0; }}
  .choix {{ display:flex; gap:8px; flex-wrap:wrap; }}
  .choix label {{ background:#1b2440; border:1px solid #2a3550; border-radius:8px; padding:10px 14px;
                  cursor:pointer; margin:0; font-size:14px; flex:1; text-align:center; }}
  .choix input {{ display:none; }}
  .choix input:checked + span {{ font-weight:700; }}
  textarea, input[type="text"], input[type="number"], select {{
              width:100%; box-sizing:border-box; background:#0b1224; color:#f4f7fb; border:1px solid #2a3550;
              border-radius:8px; padding:10px; font-family:inherit; font-size:14px; }}
  textarea {{ min-height:70px; }}
  .row {{ display:flex; gap:8px; }}
  .row > div {{ flex:1; }}
  button {{ margin-top:18px; width:100%; padding:12px; background:#2563eb; color:#fff; border:none;
            border-radius:8px; font-size:15px; cursor:pointer; }}
  p.hint {{ color:#8b95ab; font-size:13px; }}
  .souscat {{ font-weight:700; font-size:12px; color:#7c9cff; margin:16px 0 2px; }}
</style></head>
<body><div class="card">{body}</div></body></html>"""


def _rsvp_form_page(relay_id: str, token: str, current_answer: str = "", current_comment: str = "",
                     current_plus_ones: int = 0, current_children: int = 0,
                     current_meal: str = "", current_diet: str = "",
                     current_companions: list | None = None) -> str:
    options = ""
    for value, label in (("oui", "Présent(e)"), ("non", "Absent(e)"), ("peut-être", "Incertain(e)")):
        checked = "checked" if value == current_answer else ""
        options += (f'<label><input type="radio" name="answer" value="{value}" {checked} required '
                    f'onchange="_toggleExtra()"><span>{label}</span></label>')
    # Le jeton reste en paramètre de requête (?t=...), pas en segment de
    # chemin : ça permet à /{relay_id}/rsvp de correspondre exactement au
    # format déjà utilisé par le logiciel client pour ses propres liens
    # RSVP (core/mailmerge.py : f"{base}/rsvp?t={token}"), sans rien avoir
    # à changer côté appelant.
    from urllib.parse import quote
    action = f"/{quote(str(relay_id), safe='')}/rsvp?t={quote(str(token), safe='')}"
    import json as _json
    # Réponse (commentaire/menu/régime) et noms d'accompagnants : texte saisi
    # par un invité, jamais fait confiance tel quel — échappé avant d'être
    # réinjecté dans la page (elle est reservie telle quelle si l'invité
    # rouvre son lien). Pour le JSON injecté dans <script>, on échappe aussi
    # "<" pour empêcher une évasion via "</script>" dans un nom.
    current_comment = _html.escape(str(current_comment or ""))
    current_meal = _html.escape(str(current_meal or ""))
    current_diet = _html.escape(str(current_diet or ""))
    companions_js = _json.dumps(current_companions or [], ensure_ascii=False).replace("<", "\\u003c")
    # Même informations que le portail RSVP en direct (accompagnants, menu,
    # régime) — affichées seulement si « Présent(e) » est coché, en JS, pour
    # rester en un seul aller-retour (pas de second POST intermédiaire comme
    # sur le portail en direct).
    body = f"""
      <h1>Confirmez votre présence</h1>
      <form method="post" action="{action}" onsubmit="return _beforeSubmit()">
        <div class="choix">{options}</div>

        <div id="extra" style="display:none">
          <div class="row">
            <div><label>Accompagnants adultes</label>
              <input type="number" id="po" name="plus_ones" min="0" max="20" value="{int(current_plus_ones or 0)}"
                     inputmode="numeric" oninput="_rebuildNames()"></div>
            <div><label>Enfants</label>
              <input type="number" id="ch" name="children" min="0" max="20" value="{int(current_children or 0)}"
                     inputmode="numeric" oninput="_rebuildNames()"></div>
          </div>
          <div id="names"></div>
          <label>Choix du menu / préférence (facultatif)</label>
          <input type="text" name="meal" value="{current_meal}" placeholder="ex. plat végétarien">
          <label>Allergies / régime alimentaire (facultatif)</label>
          <textarea name="diet" placeholder="ex. sans gluten, allergie arachide…">{current_diet}</textarea>
          <input type="hidden" name="companions" id="companions">
        </div>

        <label for="comment">Un mot pour l'organisateur (facultatif)</label>
        <textarea id="comment" name="comment">{current_comment}</textarea>
        <button type="submit">Envoyer ma réponse</button>
      </form>
      <p class="hint">Votre réponse sera prise en compte dès que l'organisateur sera reconnecté.</p>
    <script>
      var _savedCompanions = {companions_js};
      function _toggleExtra() {{
        var oui = document.querySelector('input[name="answer"]:checked');
        var vis = !!(oui && oui.value === 'oui');
        document.getElementById('extra').style.display = vis ? 'block' : 'none';
        if (vis) _rebuildNames();
      }}
      function _esc(s) {{
        // Les noms d'accompagnants viennent d'un invité, jamais fait confiance
        // tel quel avant de le réinjecter dans du HTML via innerHTML.
        var d = document.createElement('div');
        d.textContent = String(s == null ? '' : s);
        return d.innerHTML.replace(/"/g, '&quot;');
      }}
      function _cRows(kind, label, n) {{
        var h = '';
        for (var i = 0; i < n; i++) {{
          var saved = _savedCompanions.filter(function(c) {{ return c.type === kind; }})[i] || {{}};
          h += '<div class="row"><div><label>' + label + ' ' + (i+1) + ' — prénom</label>' +
               '<input type="text" class="cn-fn" data-kind="' + kind + '" value="' + _esc(saved.first_name) +
               '" autocomplete="off"></div>' +
               '<div><label>nom</label><input type="text" class="cn-ln" data-kind="' + kind + '" value="' +
               _esc(saved.last_name) + '" autocomplete="off"></div></div>';
        }}
        return h;
      }}
      function _rebuildNames() {{
        var poEl = document.getElementById('po'), chEl = document.getElementById('ch');
        var p = Math.max(0, Math.min(20, parseInt((poEl && poEl.value) || 0) || 0));
        var c = Math.max(0, Math.min(20, parseInt((chEl && chEl.value) || 0) || 0));
        var el = document.getElementById('names'); if (!el) return;
        var t = (p || c) ? '<div class="souscat">Noms pour le plan de table (facultatif)</div>' : '';
        el.innerHTML = t + _cRows('adult', 'Adulte', p) + _cRows('child', 'Enfant', c);
      }}
      function _beforeSubmit() {{
        var list = [];
        document.querySelectorAll('.cn-fn').forEach(function(fnEl, i) {{
          var lnEl = document.querySelectorAll('.cn-ln')[i];
          var fn = (fnEl.value || '').trim(), ln = (lnEl && lnEl.value || '').trim();
          if (fn || ln) list.push({{type: fnEl.getAttribute('data-kind'), first_name: fn, last_name: ln}});
        }});
        var el = document.getElementById('companions');
        if (el) el.value = JSON.stringify(list);
        return true;
      }}
      _toggleExtra();
    </script>
    """
    return _rsvp_html_page("Confirmez votre présence", body)


def _rsvp_confirm_page(answer: str) -> str:
    label = _RSVP_ANSWER_LABELS.get(answer, answer)
    body = f"""
      <h1>Merci !</h1>
      <p>Votre réponse (« {label} ») a bien été enregistrée.</p>
      <p class="hint">Elle sera prise en compte dès que l'organisateur sera reconnecté —
      vous pouvez revenir sur ce lien à tout moment pour la modifier.</p>
    """
    return _rsvp_html_page("Merci", body)


def _rsvp_invalid_page(message: str) -> str:
    return _rsvp_html_page("Lien invalide", f"<h1>Lien invalide</h1><p>{message}</p>")


@app.post("/rsvp/register")
def rsvp_register(payload: RsvpRegisterRequest) -> dict[str, Any]:
    if _normalize_license_key(payload.product_code) != _normalize_license_key(str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE)):
        raise HTTPException(status_code=400, detail="product_code invalide.")

    machine_hash = _machine_fingerprint(payload.machine_id) if payload.machine_id else ""
    now = _utc_now()

    with _db() as con:
        license_row = _license_row_from_activation(con, payload.activation_id, machine_hash)
        license_key = str(license_row["license_key"])
        status_error = _license_status_error(license_row)
        if status_error:
            raise HTTPException(status_code=403, detail=f"Licence {status_error}.")

        relay_id = _random_relay_id()
        relay_secret = _random_relay_secret()
        con.execute(
            """
            INSERT INTO rsvp_installations(relay_id, relay_secret, license_key, created_at, last_sync_at)
            VALUES (?, ?, ?, ?, '')
            """,
            (relay_id, relay_secret, license_key, _iso(now)),
        )
        _log_event(
            "rsvp_register",
            license_key=license_key,
            activation_id=payload.activation_id.strip(),
            machine_hash=machine_hash,
            details={"relay_id": relay_id, "machine_id": payload.machine_id.strip()},
            con=con,
        )
        return {"ok": True, "relay_id": relay_id, "relay_secret": relay_secret}


class RsvpAckRequest(BaseModel):
    tokens: list[str] = Field(default_factory=list)


# Routes /rsvp/sync/... déclarées AVANT /rsvp/{relay_id}/{token} : FastAPI
# fait correspondre les routes dans l'ordre de déclaration, et {relay_id}/{token}
# capturerait sinon "sync"/"<relay_id>" comme s'il s'agissait d'un jeton invité.
@app.get("/rsvp/sync/{relay_id}")
def rsvp_sync(relay_id: str, x_relay_secret: str | None = Header(default=None)) -> dict[str, Any]:
    now = _utc_now()
    with _db() as con:
        _require_relay_installation(con, relay_id, x_relay_secret)
        rows = con.execute(
            "SELECT guest_token, answer, comment, plus_ones, children, meal, diet, "
            "companions_json, updated_at FROM rsvp_pending WHERE relay_id=? ORDER BY id",
            (relay_id,),
        ).fetchall()
        con.execute(
            "UPDATE rsvp_installations SET last_sync_at=? WHERE relay_id=?",
            (_iso(now), relay_id),
        )
        items = []
        for r in rows:
            try:
                companions = json.loads(r["companions_json"] or "[]")
                if not isinstance(companions, list):
                    companions = []
            except Exception:
                companions = []
            items.append({
                "token": str(r["guest_token"]),
                "answer": str(r["answer"]),
                "comment": str(r["comment"] or ""),
                "plus_ones": int(r["plus_ones"] or 0),
                "children": int(r["children"] or 0),
                "meal": str(r["meal"] or ""),
                "diet": str(r["diet"] or ""),
                "companions": companions,
                "updated_at": str(r["updated_at"]),
            })
        return {"ok": True, "items": items}


@app.post("/rsvp/sync/{relay_id}/ack")
def rsvp_sync_ack(relay_id: str, payload: RsvpAckRequest, x_relay_secret: str | None = Header(default=None)) -> dict[str, Any]:
    with _db() as con:
        _require_relay_installation(con, relay_id, x_relay_secret)
        tokens = [str(t).strip() for t in (payload.tokens or []) if str(t or "").strip()]
        deleted = 0
        for t in tokens:
            cur = con.execute(
                "DELETE FROM rsvp_pending WHERE relay_id=? AND guest_token=?",
                (relay_id, t),
            )
            deleted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        return {"ok": True, "deleted": deleted}


# Chemin /{relay_id}/rsvp (jeton en paramètre de requête ?t=...), et non
# /rsvp/{relay_id}/{token} : voir le commentaire dans _rsvp_form_page.
@app.get("/{relay_id}/rsvp", response_class=HTMLResponse)
def rsvp_form(relay_id: str, t: str = "") -> HTMLResponse:
    token = str(t or "").strip()
    with _db() as con:
        installation = con.execute(
            "SELECT 1 FROM rsvp_installations WHERE relay_id=?", (str(relay_id or "").strip(),)
        ).fetchone()
        if installation is None:
            return HTMLResponse(_rsvp_invalid_page("Ce lien ne correspond à aucun événement connu."), status_code=404)
        if not token:
            return HTMLResponse(_rsvp_invalid_page("Lien incomplet (jeton manquant)."), status_code=400)
        existing = con.execute(
            "SELECT answer, comment, plus_ones, children, meal, diet, companions_json "
            "FROM rsvp_pending WHERE relay_id=? AND guest_token=?",
            (relay_id, token),
        ).fetchone()
        current_answer = str(existing["answer"]) if existing else ""
        current_comment = str(existing["comment"]) if existing else ""
        current_plus_ones = int(existing["plus_ones"] or 0) if existing else 0
        current_children = int(existing["children"] or 0) if existing else 0
        current_meal = str(existing["meal"] or "") if existing else ""
        current_diet = str(existing["diet"] or "") if existing else ""
        try:
            current_companions = json.loads((existing["companions_json"] if existing else "") or "[]")
            if not isinstance(current_companions, list):
                current_companions = []
        except Exception:
            current_companions = []
    return HTMLResponse(_rsvp_form_page(relay_id, token, current_answer, current_comment,
                                        current_plus_ones, current_children,
                                        current_meal, current_diet, current_companions))


def _int_bounded(v, lo=0, hi=20, default=0) -> int:
    try:
        return max(lo, min(hi, int(str(v).strip() or default)))
    except Exception:
        return default


@app.post("/{relay_id}/rsvp", response_class=HTMLResponse)
def rsvp_submit(relay_id: str, t: str = "", answer: str = Form(...), comment: str = Form(default=""),
                plus_ones: str = Form(default="0"), children: str = Form(default="0"),
                meal: str = Form(default=""), diet: str = Form(default=""),
                companions: str = Form(default="")) -> HTMLResponse:
    token = str(t or "").strip()
    answer = str(answer or "").strip().lower()
    if answer not in _RSVP_ANSWER_LABELS:
        return HTMLResponse(_rsvp_invalid_page("Réponse non reconnue."), status_code=400)
    comment = str(comment or "").strip()[:500]
    now = _utc_now()

    # Accompagnants/menu/régime : seulement pertinents pour « Oui », comme
    # sur le portail RSVP en direct — on les ignore pour Non/Peut-être même
    # si le navigateur les a envoyés (champs cachés non affichés côté client).
    if answer == "oui":
        po = _int_bounded(plus_ones, 0, 20, 0)
        ch = _int_bounded(children, 0, 20, 0)
        meal = str(meal or "").strip()[:200]
        diet = str(diet or "").strip()[:500]
        try:
            companions_list = json.loads(companions or "[]")
            if not isinstance(companions_list, list):
                companions_list = []
        except Exception:
            companions_list = []
        # Nettoie/borne chaque entrée (défense en profondeur : le JSON vient
        # du navigateur d'un invité, jamais fait confiance tel quel).
        cleaned = []
        for c in companions_list[:40]:
            if not isinstance(c, dict):
                continue
            kind = str(c.get("type") or "").strip()
            if kind not in ("adult", "child"):
                continue
            fn = str(c.get("first_name") or "").strip()[:80]
            ln = str(c.get("last_name") or "").strip()[:80]
            if fn or ln:
                cleaned.append({"type": kind, "first_name": fn, "last_name": ln})
        companions_json = json.dumps(cleaned, ensure_ascii=False)
    else:
        po = ch = 0
        meal = diet = ""
        companions_json = ""

    with _db() as con:
        installation = con.execute(
            "SELECT 1 FROM rsvp_installations WHERE relay_id=?", (str(relay_id or "").strip(),)
        ).fetchone()
        if installation is None:
            return HTMLResponse(_rsvp_invalid_page("Ce lien ne correspond à aucun événement connu."), status_code=404)
        if not token:
            return HTMLResponse(_rsvp_invalid_page("Lien incomplet (jeton manquant)."), status_code=400)
        con.execute(
            """
            INSERT INTO rsvp_pending(relay_id, guest_token, answer, comment, plus_ones, children,
                                     meal, diet, companions_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(relay_id, guest_token)
            DO UPDATE SET answer=excluded.answer, comment=excluded.comment,
                          plus_ones=excluded.plus_ones, children=excluded.children,
                          meal=excluded.meal, diet=excluded.diet,
                          companions_json=excluded.companions_json, updated_at=excluded.updated_at
            """,
            (relay_id, token, answer, comment, po, ch, meal, diet, companions_json, _iso(now), _iso(now)),
        )
        _log_event("rsvp_answer_received", details={"relay_id": relay_id, "answer": answer}, con=con)
    return HTMLResponse(_rsvp_confirm_page(answer))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "license_server:app",
        host="0.0.0.0",
        port=8010,
        reload=False,
    )
