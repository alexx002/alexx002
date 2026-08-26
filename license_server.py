# path: EVENT_manager/license_server.py
from __future__ import annotations

import hashlib
import html as _html
import json
import os
import secrets
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask


APP_TITLE = "EventManagerPro License Server"
DB_PATH = Path("data") / "license_server.db"
SETTINGS_PATH = Path("data") / "license_server_settings.json"
DEFAULT_PRODUCT_CODE = "EventManagerPro"
DEFAULT_API_TOKEN = "CHANGE_ME"
ENV_API_TOKEN_NAME = "LICENSE_SERVER_API_TOKEN"
DEFAULT_MAX_DEVICES = 2
DEFAULT_LICENSE_DURATION_DAYS = 365
# Essai gratuit en libre-service (19/08/2026) : durée volontairement très
# longue. Le forfait Démo est le palier PERMANENT et gratuit de l'offre
# (voir core/entitlements.py : 5 invités max, 1 ligne par module...), pas
# un essai à échéance courte — ses vraies limites sont déjà appliquées côté
# logiciel, inutile de gérer une échéance serveur courte en plus.
DEMO_CLAIM_DURATION_DAYS = 3650
# Relais de projet (22/08/2026) : deux installations qui se partagent un même
# projet « à tour de rôle » (jamais en simultané) via ce serveur, en mode
# « boîte aux lettres » comme le relais RSVP — la donnée (l'archive ZIP du
# projet) n'est jamais conservée durablement : elle est effacée dès que
# l'autre poste l'a récupérée avec succès (voir /project/{key}/pull-ack).
# Limite volontairement modeste : ce relais transporte une archive complète
# (base + éventuelles photos de Galeries), pas juste du texte comme le relais
# RSVP.
MAX_PROJECT_RELAY_BYTES = 35 * 1024 * 1024

# Boîte aux lettres « photos d'invités » (Galeries partagées, 25/08/2026) :
# une photo de smartphone moderne peut dépasser 8 Mo (HEIC/JPEG haute
# résolution) ; au-delà on refuse plutôt que de saturer le disque du service
# gratuit. MAX_GALLERY_PENDING_BYTES borne le total en attente PAR jeton de
# galerie (une galerie dont l'organisateur ne se reconnecte pas longtemps ne
# doit pas bloquer les autres invités ni les autres galeries).
MAX_GALLERY_PHOTO_BYTES = 8 * 1024 * 1024
MAX_GALLERY_PENDING_BYTES = 60 * 1024 * 1024

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


# Tarifs annuels par plan, en euros. Servent UNIQUEMENT à calculer la
# différence de tarif lors d'une mise à niveau (montant fixe, pas de prorata
# du temps restant — décision d'Alex) — le serveur n'encaisse rien lui-même.
# Modifiables sans redéploiement via data/license_server_settings.json
# (clé "plan_prices").
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


def _random_project_key() -> str:
    """Identifiant opaque du relais de projet, court pour rester copiable à
    la main si besoin (le secret, lui, ne l'est pas — voir
    _random_project_secret)."""
    return "PRJ-" + secrets.token_hex(4).upper()


def _random_project_secret() -> str:
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
        # restaient à titre indicatif, et quel montant fixe a été facturé).
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
        # ── Relais de projet ─────────────────────────────────────────────
        # Permet à deux installations de se partager un même projet « à tour
        # de rôle » sans dépendre d'un envoi manuel de fichier. Le serveur ne
        # garde JAMAIS l'archive durablement : `blob` est NULL sauf entre un
        # push et le pull-ack qui suit (voir MAX_PROJECT_RELAY_BYTES
        # ci-dessus et les endpoints /project/...). `checked_out_by` est un
        # simple repère visuel côté client (« qui a la main en ce moment »),
        # pas un verrou technique infranchissable.
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS project_relays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_key TEXT NOT NULL UNIQUE,
                project_secret TEXT NOT NULL,
                owner_activation_id TEXT NOT NULL DEFAULT '',
                label TEXT NOT NULL DEFAULT '',
                blob BLOB,
                blob_size INTEGER NOT NULL DEFAULT 0,
                blob_pushed_by TEXT NOT NULL DEFAULT '',
                blob_pushed_at TEXT NOT NULL DEFAULT '',
                checked_out_by TEXT NOT NULL DEFAULT '',
                checked_out_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                last_activity_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        # ── Boîte aux lettres « photos d'invités » ──────────────────────────
        # Réutilise l'installation créée par /rsvp/register (même relay_id) :
        # une seule « boîte aux lettres » par installation pour RSVP et
        # Galeries. `blob` n'est jamais conservé durablement : il est effacé
        # dès l'accusé de réception du logiciel client (voir
        # /photos/sync/{relay_id}/ack).
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS gallery_pending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                relay_id TEXT NOT NULL,
                gallery_token TEXT NOT NULL,
                filename TEXT NOT NULL DEFAULT '',
                content_type TEXT NOT NULL DEFAULT '',
                size INTEGER NOT NULL DEFAULT 0,
                blob BLOB,
                created_at TEXT NOT NULL
            )
            """
        )
        # Achat automatisé (Stripe, 18/08/2026) : une ligne par session de
        # paiement traitée, pour ne créer qu'une seule licence même si
        # /buy/success et /buy/webhook arrivent tous les deux pour la même
        # session (ou si Stripe réessaie son webhook).
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS stripe_events (
                session_id TEXT PRIMARY KEY,
                license_key TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        # Mise à niveau payée en ligne (Stripe, 19/08/2026) : même principe
        # d'idempotence que stripe_events ci-dessus, mais pour une mise à
        # niveau de licence EXISTANTE (pas une création) — table séparée pour
        # ne pas mélanger « une licence a été créée pour cette session » et
        # « une licence existante a été mise à niveau pour cette session ».
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS stripe_upgrade_events (
                session_id TEXT PRIMARY KEY,
                license_key TEXT NOT NULL,
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


def _require_project_relay(con: sqlite3.Connection, project_key: str, x_project_secret: str | None) -> sqlite3.Row:
    row = con.execute(
        "SELECT * FROM project_relays WHERE project_key=?",
        (str(project_key or "").strip(),),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Relais de projet inconnu.")
    if not secrets.compare_digest(_normalize_token(x_project_secret), str(row["project_secret"])):
        raise HTTPException(status_code=401, detail="Secret du relais de projet invalide.")
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


class DemoClaimRequest(BaseModel):
    """Essai gratuit en libre-service (19/08/2026) : contrairement à
    ActivationRequest/ValidationRequest, aucune `license_key` — il n'y en a
    pas encore, c'est justement ce que cet appel délivre."""
    product_code: str = Field(default=DEFAULT_PRODUCT_CODE)
    app_name: str = Field(default=DEFAULT_PRODUCT_CODE)
    app_version: str = Field(default="1.0.0")
    machine_id: str
    machine_name: str = Field(default="")
    platform: str = Field(default="")
    platform_release: str = Field(default="")
    hostname: str = Field(default="")


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


class UpdateLicenseDetailsRequest(BaseModel):
    """Nom du client / note — les deux seuls champs qu'aucun endpoint
    existant ne permettait de corriger après création (une faute de frappe
    dans le nom, par exemple, obligeait jusqu'ici à supprimer et recréer la
    licence). N'affecte ni le statut, ni la formule, ni l'échéance."""
    customer_name: str = Field(default="")
    notes: str = Field(default="")


class ExtendLicenseRequest(BaseModel):
    """Prolonge l'échéance SANS changer de formule — utile pour un simple
    renouvellement (le client reste au même plan encore un an), par
    opposition à /plan qui sert à changer de formule et gère séparément la
    règle de non-rétrogradation."""
    additional_days: int = Field(ge=1, le=3650)
    notes: str = Field(default="")


class UpgradePlanRequest(BaseModel):
    """Mise à niveau d'une licence existante vers un plan SUPÉRIEUR."""
    plan_name: str
    # Montant réellement encaissé (montant fixe, différence de tarif), pour
    # l'historique. Texte libre : le serveur ne fait pas de comptabilité, il
    # conserve la trace.
    amount_charged: str = Field(default="")
    notes: str = Field(default="")
    # Durée appliquée UNIQUEMENT lors d'une sortie de démo (voir endpoint).
    duration_days: int = Field(default=DEFAULT_LICENSE_DURATION_DAYS, ge=1, le=3650)


class UpgradeCheckoutRequest(BaseModel):
    """Demande de paiement en ligne d'une mise à niveau, envoyée par le
    logiciel client. Identifie la licence par activation_id — jamais par la
    clé en clair, même logique que /validate (voir
    _license_row_from_activation) : le montant à payer est TOUJOURS
    recalculé côté serveur à partir de la licence réelle, jamais accepté tel
    quel depuis le client."""
    product_code: str = Field(default=DEFAULT_PRODUCT_CODE)
    activation_id: str = Field(default="")
    machine_id: str = Field(default="")
    plan_name: str


class PurchaseConsentRequest(BaseModel):
    """Preuve de renoncement au délai de rétractation de 14 jours (article
    L221-28, 13° du Code de la consommation), envoyée par le logiciel client
    juste avant l'ouverture du navigateur vers la page de paiement Stripe —
    que ce soit un premier achat (Payment Link statique) ou une mise à
    niveau (session Checkout dynamique). Voir POST /purchase/consent.
    Aucune donnée bancaire ici : uniquement la preuve que la case dédiée a
    été cochée, horodatée côté serveur (donc non falsifiable depuis le
    poste client)."""
    product_code: str = Field(default=DEFAULT_PRODUCT_CODE)
    machine_id: str = Field(default="")
    plan_name: str
    # "purchase" = premier achat depuis Démo (lien de paiement statique) ;
    # "upgrade" = mise à niveau d'une licence payante existante (session
    # Stripe Checkout dynamique). Texte libre volontairement (pas d'enum
    # strict côté serveur) pour ne pas bloquer un futur cas non prévu ici.
    kind: str = Field(default="purchase")


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


class ProjectRelayCreateRequest(BaseModel):
    """Même logique d'authentification que RsvpRegisterRequest : par
    activation_id, jamais par la clé de licence en clair."""
    product_code: str = Field(default=DEFAULT_PRODUCT_CODE)
    activation_id: str = Field(default="")
    machine_id: str = Field(default="")
    label: str = Field(default="")
    holder_name: str = Field(default="")


class ProjectRelayPullAckRequest(BaseModel):
    holder_name: str = Field(default="")


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


@app.post("/license/demo-claim")
def claim_demo_license(payload: DemoClaimRequest) -> dict[str, Any]:
    """Essai gratuit en libre-service (19/08/2026, demande d'Alex :
    « il faut pouvoir le faire de maintenant »). Contrairement à TOUS les
    autres forfaits — payants via Stripe (paiement d'abord, webhook délivre
    ensuite), ou activés manuellement par Alex (`POST /admin/licenses`,
    jeton admin requis) — le forfait Démo est délivré ET activé
    INSTANTANÉMENT ici, sans jeton ni paiement : c'est le palier gratuit
    permanent de l'offre, rien à facturer ni à vérifier humainement.

    Idempotent par poste : si ce poste a déjà une licence active (démo ou
    autre — activation trouvée par `machine_hash`, même fingerprint que
    /activate et /validate), on renvoie CELLE-LÀ plutôt que d'en créer une
    seconde. Un double-clic sur le bouton, ou un relancement après coupure
    réseau, n'empile donc jamais plusieurs licences démo pour le même
    poste — et un poste qui a déjà une licence payante active n'en reçoit
    pas une démo en plus par erreur."""
    if _normalize_license_key(payload.product_code) != _normalize_license_key(
            str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE)):
        raise HTTPException(status_code=400, detail="product_code invalide.")

    machine_hash = _machine_fingerprint(payload.machine_id)
    now = _utc_now()

    with _db() as con:
        existing_activation = con.execute(
            "SELECT * FROM activations WHERE machine_hash=? AND status='active' "
            "ORDER BY created_at DESC LIMIT 1",
            (machine_hash,),
        ).fetchone()
        if existing_activation is not None:
            existing_license = con.execute(
                "SELECT * FROM licenses WHERE id=?",
                (int(existing_activation["license_id"]),),
            ).fetchone()
            if existing_license is not None and _license_status_error(existing_license) is None:
                used_devices = _count_active_activations(con, int(existing_license["id"]))
                next_check_at = now + timedelta(
                    days=int(existing_license["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS))
                _log_event(
                    "demo_claim_existing",
                    license_key=str(existing_license["license_key"]),
                    activation_id=str(existing_activation["activation_id"]),
                    machine_hash=machine_hash,
                    con=con,
                )
                return _row_to_license_payload(
                    existing_license,
                    activation_id=str(existing_activation["activation_id"]),
                    used_devices=used_devices,
                    validated_at=now,
                    next_check_at=next_check_at,
                    message="Une licence est déjà active sur ce poste.",
                )

        license_key = _random_license_key()
        expires_at = now + timedelta(days=DEMO_CLAIM_DURATION_DAYS)
        con.execute(
            """
            INSERT INTO licenses(
                license_key, product_code, customer_name, plan_name, status,
                max_devices, offline_grace_days, expires_at, created_at, updated_at, notes
            ) VALUES (?, ?, '', 'demo', 'active', ?, ?, ?, ?, ?, ?)
            """
            ,
            (
                license_key,
                _normalize_license_key(payload.product_code) or DEFAULT_PRODUCT_CODE,
                # « 1 licence / 1 poste » sur la page tarifaire (même règle
                # que l'achat en ligne Stripe ci-dessus, voir son commentaire)
                # — bug signalé par Alex le 19/08/2026 : ce champ utilisait
                # encore DEFAULT_MAX_DEVICES (2, pensé pour la création
                # MANUELLE où Alex choisit lui-même le nombre de postes),
                # ce qui donnait 2 postes à un essai gratuit censé n'en
                # accorder qu'un seul.
                1,
                DEFAULT_OFFLINE_GRACE_DAYS,
                _iso(expires_at),
                _iso(now),
                _iso(now),
                "Essai gratuit auto-délivré (self-service, /license/demo-claim).",
            ),
        )
        license_row = _get_license_row(con, license_key)

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
        used_devices = _count_active_activations(con, int(license_row["id"]))
        next_check_at = now + timedelta(
            days=int(license_row["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS))
        _log_event(
            "demo_claim_issued",
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
            message="Essai gratuit activé.",
        )


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
    """Calcule le montant à facturer (FIXE, voir plus bas) et la date
    d'expiration résultante, SANS RIEN MODIFIER. Utilisé tel quel par le
    devis (lecture seule) et par l'application, pour que le montant annoncé
    avant paiement soit exactement celui appliqué ensuite."""
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

    # Montant FIXE (décision d'Alex, 19/08/2026) : la différence de tarif
    # entre les deux forfaits, SANS prorata du temps restant — un client qui
    # passe de Basic à Pro paie 20 € (49 − 29), qu'il lui reste 3 jours ou
    # 300 jours sur sa période en cours. days_remaining/total_days restent
    # calculés ci-dessus et renvoyés ci-dessous à titre indicatif seulement
    # (affichage, historique plan_changes) : ils n'entrent plus dans le prix.
    if old_plan == "demo":
        suggested = plan_price(new_plan)          # plein tarif, sortie de démo
    else:
        suggested = round(max(0.0, plan_price(new_plan) - plan_price(old_plan)), 2)

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


def _apply_plan_upgrade(
    con: sqlite3.Connection,
    row: sqlite3.Row,
    new_plan: str,
    duration_days: int,
    now: datetime,
    amount_charged: str = "",
    notes: str = "",
    event_type: str = "admin_upgrade_plan",
) -> dict[str, Any]:
    """Applique un changement de plan déjà validé par _check_upgrade_allowed
    (à l'appelant de l'avoir vérifié juste avant) : recalcule via
    _compute_upgrade (même calcul EXACT que le devis affiché), écrit la
    licence et l'historique plan_changes, journalise. Partagé par
    l'application manuelle (PATCH .../plan, outil d'administration) et la
    mise à niveau payée en ligne (Stripe, voir /upgrade/success et le
    webhook) — un seul endroit qui modifie réellement une licence pour une
    mise à niveau, pour que les deux circuits restent identiques."""
    old_plan = normalize_plan(row["plan_name"])
    calc = _compute_upgrade(row, new_plan, int(duration_days), now)
    expires_before = calc["_expires_before"]
    expires_after = calc["_expires_after"]
    days_remaining = calc["days_remaining"]

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
            _normalize_license_key(str(row["license_key"])), old_plan, new_plan, int(days_remaining),
            _iso(expires_before) if expires_before else "",
            _iso(expires_after) if expires_after else "",
            str(amount_charged or "").strip(),
            str(notes or "").strip(),
            _iso(now),
        ),
    )
    _log_event(
        event_type,
        license_key=_normalize_license_key(str(row["license_key"])),
        details={
            "old_plan": old_plan, "new_plan": new_plan,
            "days_remaining": days_remaining,
            "expiry_reset": bool(old_plan == "demo"),
            "suggested_amount": calc["suggested_amount"],
            "amount_charged": str(amount_charged or "").strip(),
        },
        con=con,
    )
    return calc


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

        calc = _apply_plan_upgrade(
            con, row, new_plan, int(payload.duration_days), now,
            amount_charged=str(payload.amount_charged or "").strip(),
            notes=str(payload.notes or "").strip(),
            event_type="admin_upgrade_plan",
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
# Extensions admin additionnelles (nouveaux endpoints, aucun endpoint
# ci-dessus modifié) : modifier nom/note, prolonger une échéance, consulter
# le journal d'audit, télécharger une sauvegarde de la base.
# ═══════════════════════════════════════════════════════════════════════════

@app.patch("/admin/licenses/{license_key}/details")
def update_license_details(
    license_key: str,
    payload: UpdateLicenseDetailsRequest,
    x_api_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Corrige le nom du client et/ou la note — aucun autre champ n'est
    modifiable ici (statut, formule, échéance : voir les endpoints dédiés)."""
    _require_api_token(x_api_token)
    now = _utc_now()
    with _db() as con:
        row = _get_license_row(con, license_key)
        con.execute(
            "UPDATE licenses SET customer_name=?, notes=?, updated_at=? WHERE id=?",
            (payload.customer_name.strip(), payload.notes.strip(), _iso(now), int(row["id"])),
        )
        updated = _get_license_row(con, license_key)
        used_devices = _count_active_activations(con, int(updated["id"]))
        _log_event(
            "admin_update_details",
            license_key=_normalize_license_key(license_key),
            con=con,
        )
        return _row_to_license_payload(
            updated,
            used_devices=used_devices,
            validated_at=now,
            next_check_at=now + timedelta(days=int(updated["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS)),
            message="Informations mises à jour.",
        )


@app.patch("/admin/licenses/{license_key}/extend")
def extend_license(
    license_key: str,
    payload: ExtendLicenseRequest,
    x_api_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Ajoute des jours à l'échéance actuelle, SANS toucher à la formule —
    un simple renouvellement au même plan. Si l'échéance est déjà dépassée,
    on repart d'aujourd'hui plutôt que d'empiler les jours sur une date
    passée (sinon la licence resterait « expirée » malgré la prolongation)."""
    _require_api_token(x_api_token)
    now = _utc_now()
    with _db() as con:
        row = _get_license_row(con, license_key)
        current_expiry = _parse_iso(row["expires_at"])
        base_date = current_expiry if (current_expiry and current_expiry > now) else now
        new_expiry = base_date + timedelta(days=int(payload.additional_days))
        con.execute(
            "UPDATE licenses SET expires_at=?, notes=?, updated_at=? WHERE id=?",
            (
                _iso(new_expiry),
                payload.notes.strip() or str(row["notes"] or ""),
                _iso(now),
                int(row["id"]),
            ),
        )
        updated = _get_license_row(con, license_key)
        used_devices = _count_active_activations(con, int(updated["id"]))
        _log_event(
            "admin_extend_license",
            license_key=_normalize_license_key(license_key),
            details={"additional_days": int(payload.additional_days),
                     "expires_at_before": _iso(current_expiry) if current_expiry else "",
                     "expires_at_after": _iso(new_expiry)},
            con=con,
        )
        return _row_to_license_payload(
            updated,
            used_devices=used_devices,
            validated_at=now,
            next_check_at=now + timedelta(days=int(updated["offline_grace_days"] or DEFAULT_OFFLINE_GRACE_DAYS)),
            message=f"Échéance prolongée de {int(payload.additional_days)} jour(s).",
        )


@app.get("/admin/audit-log")
def list_audit_log(
    license_key: str = "",
    limit: int = 200,
    x_api_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Derniers événements du journal d'audit (table déjà existante, jamais
    exposée jusqu'ici) — utile pour voir qui a fait quoi et quand, sans avoir
    à ouvrir la base SQLite à la main. Filtrable par licence."""
    _require_api_token(x_api_token)
    safe_limit = max(1, min(1000, int(limit or 200)))
    with _db() as con:
        if license_key.strip():
            rows = con.execute(
                "SELECT event_type, license_key, activation_id, machine_hash, details_json, created_at "
                "FROM audit_log WHERE license_key=? ORDER BY id DESC LIMIT ?",
                (_normalize_license_key(license_key), safe_limit),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT event_type, license_key, activation_id, machine_hash, details_json, created_at "
                "FROM audit_log ORDER BY id DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        items = []
        for r in rows:
            try:
                details = json.loads(r["details_json"] or "{}")
                if not isinstance(details, dict):
                    details = {}
            except Exception:
                details = {}
            items.append({
                "event_type": str(r["event_type"]),
                "license_key": str(r["license_key"] or ""),
                "activation_id": str(r["activation_id"] or ""),
                "details": details,
                "created_at": str(r["created_at"]),
            })
        return {"ok": True, "items": items}


@app.get("/admin/backup")
def download_backup(x_api_token: str | None = Header(default=None)) -> FileResponse:
    """Télécharge une copie cohérente de la base de licences SQLite — filet
    de sécurité en plus du disque persistant Render. Utilise l'API de
    sauvegarde native de SQLite (Connection.backup), pas une simple copie de
    fichier : sûr même si le serveur est en train d'écrire au même instant.
    Le fichier temporaire produit est supprimé juste après l'envoi."""
    _require_api_token(x_api_token)
    _ensure_parent(DB_PATH)
    fd, tmp_path = tempfile.mkstemp(prefix="license_server_backup_", suffix=".db")
    os.close(fd)
    source = sqlite3.connect(str(DB_PATH))
    try:
        dest = sqlite3.connect(tmp_path)
        try:
            source.backup(dest)
        finally:
            dest.close()
    finally:
        source.close()
    _log_event("admin_download_backup")
    filename = f"license_server_backup_{_utc_now().strftime('%Y%m%d_%H%M%S')}.db"
    return FileResponse(
        tmp_path, filename=filename, media_type="application/octet-stream",
        background=BackgroundTask(lambda: os.unlink(tmp_path) if os.path.exists(tmp_path) else None),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Achat automatisé (Stripe) — 18/08/2026
#
# Objectif : qu'un client puisse payer et recevoir sa clé de licence SANS
# passer par un e-mail manuel. Le paiement lui-même est entièrement géré par
# Stripe (Payment Links) — ce serveur ne voit ni ne stocke jamais de moyen de
# paiement, seulement la confirmation que Stripe a été payé.
#
# Fonctionnement :
#   1. Alex crée dans son tableau de bord Stripe un Prix par forfait (Basic,
#      Pro, Expert) et un « Payment Link » par prix, avec pour URL de succès
#      "<url-du-serveur>/buy/success?session_id={CHECKOUT_SESSION_ID}".
#   2. Le logiciel client (bouton « Payer maintenant ») ouvre ce lien dans le
#      navigateur — récupéré via GET /buy/links, pour ne pas être à coder en
#      dur côté logiciel si Alex change ses liens.
#   3. Une fois le paiement effectué, Stripe redirige le navigateur du client
#      vers /buy/success, qui crée la licence et l'affiche immédiatement.
#   4. En parallèle (et en secours si le client ferme l'onglet avant la
#      redirection), Stripe appelle aussi /buy/webhook — même logique de
#      création, protégée par vérification de signature et rendue idempotente
#      (une seule licence par session Stripe, quel que soit le nombre
#      d'appels, quel que soit celui des deux qui arrive en premier).
#
# Configuration (variables d'environnement Render, JAMAIS écrites ici) :
#   STRIPE_SECRET_KEY      clé secrète Stripe (tableau de bord → Développeurs
#                          → Clés API). Sert à interroger l'API Stripe pour
#                          confirmer un paiement.
#   STRIPE_WEBHOOK_SECRET  secret de signature du point de terminaison webhook
#                          (tableau de bord → Développeurs → Webhooks → créer
#                          un point de terminaison vers <url-serveur>/buy/webhook,
#                          événements "checkout.session.completed" et
#                          "checkout.session.async_payment_succeeded").
#   STRIPE_PRICE_MAP       JSON associant un id de Prix Stripe (price_xxx) au
#                          forfait et à la durée à créer, ex. :
#                          {"price_ABC": {"plan": "Basic", "days": 365},
#                           "price_DEF": {"plan": "Pro",   "days": 365},
#                           "price_GHI": {"plan": "Expert","days": 365}}
#   PAYMENT_LINKS          JSON associant un forfait à son Payment Link
#                          public, ex. {"basic": "https://buy.stripe.com/xxx",
#                          "pro": "...", "expert": "..."} — exposé tel quel
#                          par GET /buy/links (pages de paiement publiques,
#                          pas des secrets).
#   SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASSWORD / SMTP_FROM (optionnels)
#                          si renseignés, la clé est en plus envoyée par
#                          e-mail au client (elle reste de toute façon
#                          affichée sur /buy/success même sans SMTP).
#
# Tant que STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET ne sont pas configurés,
# ces endpoints répondent 503 sans jamais affecter le reste du serveur —
# l'achat automatisé est un AJOUT, pas un remplacement du circuit manuel
# existant (/admin/licenses reste utilisable exactement comme avant).
# ═══════════════════════════════════════════════════════════════════════════

class _StripeNotConfigured(Exception):
    pass


def _stripe_secret_key() -> str:
    return _normalize_token(os.getenv("STRIPE_SECRET_KEY"))


def _stripe_webhook_secret() -> str:
    return _normalize_token(os.getenv("STRIPE_WEBHOOK_SECRET"))


def _stripe_price_map() -> dict[str, Any]:
    raw = os.getenv("STRIPE_PRICE_MAP") or ""
    try:
        data = json.loads(raw) if raw.strip() else {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _payment_links() -> dict[str, str]:
    raw = os.getenv("PAYMENT_LINKS") or ""
    try:
        data = json.loads(raw) if raw.strip() else {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except Exception:
        return {}


def _stripe_api_get(path: str) -> dict[str, Any]:
    """Appel GET minimal à l'API Stripe, sans dépendance au SDK officiel —
    une poignée d'appels ne justifient pas d'ajouter une bibliothèque au
    déploiement."""
    import urllib.request
    import urllib.error

    key = _stripe_secret_key()
    if not key:
        raise _StripeNotConfigured("STRIPE_SECRET_KEY non configuré côté serveur.")
    url = f"https://api.stripe.com/v1/{path}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=502, detail=f"Réponse Stripe inattendue : {detail}") from exc


def _stripe_flatten_params(prefix: str, value: Any, out: list[tuple[str, str]]) -> None:
    """Convertit un dict Python en paramètres de formulaire imbriqués comme
    l'attend l'API Stripe (ex. line_items[0][price_data][unit_amount]) —
    évite d'ajouter le SDK Stripe au déploiement pour ce seul besoin."""
    if isinstance(value, dict):
        for k, v in value.items():
            _stripe_flatten_params(f"{prefix}[{k}]" if prefix else str(k), v, out)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _stripe_flatten_params(f"{prefix}[{i}]", v, out)
    elif value is not None:
        out.append((prefix, str(value)))


def _stripe_api_post(path: str, params: dict[str, Any]) -> dict[str, Any]:
    """Appel POST minimal à l'API Stripe (formulaire url-encodé, comme
    l'exige l'API Stripe), sans dépendance au SDK officiel — même choix que
    _stripe_api_get."""
    import urllib.request
    import urllib.parse
    import urllib.error

    key = _stripe_secret_key()
    if not key:
        raise _StripeNotConfigured("STRIPE_SECRET_KEY non configuré côté serveur.")
    flat: list[tuple[str, str]] = []
    for k, v in params.items():
        _stripe_flatten_params(k, v, flat)
    body = urllib.parse.urlencode(flat).encode("utf-8")
    url = f"https://api.stripe.com/v1/{path}"
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=502, detail=f"Réponse Stripe inattendue : {detail}") from exc


def _verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    """Vérification manuelle de la signature webhook Stripe (schéma documenté
    par Stripe : en-tête "t=<horodatage>,v1=<hmac>", comparaison en temps
    constant) — évite d'ajouter le SDK Stripe au déploiement pour cette seule
    fonction."""
    import hmac as _hmac

    try:
        parts = dict(
            item.split("=", 1) for item in str(sig_header or "").split(",") if "=" in item
        )
        timestamp = parts.get("t", "")
        signature = parts.get("v1", "")
        if not timestamp or not signature:
            return False
        signed_payload = f"{timestamp}.".encode("utf-8") + payload
        expected = _hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
        return _hmac.compare_digest(expected, signature)
    except Exception:
        return False


def _maybe_send_license_email(to_email: str, license_key: str, plan_name: str, expires_at: str) -> None:
    """Best-effort : n'envoie rien si SMTP_HOST n'est pas configuré, et ne
    lève jamais — la clé reste de toute façon affichée sur /buy/success."""
    host = _normalize_token(os.getenv("SMTP_HOST"))
    if not host or not to_email:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText

        port = int(os.getenv("SMTP_PORT") or 587)
        user = _normalize_token(os.getenv("SMTP_USER"))
        password = os.getenv("SMTP_PASSWORD") or ""
        sender = _normalize_token(os.getenv("SMTP_FROM")) or user or "no-reply@eventmanagerpro"

        body = (
            f"Merci pour votre achat d'Event Manager Pro — forfait {plan_name}.\n\n"
            f"Votre clé de licence : {license_key}\n"
            f"Valable jusqu'au : {expires_at[:10]}\n\n"
            "Pour l'activer : ouvrez Event Manager Pro, rubrique Licence, "
            "« J'ai une licence », puis collez cette clé.\n"
        )
        msg = MIMEText(body, _charset="utf-8")
        msg["Subject"] = "Votre licence Event Manager Pro"
        msg["From"] = sender
        msg["To"] = to_email

        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as server:
                if user:
                    server.login(user, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.starttls()
                if user:
                    server.login(user, password)
                server.send_message(msg)
    except Exception:
        pass  # l'e-mail est un plus, jamais un blocage


def _issue_license_for_stripe_session(session_id: str) -> tuple[Optional[sqlite3.Row], str]:
    """Crée (ou retrouve, si déjà traitée) la licence correspondant à une
    session Stripe payée. Idempotent : appelable sans risque à la fois depuis
    /buy/success (dès le retour du navigateur) et /buy/webhook (en secours),
    quel que soit celui des deux qui arrive en premier.

    Retourne (ligne de licence ou None, message d'erreur ou "")."""
    session_id = str(session_id or "").strip()
    if not session_id:
        return None, "Session de paiement manquante."

    with _db() as con:
        existing = con.execute(
            "SELECT license_key FROM stripe_events WHERE session_id=?", (session_id,)
        ).fetchone()
        if existing is not None:
            return _get_license_row(con, str(existing["license_key"])), ""

    session = _stripe_api_get(f"checkout/sessions/{session_id}?expand[]=line_items")
    if str(session.get("payment_status") or "") != "paid":
        return None, "Paiement pas encore confirmé — réessaie dans quelques instants."

    line_items = ((session.get("line_items") or {}).get("data") or [])
    price_id = ""
    if line_items:
        price_id = str(((line_items[0] or {}).get("price") or {}).get("id") or "")
    mapping = _stripe_price_map().get(price_id)
    if not mapping:
        _log_event("stripe_unknown_price", details={"session_id": session_id, "price_id": price_id})
        return None, "Forfait non reconnu pour ce paiement — contacte le support avec ta référence de paiement."

    plan_name = str(mapping.get("plan") or "").strip() or "Basic"
    days = int(mapping.get("days") or DEFAULT_LICENSE_DURATION_DAYS)
    # « 1 licence / 1 poste » sur la page tarifaire : la vente en ligne doit
    # donc créer 1 poste par défaut, pas le défaut serveur (2, pensé pour la
    # création manuelle où Alex choisit lui-même). Réglable par forfait via
    # STRIPE_PRICE_MAP (clé optionnelle "devices"), pour le jour où un forfait
    # vendrait explicitement plusieurs postes.
    devices = max(1, int(mapping.get("devices") or 1))

    customer_details = session.get("customer_details") or {}
    email = str(customer_details.get("email") or "").strip()
    customer_name = str(customer_details.get("name") or "").strip() or email or "Client (achat en ligne)"

    now = _utc_now()
    expires_at = now + timedelta(days=days)
    license_key = _random_license_key()

    with _db() as con:
        # Revérifié SOUS l'écriture : deux appels concurrents (retour
        # navigateur + webhook arrivant en même temps) ne doivent créer
        # qu'UNE seule licence pour la même session.
        existing = con.execute(
            "SELECT license_key FROM stripe_events WHERE session_id=?", (session_id,)
        ).fetchone()
        if existing is not None:
            return _get_license_row(con, str(existing["license_key"])), ""
        con.execute(
            """
            INSERT INTO licenses(
                license_key, product_code, customer_name, plan_name, status,
                max_devices, offline_grace_days, expires_at, created_at, updated_at, notes
            ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
            """,
            (
                license_key,
                DEFAULT_PRODUCT_CODE,
                customer_name,
                plan_name,
                devices,
                int(SETTINGS.get("default_offline_grace_days") or DEFAULT_OFFLINE_GRACE_DAYS),
                _iso(expires_at),
                _iso(now),
                _iso(now),
                f"Achat automatique en ligne (Stripe) — session {session_id}"
                + (f" — {email}" if email else ""),
            ),
        )
        con.execute(
            "INSERT INTO stripe_events(session_id, license_key, created_at) VALUES (?, ?, ?)",
            (session_id, license_key, _iso(now)),
        )
        row = _get_license_row(con, license_key)
        _log_event(
            "stripe_purchase", license_key=license_key,
            details={"session_id": session_id, "plan": plan_name, "email": email},
            con=con,
        )

    _maybe_send_license_email(email, license_key, plan_name, _iso(expires_at))
    return row, ""


def _apply_stripe_upgrade_session(session_id: str) -> tuple[Optional[sqlite3.Row], str]:
    """Applique la mise à niveau correspondant à une session Stripe payée.
    Idempotent comme _issue_license_for_stripe_session ci-dessus (même
    principe, table dédiée stripe_upgrade_events) : /upgrade/success (retour
    navigateur) et le webhook peuvent l'appeler tous les deux pour la même
    session, dans n'importe quel ordre, sans jamais facturer ni appliquer
    deux fois.

    Le plan cible et la licence concernée viennent des MÉTADONNÉES de la
    session Stripe (posées par le serveur lui-même à la création, jamais
    fournies par le client à cet endpoint) — la même prudence que pour
    STRIPE_PRICE_MAP côté achat initial : on ne fait jamais confiance à une
    valeur reçue après coup pour décider quoi appliquer."""
    session_id = str(session_id or "").strip()
    if not session_id:
        return None, "Session de paiement manquante."

    with _db() as con:
        existing = con.execute(
            "SELECT license_key FROM stripe_upgrade_events WHERE session_id=?", (session_id,)
        ).fetchone()
        if existing is not None:
            return _get_license_row(con, str(existing["license_key"])), ""

    session = _stripe_api_get(f"checkout/sessions/{session_id}")
    if str(session.get("payment_status") or "") != "paid":
        return None, "Paiement pas encore confirmé — réessaie dans quelques instants."

    metadata = session.get("metadata") or {}
    if str(metadata.get("kind") or "") != "upgrade":
        return None, "Cette session ne correspond pas à une mise à niveau."
    license_key = _normalize_license_key(str(metadata.get("license_key") or ""))
    new_plan = normalize_plan(str(metadata.get("new_plan") or ""))
    if not license_key or new_plan not in PLAN_ORDER:
        _log_event("stripe_upgrade_bad_metadata", details={"session_id": session_id})
        return None, "Référence de mise à niveau incomplète — contacte le support."

    amount_paid = float(int(session.get("amount_total") or 0)) / 100.0
    now = _utc_now()

    with _db() as con:
        existing = con.execute(
            "SELECT license_key FROM stripe_upgrade_events WHERE session_id=?", (session_id,)
        ).fetchone()
        if existing is not None:
            return _get_license_row(con, str(existing["license_key"])), ""

        row = _get_license_row(con, license_key)
        old_plan = normalize_plan(row["plan_name"])
        if plan_rank(new_plan) <= plan_rank(old_plan):
            # Déjà mise à niveau entretemps par un autre chemin (admin, ou
            # /upgrade/success et le webhook arrivés dans l'autre ordre) —
            # on considère l'opération faite, pas d'erreur pour un client qui
            # vient de payer avec succès.
            con.execute(
                "INSERT OR IGNORE INTO stripe_upgrade_events(session_id, license_key, created_at) VALUES (?, ?, ?)",
                (session_id, license_key, _iso(now)),
            )
            return _get_license_row(con, license_key), ""

        _apply_plan_upgrade(
            con, row, new_plan, DEFAULT_LICENSE_DURATION_DAYS, now,
            amount_charged=f"{amount_paid:.2f} EUR (Stripe, session {session_id})",
            notes="Mise à niveau payée en ligne (Stripe).",
            event_type="stripe_upgrade",
        )
        con.execute(
            "INSERT INTO stripe_upgrade_events(session_id, license_key, created_at) VALUES (?, ?, ?)",
            (session_id, license_key, _iso(now)),
        )
        return _get_license_row(con, license_key), ""


def _buy_page(title: str, body_html: str, refresh: bool = False) -> str:
    meta = '<meta http-equiv="refresh" content="5">' if refresh else ""
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
{meta}
<title>{_html.escape(title)}</title>
<style>
    body {{ font-family: -apple-system, "Segoe UI", sans-serif; background:#0f1420; color:#f4f7fb;
            display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }}
    .card {{ background:#1b2233; border:1px solid #2c3445; border-radius:14px; padding:32px;
             max-width:480px; text-align:center; }}
    h1 {{ font-size:20px; margin-top:0; }}
    .key-box {{ font-family: monospace; font-size:20px; letter-spacing:1px; background:#0f1420;
                border:1px dashed #7c4dcc; border-radius:8px; padding:14px; margin:16px 0; user-select:all; }}
    button {{ background:#7c4dcc; color:white; border:none; border-radius:8px; padding:10px 18px;
              font-weight:700; cursor:pointer; }}
</style></head><body><div class="card"><h1>{_html.escape(title)}</h1>{body_html}</div></body></html>"""


@app.post("/purchase/consent")
def record_purchase_consent(payload: PurchaseConsentRequest, request: Request) -> dict[str, Any]:
    """Enregistre, AVANT paiement, la preuve que le client a coché la case
    dédiée de renoncement au délai de rétractation de 14 jours (article
    L221-28, 13° du Code de la consommation — voir Article 6 des CGV).

    Deux conditions cumulatives sont exigées par ce texte pour que la
    renonciation soit valable : (1) l'accord préalable exprès pour une
    exécution immédiate, et (2) la reconnaissance expresse de la perte du
    droit de rétractation qui en découle. La case à cocher présentée côté
    logiciel (voir ui/consent_dialog.py) porte les deux mentions ; cet
    appel n'enregistre que le fait que la case a été cochée avant de
    poursuivre — l'horodatage `created_at`, généré ici et non par le poste
    client, est ce qui rend la preuve difficile à falsifier après coup.

    N'exige aucun jeton (comme /license/demo-claim et /buy/links) : c'est
    une écriture, pas une lecture de données sensibles, et elle doit
    pouvoir avoir lieu avant qu'une licence ou une session Stripe existe.
    Consultable ensuite via GET /admin/audit-log (event_type
    "purchase_consent_recorded")."""
    if _normalize_license_key(payload.product_code) != _normalize_license_key(
            str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE)):
        raise HTTPException(status_code=400, detail="product_code invalide.")
    plan = str(payload.plan_name or "").strip().lower()
    if plan not in PLAN_ALIASES:
        raise HTTPException(
            status_code=400,
            detail=f"Plan inconnu : « {payload.plan_name} ». Attendu : {', '.join(PLAN_ORDER)}.",
        )
    machine_hash = _machine_fingerprint(payload.machine_id) if payload.machine_id else ""
    now = _utc_now()
    client_ip = str(request.client.host) if request.client else ""
    _log_event(
        "purchase_consent_recorded",
        machine_hash=machine_hash,
        details={
            "plan_name": normalize_plan(plan),
            "kind": str(payload.kind or "purchase").strip() or "purchase",
            "ip": client_ip,
        },
    )
    return {"ok": True, "recorded_at": _iso(now)}


@app.get("/buy/links")
def get_payment_links() -> dict[str, Any]:
    """Liste des pages de paiement configurées, par forfait. Public et sans
    jeton : ce sont des liens de paiement publics (n'importe qui peut de
    toute façon les trouver en cliquant « Acheter » dans le logiciel), pas
    des informations sensibles."""
    return {"links": _payment_links()}


@app.get("/buy/success", response_class=HTMLResponse)
def buy_success(session_id: str = "") -> HTMLResponse:
    try:
        row, error = _issue_license_for_stripe_session(session_id)
    except _StripeNotConfigured as exc:
        return HTMLResponse(_buy_page("Achat automatisé non configuré", str(exc)), status_code=503)
    except HTTPException as exc:
        return HTMLResponse(_buy_page("Erreur", str(exc.detail)), status_code=exc.status_code)

    if row is None:
        return HTMLResponse(_buy_page(
            "Paiement en cours de confirmation",
            f"<p>{_html.escape(error or 'Merci de patienter quelques instants…')}</p>"
            "<p>Cette page se rafraîchit toute seule.</p>",
            refresh=True,
        ))

    key = str(row["license_key"])
    return HTMLResponse(_buy_page(
        "Merci pour votre achat !",
        f"""
        <p>Votre forfait <b>{_html.escape(str(row['plan_name']))}</b> est prêt.</p>
        <div class="key-box">{_html.escape(key)}</div>
        <button onclick="navigator.clipboard.writeText('{key}')">📋 Copier la clé</button>
        <p style="margin-top:18px;">Valable jusqu'au {_html.escape(str(row['expires_at'])[:10])}.</p>
        <p>Pour l'activer : ouvre <b>Event Manager Pro</b> → Licence →
        « J'ai une licence » → colle cette clé.</p>
        """,
    ))


@app.post("/license/upgrade-checkout")
def create_upgrade_checkout(payload: UpgradeCheckoutRequest, request: Request) -> dict[str, Any]:
    """Crée une session de paiement Stripe pour le montant EXACT d'une mise
    à niveau (montant fixe = différence de tarif entre les deux forfaits,
    sans prorata du temps restant) — même calcul que
    /admin/licenses/{clé}/upgrade-quote (_compute_upgrade), jamais un
    montant fourni par le client. Renvoie
    l'URL Stripe hébergée à ouvrir dans le navigateur (le logiciel client
    fait ensuite la même chose qu'avec les boutons « Payer en ligne » du
    comparatif des forfaits : QDesktopServices.openUrl). La mise à niveau
    s'applique toute seule dès le paiement confirmé, voir /upgrade/success
    et le webhook — pas besoin de repasser par license_admin_tool."""
    if _normalize_license_key(payload.product_code) != _normalize_license_key(str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE)):
        raise HTTPException(status_code=400, detail="product_code invalide.")
    if str(payload.plan_name or "").strip().lower() not in PLAN_ALIASES:
        raise HTTPException(
            status_code=400,
            detail=f"Plan inconnu : « {payload.plan_name} ». Attendu : {', '.join(PLAN_ORDER)}.",
        )
    new_plan = normalize_plan(payload.plan_name)
    machine_hash = _machine_fingerprint(payload.machine_id)
    now = _utc_now()

    with _db() as con:
        row = _license_row_from_activation(con, payload.activation_id, machine_hash)
        license_key = _normalize_license_key(str(row["license_key"] or ""))
        old_plan = normalize_plan(row["plan_name"])
        _check_upgrade_allowed(old_plan, new_plan)
        calc = _compute_upgrade(row, new_plan, DEFAULT_LICENSE_DURATION_DAYS, now)

    amount = float(calc["suggested_amount"] or 0)
    if amount <= 0:
        raise HTTPException(
            status_code=400,
            detail="Montant de mise à niveau nul ou négatif — contacte le support avec ta clé de licence.",
        )

    base_url = str(request.base_url).rstrip("/")
    session = _stripe_api_post("checkout/sessions", {
        "mode": "payment",
        "line_items": [{
            "quantity": 1,
            "price_data": {
                "currency": "eur",
                "unit_amount": int(round(amount * 100)),
                "product_data": {
                    "name": f"Event Manager Pro — mise à niveau {old_plan.capitalize()} → {new_plan.capitalize()}",
                },
            },
        }],
        "success_url": f"{base_url}/upgrade/success?session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url": f"{base_url}/buy/links",
        "metadata": {
            "kind": "upgrade",
            "license_key": license_key,
            "new_plan": new_plan,
        },
    })
    checkout_url = str(session.get("url") or "")
    if not checkout_url:
        raise HTTPException(status_code=502, detail="Stripe n'a pas renvoyé d'URL de paiement.")

    _log_event(
        "stripe_upgrade_checkout_created",
        license_key=license_key,
        details={"old_plan": old_plan, "new_plan": new_plan, "amount": amount},
    )
    return {
        "ok": True,
        "checkout_url": checkout_url,
        "amount": amount,
        "old_plan": old_plan,
        "new_plan": new_plan,
    }


@app.get("/upgrade/success", response_class=HTMLResponse)
def upgrade_success(session_id: str = "") -> HTMLResponse:
    try:
        row, error = _apply_stripe_upgrade_session(session_id)
    except _StripeNotConfigured as exc:
        return HTMLResponse(_buy_page("Mise à niveau non configurée", str(exc)), status_code=503)
    except HTTPException as exc:
        return HTMLResponse(_buy_page("Erreur", str(exc.detail)), status_code=exc.status_code)

    if row is None:
        return HTMLResponse(_buy_page(
            "Paiement en cours de confirmation",
            f"<p>{_html.escape(error or 'Merci de patienter quelques instants…')}</p>"
            "<p>Cette page se rafraîchit toute seule.</p>",
            refresh=True,
        ))

    return HTMLResponse(_buy_page(
        "Mise à niveau effectuée !",
        f"""
        <p>Ta licence est maintenant en <b>{_html.escape(str(row['plan_name']).capitalize())}</b>.</p>
        <p style="margin-top:18px;">Toujours valable jusqu'au
        {_html.escape(str(row['expires_at'])[:10])} — la date n'a pas changé.</p>
        <p>Ouvre <b>Event Manager Pro</b> et clique « 🔄 Vérifier ma licence »
        pour l'activer immédiatement.</p>
        """,
    ))


@app.post("/buy/webhook")
async def stripe_webhook(request: Request) -> dict[str, Any]:
    secret = _stripe_webhook_secret()
    if not secret:
        raise HTTPException(status_code=503, detail="STRIPE_WEBHOOK_SECRET non configuré côté serveur.")
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature") or ""
    if not _verify_stripe_signature(payload, sig_header, secret):
        raise HTTPException(status_code=400, detail="Signature webhook invalide.")

    try:
        event = json.loads(payload.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Corps de requête illisible.")

    event_type = str(event.get("type") or "")
    if event_type in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        session_obj = ((event.get("data") or {}).get("object") or {})
        session_id = str(session_obj.get("id") or "")
        # Une session envoie ses métadonnées dans l'événement lui-même — pas
        # besoin d'un deuxième point de terminaison webhook pour distinguer
        # un ACHAT (nouvelle licence) d'une MISE À NIVEAU (licence existante,
        # posé par le serveur à la création de la session, voir
        # /license/upgrade-checkout) : Alex n'a rien à reconfigurer côté
        # Stripe, le webhook déjà en place couvre les deux cas.
        kind = str((session_obj.get("metadata") or {}).get("kind") or "")
        if session_id:
            try:
                if kind == "upgrade":
                    _apply_stripe_upgrade_session(session_id)
                else:
                    _issue_license_for_stripe_session(session_id)
            except Exception:
                # Ne jamais faire échouer le webhook : Stripe réessaierait en
                # boucle. Les échecs restent consultables via
                # /admin/audit-log (evénement "stripe_unknown_price") ou dans
                # les journaux Render.
                pass

    return {"received": True}


# ═══════════════════════════════════════════════════════════════════════════
# Interface d'administration mobile
#
# Page statique uniquement : c'est un client JavaScript qui appelle les
# endpoints /admin/* CI-DESSUS, INCHANGÉS, avec le même header x-api-token
# que n'importe quel autre appelant de l'API (logiciel client, curl…).
# Aucune fonction ni aucun endpoint existant n'est modifié — une seule route
# GET statique est ajoutée, plus bas.
#
# Sécurité :
#   • le jeton n'est JAMAIS écrit dans le HTML renvoyé par le serveur — cette
#     page ne contient aucune donnée dynamique interpolée côté serveur, elle
#     est strictement identique pour tout le monde ;
#   • il est saisi par l'utilisateur dans son navigateur, gardé en mémoire
#     JS et en sessionStorage (effacé à la fermeture de l'onglet) — jamais en
#     localStorage, qui persisterait indéfiniment sur le téléphone ;
#   • il n'est jamais placé dans une URL, toujours en en-tête HTTP ;
#   • le serveur ne journalise aucun en-tête de requête (_log_event()
#     n'a jamais reçu x_api_token, avant comme après ce changement).
# ═══════════════════════════════════════════════════════════════════════════

_ADMIN_MOBILE_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, maximum-scale=1">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#1c1a17">
<title>Administration — EventManagerPro</title>
<style>
  :root { --ink:#1c1a17; --muted:#7a7168; --line:rgba(120,90,60,.14); --gold:#b08d57;
    --bg:#f6f3ee; --card:#ffffff; --danger:#c0392b; --ok:#2f9e5c; --warn:#b8860b; }
  * { box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
  html,body { height:100%; }
  body { margin:0; background:var(--bg); color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    padding-bottom:calc(24px + env(safe-area-inset-bottom)); }
  header { position:sticky; top:0; z-index:10; background:var(--ink); color:#fff;
    padding:calc(14px + env(safe-area-inset-top)) 18px 14px;
    display:flex; align-items:center; justify-content:space-between; }
  header h1 { font-size:17px; margin:0; font-weight:700; letter-spacing:.2px; }
  header button { background:none; border:1px solid rgba(255,255,255,.35); color:#fff;
    padding:8px 12px; border-radius:10px; font-size:13px; }
  main { max-width:640px; margin:0 auto; padding:16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:16px;
    padding:18px; margin-bottom:16px; box-shadow:0 6px 20px rgba(40,30,15,.06); }
  h2 { font-size:15px; margin:0 0 14px; font-weight:700; }
  label { display:block; font-size:12.5px; font-weight:600; margin:12px 0 6px; color:var(--muted); }
  input[type=text], input[type=number], input[type=password], select, textarea {
    width:100%; font-size:16px; padding:12px 13px; border:1px solid var(--line);
    border-radius:12px; background:#fff; color:var(--ink); font-family:inherit;
    -webkit-appearance:none; appearance:none; }
  textarea { min-height:64px; resize:vertical; }
  .row { display:flex; gap:10px; }
  .row > div { flex:1; min-width:0; }
  button.primary { width:100%; margin-top:16px; padding:14px; border:none; border-radius:12px;
    background:var(--gold); color:#fff; font-size:16px; font-weight:700; }
  button.ghost { padding:9px 12px; border-radius:10px; border:1px solid var(--line);
    background:#fff; color:var(--ink); font-size:13px; font-weight:600; }
  button.danger-ghost { padding:9px 12px; border-radius:10px; border:1px solid rgba(192,57,43,.35);
    background:#fff; color:var(--danger); font-size:13px; font-weight:600; }
  button:disabled { opacity:.5; }
  .msg { font-size:13px; padding:11px 13px; border-radius:11px; margin:0 0 14px; }
  .msg.err { background:#fbe9e6; color:var(--danger); }
  .msg.ok { background:#eaf6ee; color:var(--ok); }
  #view-login { min-height:80vh; display:flex; align-items:center; justify-content:center; padding:20px; }
  #view-login .card { width:100%; max-width:360px; }
  .lic { border-bottom:1px solid var(--line); padding:14px 0; }
  .lic:last-child { border-bottom:none; }
  .lic-top { display:flex; justify-content:space-between; align-items:flex-start; gap:10px; }
  .lic-name { font-weight:700; font-size:15px; }
  .lic-plan { color:var(--muted); font-size:12.5px; margin-top:2px; }
  .badge { font-size:11px; font-weight:700; padding:4px 9px; border-radius:20px; white-space:nowrap; }
  .badge.active { background:#eaf6ee; color:var(--ok); }
  .badge.blocked, .badge.revoked { background:#fbe9e6; color:var(--danger); }
  .badge.expired { background:#f1eee8; color:var(--muted); }
  .badge.trial { background:#fbf3de; color:var(--warn); }
  .lic-key { font-family:ui-monospace,Menlo,monospace; font-size:12.5px; color:var(--muted);
    margin-top:6px; word-break:break-all; }
  .lic-meta { font-size:12px; color:var(--muted); margin-top:4px; }
  .lic-actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
  .keybox { background:#fbf7ee; border:1.5px dashed var(--gold); border-radius:13px;
    padding:16px; text-align:center; margin-bottom:16px; }
  .keybox .k { font-family:ui-monospace,Menlo,monospace; font-size:20px; font-weight:700;
    letter-spacing:1px; word-break:break-all; margin:6px 0 12px; }
  .overlay { position:fixed; inset:0; background:rgba(20,15,8,.45); display:flex;
    align-items:flex-end; justify-content:center; z-index:50; }
  .sheet { background:#fff; width:100%; max-width:480px; border-radius:20px 20px 0 0;
    padding:20px 20px calc(20px + env(safe-area-inset-bottom)); max-height:82vh; overflow:auto; }
  .sheet h3 { margin:0 0 14px; font-size:16px; }
  .act-row { padding:10px 0; border-bottom:1px solid var(--line); font-size:13px; }
  .act-row:last-child { border-bottom:none; }
  .act-row .n { font-weight:700; }
  .act-row .s { color:var(--muted); }
  .hidden { display:none !important; }
  .spinner { display:inline-block; width:16px; height:16px; border:2px solid rgba(0,0,0,.15);
    border-top-color:var(--gold); border-radius:50%; animation:spin .7s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .empty { text-align:center; color:var(--muted); font-size:13.5px; padding:20px 0; }
  .stats { display:flex; gap:6px; margin-bottom:14px; }
  .stat { flex:1; min-width:0; background:var(--bg); border:1px solid var(--line); border-radius:12px;
    padding:9px 4px; text-align:center; }
  .stat .n { font-size:17px; font-weight:800; }
  .stat .l { font-size:9.5px; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.2px;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .stat.warn .n { color:var(--warn); }
  .audit-row { padding:9px 0; border-bottom:1px solid var(--line); font-size:12.5px; }
  .audit-row:last-child { border-bottom:none; }
  .audit-row .t { font-weight:700; }
  .audit-row .d { color:var(--muted); }
</style>
</head>
<body>

<div id="view-login">
  <div class="card">
    <h2>Administration EventManagerPro</h2>
    <div id="login-msg"></div>
    <label for="login-token">Jeton d'administration</label>
    <input type="password" id="login-token" autocomplete="off" autocapitalize="off"
           autocorrect="off" spellcheck="false" placeholder="x-api-token">
    <button class="primary" id="login-btn" onclick="doLogin()">Se connecter</button>
  </div>
</div>

<div id="view-main" class="hidden">
  <header>
    <h1>Licences</h1>
    <button onclick="doLogout()">Déconnexion</button>
  </header>
  <main>
    <div id="main-msg"></div>

    <div class="card">
      <h2>Nouvelle licence</h2>
      <label for="f-customer">Nom du client</label>
      <input type="text" id="f-customer" autocomplete="off" placeholder="ex. Sophie et Marc">

      <label for="f-plan">Formule</label>
      <select id="f-plan">
        <option value="Démo">Démo</option>
        <option value="Basic">Basic</option>
        <option value="Pro" selected>Pro</option>
        <option value="Expert">Expert</option>
      </select>

      <div class="row">
        <div>
          <label for="f-duration">Durée</label>
          <select id="f-duration" onchange="onDurationChange()">
            <option value="30">30 jours</option>
            <option value="90">90 jours</option>
            <option value="180">180 jours</option>
            <option value="365" selected>1 an</option>
            <option value="730">2 ans</option>
            <option value="custom">Personnalisée…</option>
          </select>
        </div>
        <div>
          <label for="f-devices">Postes</label>
          <input type="number" id="f-devices" min="1" max="100" value="2" inputmode="numeric">
        </div>
      </div>
      <input type="number" id="f-duration-custom" class="hidden" min="1" max="3650"
             inputmode="numeric" placeholder="Nombre de jours" style="margin-top:10px">

      <label for="f-notes">Note (facultatif)</label>
      <textarea id="f-notes" placeholder="ex. mariage du 12 juin 2027"></textarea>

      <button class="primary" id="create-btn">Créer la licence</button>
    </div>

    <div id="new-key-card" class="card hidden">
      <div class="keybox">
        <div style="font-size:12.5px;color:var(--muted);font-weight:600;">Licence créée</div>
        <div class="k" id="new-key-value"></div>
        <button class="ghost" id="copy-key-btn">📋 Copier la clé</button>
      </div>
    </div>

    <div class="card">
      <h2>Outils</h2>
      <div class="lic-actions">
        <button class="ghost" id="audit-log-btn">🗂️ Journal d'audit</button>
        <button class="ghost" id="backup-btn">💾 Sauvegarder la base</button>
      </div>
    </div>

    <div class="card">
      <h2>Licences existantes</h2>
      <div class="stats" id="stats-row"></div>
      <input type="text" id="lic-search" autocomplete="off" placeholder="Rechercher un client ou une clé…"
             style="margin-bottom:12px">
      <div id="lic-list"><div class="empty">Chargement…</div></div>
    </div>
  </main>
</div>

<div id="overlay-root"></div>

<script>
(function () {
  'use strict';
  var STORAGE_KEY = 'emp_admin_token';
  var token = '';
  var currentKey = '';

  function saveToken(t) { token = t; try { sessionStorage.setItem(STORAGE_KEY, t); } catch (e) {} }
  function loadSavedToken() { try { return sessionStorage.getItem(STORAGE_KEY) || ''; } catch (e) { return ''; } }
  function clearToken() { token = ''; try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) {} }

  function esc(s) {
    var d = document.createElement('div');
    d.textContent = (s === null || s === undefined) ? '' : String(s);
    return d.innerHTML;
  }
  function escAttr(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function api(path, opts) {
    opts = opts || {};
    var headers = Object.assign({ 'x-api-token': token }, opts.headers || {});
    var init = { method: opts.method || 'GET', headers: headers };
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.body);
    }
    return fetch(path, init).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var detail = (data && data.detail) ? data.detail : ('Erreur ' + res.status);
          var err = new Error(detail);
          err.status = res.status;
          throw err;
        }
        return data;
      });
    });
  }

  function showMsg(elId, text, isError) {
    var el = document.getElementById(elId);
    el.innerHTML = text ? ('<div class="msg ' + (isError ? 'err' : 'ok') + '">' + esc(text) + '</div>') : '';
  }

  // ── Connexion ────────────────────────────────────────────────────────
  function doLogin() {
    var t = (document.getElementById('login-token').value || '').trim();
    if (!t) { showMsg('login-msg', "Entre le jeton d'administration.", true); return; }
    var btn = document.getElementById('login-btn');
    btn.disabled = true; btn.textContent = 'Connexion…';
    token = t;
    api('/admin/licenses').then(function (data) {
      saveToken(t);
      showMsg('login-msg', '');
      document.getElementById('view-login').classList.add('hidden');
      document.getElementById('view-main').classList.remove('hidden');
      applyLicenses(data.items);
    }).catch(function (err) {
      token = '';
      showMsg('login-msg', err.status === 401 ? 'Jeton invalide.' : err.message, true);
    }).finally(function () {
      btn.disabled = false; btn.textContent = 'Se connecter';
    });
  }

  function doLogout() {
    clearToken();
    document.getElementById('login-token').value = '';
    document.getElementById('view-main').classList.add('hidden');
    document.getElementById('view-login').classList.remove('hidden');
  }

  // ── Formulaire de création ──────────────────────────────────────────
  function onDurationChange() {
    var sel = document.getElementById('f-duration');
    document.getElementById('f-duration-custom').classList.toggle('hidden', sel.value !== 'custom');
  }

  function createLicense() {
    var duration = document.getElementById('f-duration').value;
    if (duration === 'custom') duration = document.getElementById('f-duration-custom').value;
    duration = parseInt(duration, 10);
    var devices = parseInt(document.getElementById('f-devices').value, 10);
    if (!duration || duration < 1) { showMsg('main-msg', 'Durée invalide.', true); return; }
    if (!devices || devices < 1) { showMsg('main-msg', 'Nombre de postes invalide.', true); return; }

    var body = {
      customer_name: document.getElementById('f-customer').value.trim(),
      plan_name: document.getElementById('f-plan').value,
      max_devices: devices,
      duration_days: duration,
      notes: document.getElementById('f-notes').value.trim()
    };
    var btn = document.getElementById('create-btn');
    btn.disabled = true; btn.textContent = 'Création…';
    api('/admin/licenses', { method: 'POST', body: body }).then(function (data) {
      showMsg('main-msg', '');
      document.getElementById('f-customer').value = '';
      document.getElementById('f-notes').value = '';
      document.getElementById('new-key-value').textContent = data.license_key;
      document.getElementById('new-key-card').classList.remove('hidden');
      loadLicenses();
    }).catch(function (err) {
      showMsg('main-msg', err.message, true);
    }).finally(function () {
      btn.disabled = false; btn.textContent = 'Créer la licence';
    });
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(function () { fallbackCopy(text); });
    } else {
      fallbackCopy(text);
    }
  }
  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }

  // ── Liste des licences ──────────────────────────────────────────────
  var allLicenses = [];

  function applyLicenses(items) {
    allLicenses = items || [];
    renderStats(allLicenses);
    renderLicenses(filterLicenses(allLicenses, document.getElementById('lic-search').value));
  }

  function loadLicenses() {
    api('/admin/licenses').then(function (data) { applyLicenses(data.items); })
      .catch(function (err) { showMsg('main-msg', err.message, true); });
  }

  var STATUS_LABELS = { active: 'Active', blocked: 'Bloquée', revoked: 'Révoquée',
                         expired: 'Expirée', trial: 'Essai' };
  var PLAN_OPTIONS = ['Basic', 'Pro', 'Expert'];
  var SOON_DAYS = 30;

  function filterLicenses(items, term) {
    term = (term || '').trim().toLowerCase();
    if (!term) return items;
    return items.filter(function (it) {
      return (it.customer_name || '').toLowerCase().indexOf(term) !== -1 ||
             (it.license_key || '').toLowerCase().indexOf(term) !== -1;
    });
  }

  function renderStats(items) {
    var now = new Date();
    var soonLimit = new Date(now.getTime() + SOON_DAYS * 86400000);
    var counts = { total: items.length, active: 0, blocked: 0, soon: 0 };
    items.forEach(function (it) {
      if (it.status === 'active' || it.status === 'trial') counts.active++;
      if (it.status === 'blocked' || it.status === 'revoked') counts.blocked++;
      var exp = it.expires_at ? new Date(it.expires_at) : null;
      if (exp && exp > now && exp <= soonLimit && (it.status === 'active' || it.status === 'trial')) counts.soon++;
    });
    document.getElementById('stats-row').innerHTML =
      '<div class="stat"><div class="n">' + counts.total + '</div><div class="l">Total</div></div>' +
      '<div class="stat"><div class="n">' + counts.active + '</div><div class="l">Actives</div></div>' +
      '<div class="stat"><div class="n">' + counts.blocked + '</div><div class="l">Bloquées</div></div>' +
      '<div class="stat warn"><div class="n">' + counts.soon + '</div><div class="l">Expire &lt;30j</div></div>';
  }

  function renderLicenses(items) {
    var el = document.getElementById('lic-list');
    if (!items.length) { el.innerHTML = '<div class="empty">Aucune licence.</div>'; return; }
    el.innerHTML = items.map(function (it) {
      var statusCls = STATUS_LABELS[it.status] ? it.status : 'expired';
      var expires = it.expires_at ? it.expires_at.slice(0, 10) : '—';
      return (
        '<div class="lic">' +
          '<div class="lic-top">' +
            '<div>' +
              '<div class="lic-name">' + esc(it.customer_name || '(sans nom)') + '</div>' +
              '<div class="lic-plan">' + esc(it.plan_name) + ' · ' + it.used_devices + '/' + it.max_devices + ' postes</div>' +
            '</div>' +
            '<span class="badge ' + statusCls + '">' + (STATUS_LABELS[it.status] || esc(it.status)) + '</span>' +
          '</div>' +
          '<div class="lic-key">' + esc(it.license_key) + '</div>' +
          '<div class="lic-meta">Expire le ' + expires + (it.notes ? ' · ' + esc(it.notes) : '') + '</div>' +
          '<div class="lic-actions">' +
            '<button class="ghost" data-act="activations" data-key="' + escAttr(it.license_key) + '">Activations</button>' +
            '<button class="ghost" data-act="status" data-key="' + escAttr(it.license_key) + '" data-status="' + escAttr(it.status) + '">Statut</button>' +
            '<button class="ghost" data-act="plan" data-key="' + escAttr(it.license_key) + '" data-plan="' + escAttr(it.plan_name) + '">Formule</button>' +
            '<button class="ghost" data-act="history" data-key="' + escAttr(it.license_key) + '">Historique</button>' +
            '<button class="ghost" data-act="edit" data-key="' + escAttr(it.license_key) + '" data-customer="' + escAttr(it.customer_name) + '" data-notes="' + escAttr(it.notes) + '">Modifier</button>' +
            '<button class="ghost" data-act="extend" data-key="' + escAttr(it.license_key) + '">Prolonger</button>' +
            '<button class="danger-ghost" data-act="delete" data-key="' + escAttr(it.license_key) + '">Supprimer</button>' +
          '</div>' +
        '</div>'
      );
    }).join('');
  }

  // ── Feuilles modales ─────────────────────────────────────────────────
  function openSheet(html) {
    var root = document.getElementById('overlay-root');
    var overlay = document.createElement('div');
    overlay.className = 'overlay';
    overlay.innerHTML = '<div class="sheet">' + html + '</div>';
    overlay.addEventListener('click', function (ev) { if (ev.target === overlay) closeSheet(); });
    root.innerHTML = '';
    root.appendChild(overlay);
  }
  function closeSheet() { document.getElementById('overlay-root').innerHTML = ''; }

  function openActivations(key) {
    currentKey = key;
    openSheet('<h3>Activations — ' + esc(key) + '</h3><div id="act-body">Chargement…</div>');
    api('/admin/licenses/' + encodeURIComponent(key) + '/activations').then(function (data) {
      var items = data.items || [];
      var html = items.length ? items.map(function (a) {
        return '<div class="act-row"><div class="n">' + esc(a.machine_name || a.hostname || a.machine_id || '(poste sans nom)') +
          '</div><div class="s">' + esc(a.platform) + ' ' + esc(a.platform_release) + ' · ' + esc(a.status) +
          '<br>Dernière validation : ' + esc((a.last_validated_at || '').slice(0, 16).replace('T', ' ')) + '</div></div>';
      }).join('') : '<div class="empty">Aucune activation.</div>';
      document.getElementById('act-body').innerHTML = html;
    }).catch(function (err) {
      document.getElementById('act-body').innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
    });
  }

  function openStatus(key, current) {
    currentKey = key;
    var opts = Object.keys(STATUS_LABELS).map(function (s) {
      return '<option value="' + s + '"' + (s === current ? ' selected' : '') + '>' + STATUS_LABELS[s] + '</option>';
    }).join('');
    openSheet(
      '<h3>Statut — ' + esc(key) + '</h3>' +
      '<label>Nouveau statut</label><select id="status-select">' + opts + '</select>' +
      '<div id="status-msg"></div>' +
      '<button class="primary" id="status-confirm-btn">Mettre à jour</button>'
    );
  }
  function confirmStatus() {
    var status = document.getElementById('status-select').value;
    api('/admin/licenses/' + encodeURIComponent(currentKey) + '/status',
        { method: 'PATCH', body: { status: status } }).then(function () {
      closeSheet(); loadLicenses();
    }).catch(function (err) {
      document.getElementById('status-msg').innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
    });
  }

  function openPlan(key, current) {
    currentKey = key;
    var opts = PLAN_OPTIONS.map(function (p) { return '<option value="' + p + '">' + p + '</option>'; }).join('');
    openSheet(
      '<h3>Changer de formule — ' + esc(key) + '</h3>' +
      '<div class="lic-meta" style="margin-bottom:10px">Formule actuelle : ' + esc(current) + '</div>' +
      '<label>Nouvelle formule</label><select id="plan-select">' + opts + '</select>' +
      '<div id="plan-quote"></div>' +
      '<div id="plan-msg"></div>' +
      '<button class="ghost" id="plan-quote-btn" style="margin-top:14px;width:100%">Voir le montant proposé</button>' +
      '<button class="primary" id="plan-confirm-btn">Appliquer</button>'
    );
  }
  function quotePlan() {
    var plan = document.getElementById('plan-select').value;
    document.getElementById('plan-quote').innerHTML = '<div class="spinner"></div>';
    api('/admin/licenses/' + encodeURIComponent(currentKey) + '/upgrade-quote?plan_name=' + encodeURIComponent(plan))
      .then(function (data) {
        var q = data.quote;
        document.getElementById('plan-quote').innerHTML =
          '<div class="lic-meta" style="margin:10px 0">Montant suggéré : <b>' + q.suggested_amount + ' €</b>' +
          (q.expiry_reset ? ' (nouvelle période de licence)' : ' (échéance conservée)') + '</div>';
      }).catch(function (err) {
        document.getElementById('plan-quote').innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
      });
  }
  function confirmPlan() {
    var plan = document.getElementById('plan-select').value;
    api('/admin/licenses/' + encodeURIComponent(currentKey) + '/plan',
        { method: 'PATCH', body: { plan_name: plan } }).then(function () {
      closeSheet(); loadLicenses();
    }).catch(function (err) {
      document.getElementById('plan-msg').innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
    });
  }

  function openDelete(key) {
    currentKey = key;
    openSheet(
      '<h3>Supprimer la licence</h3>' +
      '<div class="lic-meta" style="margin-bottom:14px">Cette action est définitive et supprime aussi toutes ses activations. ' +
      'Pour confirmer, saisis la clé complète : <b>' + esc(key) + '</b></div>' +
      '<input type="text" id="del-confirm" autocomplete="off" autocapitalize="characters">' +
      '<div id="del-msg"></div>' +
      '<button class="primary" id="del-confirm-btn" style="background:var(--danger)">Supprimer définitivement</button>'
    );
  }
  function confirmDelete() {
    var typed = (document.getElementById('del-confirm').value || '').trim().toUpperCase();
    if (typed !== currentKey.toUpperCase()) {
      document.getElementById('del-msg').innerHTML = '<div class="msg err">La clé saisie ne correspond pas.</div>';
      return;
    }
    api('/admin/licenses/' + encodeURIComponent(currentKey), { method: 'DELETE' }).then(function () {
      closeSheet(); loadLicenses();
    }).catch(function (err) {
      document.getElementById('del-msg').innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
    });
  }

  function openHistory(key) {
    currentKey = key;
    openSheet('<h3>Historique des formules — ' + esc(key) + '</h3><div id="hist-body">Chargement…</div>');
    api('/admin/licenses/' + encodeURIComponent(key) + '/plan-changes').then(function (data) {
      var items = data.items || [];
      var html = items.length ? items.map(function (h) {
        return '<div class="audit-row"><div class="t">' + esc(h.old_plan) + ' → ' + esc(h.new_plan) + '</div>' +
          '<div class="d">' + esc((h.created_at || '').slice(0, 16).replace('T', ' ')) +
          (h.amount_charged ? ' · ' + esc(h.amount_charged) + ' €' : '') +
          (h.notes ? ' · ' + esc(h.notes) : '') + '</div></div>';
      }).join('') : '<div class="empty">Aucun changement de formule.</div>';
      document.getElementById('hist-body').innerHTML = html;
    }).catch(function (err) {
      document.getElementById('hist-body').innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
    });
  }

  function openEdit(key, customer, notes) {
    currentKey = key;
    openSheet(
      '<h3>Modifier — ' + esc(key) + '</h3>' +
      '<label>Nom du client</label><input type="text" id="edit-customer" value="' + escAttr(customer) + '">' +
      '<label>Note</label><textarea id="edit-notes">' + esc(notes) + '</textarea>' +
      '<div id="edit-msg"></div>' +
      '<button class="primary" id="edit-confirm-btn">Enregistrer</button>'
    );
  }
  function confirmEdit() {
    var body = {
      customer_name: document.getElementById('edit-customer').value.trim(),
      notes: document.getElementById('edit-notes').value.trim()
    };
    api('/admin/licenses/' + encodeURIComponent(currentKey) + '/details',
        { method: 'PATCH', body: body }).then(function () {
      closeSheet(); loadLicenses();
    }).catch(function (err) {
      document.getElementById('edit-msg').innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
    });
  }

  function openExtend(key) {
    currentKey = key;
    openSheet(
      '<h3>Prolonger l’échéance — ' + esc(key) + '</h3>' +
      '<div class="lic-meta" style="margin-bottom:10px">La formule actuelle est conservée — seule la date d’échéance avance.</div>' +
      '<label>Jours à ajouter</label>' +
      '<input type="number" id="extend-days" min="1" max="3650" value="365" inputmode="numeric">' +
      '<div id="extend-msg"></div>' +
      '<button class="primary" id="extend-confirm-btn">Prolonger</button>'
    );
  }
  function confirmExtend() {
    var days = parseInt(document.getElementById('extend-days').value, 10);
    if (!days || days < 1) {
      document.getElementById('extend-msg').innerHTML = '<div class="msg err">Nombre de jours invalide.</div>';
      return;
    }
    api('/admin/licenses/' + encodeURIComponent(currentKey) + '/extend',
        { method: 'PATCH', body: { additional_days: days } }).then(function () {
      closeSheet(); loadLicenses();
    }).catch(function (err) {
      document.getElementById('extend-msg').innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
    });
  }

  function openAuditLog() {
    openSheet('<h3>Journal d’audit</h3><div id="audit-body">Chargement…</div>');
    api('/admin/audit-log?limit=100').then(function (data) {
      var items = data.items || [];
      var html = items.length ? items.map(function (a) {
        return '<div class="audit-row"><div class="t">' + esc(a.event_type) +
          (a.license_key ? ' · ' + esc(a.license_key) : '') + '</div>' +
          '<div class="d">' + esc((a.created_at || '').slice(0, 16).replace('T', ' ')) + '</div></div>';
      }).join('') : '<div class="empty">Aucun événement.</div>';
      document.getElementById('audit-body').innerHTML = html;
    }).catch(function (err) {
      document.getElementById('audit-body').innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
    });
  }

  function downloadBackup() {
    var btn = document.getElementById('backup-btn');
    btn.disabled = true; btn.textContent = 'Préparation…';
    fetch('/admin/backup', { headers: { 'x-api-token': token } }).then(function (res) {
      if (!res.ok) throw new Error('Erreur ' + res.status);
      return res.blob();
    }).then(function (blob) {
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'license_server_backup.db';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    }).catch(function (err) {
      showMsg('main-msg', err.message, true);
    }).finally(function () {
      btn.disabled = false; btn.textContent = '💾 Sauvegarder la base';
    });
  }

  // ── Délégation d'évènements (aucune valeur dynamique dans du HTML/JS
  // généré : clé, statut, formule circulent comme de vraies valeurs JS, pas
  // comme du texte réinterprété) ─────────────────────────────────────────
  document.getElementById('login-btn').addEventListener('click', doLogin);
  document.getElementById('login-token').addEventListener('keydown', function (ev) {
    if (ev.key === 'Enter') doLogin();
  });
  document.querySelector('header button').addEventListener('click', doLogout);
  document.getElementById('f-duration').addEventListener('change', onDurationChange);
  document.getElementById('create-btn').addEventListener('click', createLicense);
  document.getElementById('copy-key-btn').addEventListener('click', function () {
    copyText(document.getElementById('new-key-value').textContent);
  });
  document.getElementById('lic-list').addEventListener('click', function (ev) {
    var btn = ev.target.closest('button[data-act]');
    if (!btn) return;
    var act = btn.getAttribute('data-act');
    var key = btn.getAttribute('data-key');
    if (act === 'activations') openActivations(key);
    else if (act === 'status') openStatus(key, btn.getAttribute('data-status'));
    else if (act === 'plan') openPlan(key, btn.getAttribute('data-plan'));
    else if (act === 'history') openHistory(key);
    else if (act === 'edit') openEdit(key, btn.getAttribute('data-customer'), btn.getAttribute('data-notes'));
    else if (act === 'extend') openExtend(key);
    else if (act === 'delete') openDelete(key);
  });
  document.getElementById('overlay-root').addEventListener('click', function (ev) {
    if (ev.target.id === 'status-confirm-btn') confirmStatus();
    else if (ev.target.id === 'plan-quote-btn') quotePlan();
    else if (ev.target.id === 'plan-confirm-btn') confirmPlan();
    else if (ev.target.id === 'edit-confirm-btn') confirmEdit();
    else if (ev.target.id === 'extend-confirm-btn') confirmExtend();
    else if (ev.target.id === 'del-confirm-btn') confirmDelete();
  });
  document.getElementById('audit-log-btn').addEventListener('click', openAuditLog);
  document.getElementById('backup-btn').addEventListener('click', downloadBackup);
  document.getElementById('lic-search').addEventListener('input', function () {
    renderLicenses(filterLicenses(allLicenses, this.value));
  });

  // ── Démarrage : reprise de session si un jeton est déjà en mémoire ────
  var saved = loadSavedToken();
  if (saved) {
    token = saved;
    api('/admin/licenses').then(function (data) {
      document.getElementById('view-login').classList.add('hidden');
      document.getElementById('view-main').classList.remove('hidden');
      applyLicenses(data.items);
    }).catch(function () { clearToken(); });
  }
})();
</script>
</body>
</html>"""


@app.get("/admin-mobile", response_class=HTMLResponse)
def admin_mobile_page() -> HTMLResponse:
    """Interface d'administration mobile — page STATIQUE uniquement : aucune
    donnée n'est interpolée côté serveur (le même HTML est renvoyé à tout le
    monde, jeton ou pas). Toutes les actions (création, liste, statut,
    formule, activations, suppression) passent par les endpoints /admin/*
    déjà existants et déjà protégés par _require_api_token — appelés
    directement depuis le JavaScript du navigateur avec le header
    x-api-token saisi par l'utilisateur. Rien n'est dupliqué ni modifié."""
    return HTMLResponse(_ADMIN_MOBILE_HTML)


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

_RSVP_ANSWER_LABELS = {"oui": "Oui", "non": "Non", "peut-être": "Peut-être"}
_RSVP_ANSWER_EMOJI = {"oui": "🎉", "non": "🤍", "peut-être": "🤔"}


def _rsvp_html_page(title: str, body: str) -> str:
    # Même thème (crème/or, carte arrondie, en-tête doré) que le portail RSVP
    # en direct (ui/rsvp_portal.py, _RSVP_CSS) — pour que l'invité ne voie
    # aucune différence visuelle entre les deux façons de répondre.
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#efe7db">
<title>{title}</title>
<style>
  :root {{ --ink:#2a2320; --muted:#8a7d72; --line:rgba(120,90,60,.16); --gold:#b08d57; --card:#fffdfa; }}
  * {{ box-sizing:border-box; -webkit-tap-highlight-color:transparent; }}
  body {{ margin:0; min-height:100vh; color:var(--ink);
    font-family: system-ui,-apple-system,'Segoe UI',sans-serif;
    background:
      radial-gradient(1200px 500px at 50% -10%, #fbf3e6 0%, rgba(251,243,230,0) 60%),
      linear-gradient(160deg,#f7f2ea 0%,#efe7db 100%);
    display:flex; align-items:flex-start; justify-content:center;
    padding:28px 16px calc(28px + env(safe-area-inset-bottom)); }}
  .wrap {{ width:100%; max-width:460px; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:22px;
    box-shadow:0 18px 50px rgba(70,50,30,.12); overflow:hidden; }}
  .top {{ height:6px; background:linear-gradient(90deg,#d9b877,#b08d57,#d9b877); }}
  .pad {{ padding:30px 26px 26px; }}
  h1 {{ font-family:Georgia,'Times New Roman',serif; font-weight:600;
    text-align:center; font-size:26px; line-height:1.15; margin:0 0 18px; }}
  label {{ display:block; font-weight:600; margin:14px 0 6px; font-size:13px; color:var(--ink); }}
  .choix {{ display:flex; flex-direction:column; gap:11px; margin-bottom:6px; }}
  .choix label {{ display:block; text-align:center; padding:15px; border-radius:13px;
                  cursor:pointer; margin:0; font-size:16px; font-weight:700;
                  background:#fff; color:var(--ink); border:1.5px solid var(--line);
                  transition:transform .08s, filter .15s; }}
  .choix label:active {{ transform:scale(.985); }}
  .choix input {{ display:none; }}
  .choix input:checked + span {{ }}
  .choix label.c-oui {{ background:linear-gradient(180deg,#3fbf72,#2f9e5c); color:#fff; border:none; }}
  .choix input:not(:checked) ~ span {{ }}
  .choix label.c-oui:has(input:not(:checked)) {{ background:#fff; color:#2f9e5c; border:1.5px solid #b7e3c8; }}
  .choix label.c-mb {{ color:#a9781c; border:1.5px solid #e6c98a; }}
  .choix label.c-mb:has(input:checked) {{ background:#fbf3de; }}
  .choix label.c-non {{ color:#b5473d; border:1.5px solid #e7b4ac; }}
  .choix label.c-non:has(input:checked) {{ background:#fbe9e6; }}
  textarea, input[type="text"], input[type="number"] {{
              width:100%; box-sizing:border-box; background:#fff; color:var(--ink);
              border:1px solid var(--line); border-radius:12px; padding:11px 12px;
              font-family:inherit; font-size:15px; }}
  textarea {{ min-height:70px; }}
  .row {{ display:flex; gap:10px; }}
  .row > div {{ flex:1; }}
  button {{ margin-top:20px; width:100%; padding:14px; border:none; border-radius:13px;
            background:var(--gold); color:#fff; font-size:16px; font-weight:700; cursor:pointer; }}
  p.hint {{ color:var(--muted); font-size:12.5px; text-align:center; margin:16px 0 0; }}
  .souscat {{ font-weight:700; font-size:12px; color:var(--gold); margin:16px 0 2px; }}
  .emoji {{ font-size:52px; text-align:center; margin:2px 0 8px; }}
  .greet {{ text-align:center; font-size:16px; margin:0 0 4px; }}
</style></head>
<body><div class="wrap"><div class="card"><div class="top"></div><div class="pad">{body}</div></div></div></body></html>"""


def _rsvp_form_page(relay_id: str, token: str, current_answer: str = "", current_comment: str = "",
                     current_plus_ones: int = 0, current_children: int = 0,
                     current_meal: str = "", current_diet: str = "",
                     current_companions: list | None = None) -> str:
    options = ""
    for value, label, css in (("oui", "Oui, avec joie !", "c-oui"),
                              ("peut-être", "Peut-être", "c-mb"),
                              ("non", "Non, je ne pourrai pas", "c-non")):
        checked = "checked" if value == current_answer else ""
        options += (f'<label class="{css}"><input type="radio" name="answer" value="{value}" {checked} required '
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
    emoji = _RSVP_ANSWER_EMOJI.get(answer, "✅")
    body = f"""
      <div class="emoji">{emoji}</div>
      <h1>Merci !</h1>
      <p class="greet">Votre réponse « <b>{label}</b> » a bien été enregistrée.</p>
      <p class="hint">Elle sera prise en compte dès que l'organisateur sera reconnecté —
      vous pouvez revenir sur ce lien à tout moment pour la modifier.</p>
    """
    return _rsvp_html_page("Merci", body)


def _rsvp_invalid_page(message: str) -> str:
    body = f"""
      <div class="emoji">🌸</div>
      <h1>Oups…</h1>
      <p class="greet">{message}</p>
    """
    return _rsvp_html_page("Lien invalide", body)


@app.post("/project/create")
def project_relay_create(payload: ProjectRelayCreateRequest) -> dict[str, Any]:
    """Crée un nouveau relais de projet. Ne transporte encore aucune donnée :
    le poste créateur doit ensuite appeler /project/{key}/push pour que
    l'autre poste ait quelque chose à récupérer (voir la doc du client)."""
    if _normalize_license_key(payload.product_code) != _normalize_license_key(str(SETTINGS.get("product_code") or DEFAULT_PRODUCT_CODE)):
        raise HTTPException(status_code=400, detail="product_code invalide.")

    machine_hash = _machine_fingerprint(payload.machine_id) if payload.machine_id else ""
    now = _utc_now()

    with _db() as con:
        license_row = _license_row_from_activation(con, payload.activation_id, machine_hash)
        status_error = _license_status_error(license_row)
        if status_error:
            raise HTTPException(status_code=403, detail=f"Licence {status_error}.")

        project_key = _random_project_key()
        project_secret = _random_project_secret()
        con.execute(
            """
            INSERT INTO project_relays(
                project_key, project_secret, owner_activation_id, label,
                checked_out_by, checked_out_at, created_at, last_activity_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_key, project_secret, payload.activation_id.strip(),
                payload.label.strip(), payload.holder_name.strip(), _iso(now),
                _iso(now), _iso(now),
            ),
        )
        _log_event(
            "project_relay_create",
            activation_id=payload.activation_id.strip(),
            machine_hash=machine_hash,
            details={"project_key": project_key, "label": payload.label.strip()},
            con=con,
        )
        return {"ok": True, "project_key": project_key, "project_secret": project_secret}


@app.post("/project/{project_key}/push")
def project_relay_push(
    project_key: str,
    file: UploadFile = File(...),
    holder_name: str = Form(default=""),
    x_project_secret: str | None = Header(default=None),
) -> dict[str, Any]:
    """Dépose la dernière version du projet (archive ZIP) sur le relais, prête
    à être récupérée par l'autre poste. `checked_out_by` est vidé : personne
    n'a « la main » tant que le pull-ack n'a pas eu lieu de l'autre côté."""
    data = file.file.read()
    if len(data) > MAX_PROJECT_RELAY_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Projet trop volumineux pour le relais cloud "
                f"({len(data) / (1024*1024):.1f} Mo, limite {MAX_PROJECT_RELAY_BYTES // (1024*1024)} Mo) "
                f"— souvent à cause des photos dans Galeries. Utilise l'export/import manuel (fichier ZIP) pour ce transfert."
            ),
        )
    now = _utc_now()
    with _db() as con:
        row = _require_project_relay(con, project_key, x_project_secret)
        con.execute(
            """
            UPDATE project_relays
            SET blob=?, blob_size=?, blob_pushed_by=?, blob_pushed_at=?,
                checked_out_by='', checked_out_at='', last_activity_at=?
            WHERE project_key=?
            """,
            (data, len(data), holder_name.strip(), _iso(now), _iso(now), str(row["project_key"])),
        )
        return {"ok": True, "blob_size": len(data)}


@app.get("/project/{project_key}/pull")
def project_relay_pull(project_key: str, x_project_secret: str | None = Header(default=None)) -> Response:
    """Renvoie l'archive en attente, SANS l'effacer — l'effacement n'a lieu
    qu'après confirmation de bonne réception via /pull-ack, pour ne rien
    perdre si le téléchargement échoue en cours de route."""
    with _db() as con:
        row = _require_project_relay(con, project_key, x_project_secret)
        if row["blob"] is None:
            raise HTTPException(status_code=404, detail="Rien à récupérer pour ce projet en ce moment.")
        return Response(
            content=bytes(row["blob"]),
            media_type="application/zip",
            headers={
                "X-Pushed-By": str(row["blob_pushed_by"] or ""),
                "X-Pushed-At": str(row["blob_pushed_at"] or ""),
            },
        )


@app.post("/project/{project_key}/pull-ack")
def project_relay_pull_ack(
    project_key: str, payload: ProjectRelayPullAckRequest,
    x_project_secret: str | None = Header(default=None),
) -> dict[str, Any]:
    """Confirme la récupération réussie : efface l'archive du serveur (jamais
    conservée durablement, même principe que le relais RSVP) et marque le
    poste qui vient de récupérer comme ayant désormais « la main »."""
    now = _utc_now()
    with _db() as con:
        row = _require_project_relay(con, project_key, x_project_secret)
        if row["blob"] is None:
            raise HTTPException(status_code=409, detail="Rien à confirmer : aucune archive en attente.")
        con.execute(
            """
            UPDATE project_relays
            SET blob=NULL, blob_size=0, checked_out_by=?, checked_out_at=?, last_activity_at=?
            WHERE project_key=?
            """,
            (payload.holder_name.strip(), _iso(now), _iso(now), str(row["project_key"])),
        )
        return {"ok": True}


@app.get("/project/{project_key}/status")
def project_relay_status(project_key: str, x_project_secret: str | None = Header(default=None)) -> dict[str, Any]:
    with _db() as con:
        row = _require_project_relay(con, project_key, x_project_secret)
        return {
            "ok": True,
            "label": str(row["label"] or ""),
            "has_pending": row["blob"] is not None,
            "pending_size": int(row["blob_size"] or 0),
            "pushed_by": str(row["blob_pushed_by"] or ""),
            "pushed_at": str(row["blob_pushed_at"] or ""),
            "checked_out_by": str(row["checked_out_by"] or ""),
            "checked_out_at": str(row["checked_out_at"] or ""),
            "created_at": str(row["created_at"] or ""),
        }


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


# ═══════════════════════════════════════════════════════════════════════════
# Boîte aux lettres « photos d'invités » (Galeries partagées, 25/08/2026)
#
# Même principe que la boîte aux lettres RSVP ci-dessus : réutilise la MÊME
# installation (relay_id/relay_secret créés par /rsvp/register — pas de
# second enregistrement, une seule « boîte aux lettres » par installation
# pour RSVP et Galeries). Un invité dépose une photo même quand le PC de
# l'organisateur est éteint ou hors wifi (26/08/2026 : ce lien passe
# désormais TOUJOURS par ce service, jamais par le Wi-Fi local — voir
# core/mailmerge.base_gallery_direct_url) ; le logiciel vient la récupérer
# puis en accuse réception (elle est alors effacée d'ici — ce serveur ne
# conserve jamais les photos durablement, seulement le temps du transit).
#
# Confidentialité : le serveur ne connaît jamais l'invité, seulement le
# jeton de galerie (gallery_token, déjà imprévisible, généré côté client).
# ═══════════════════════════════════════════════════════════════════════════


class GalleryAckRequest(BaseModel):
    ids: list[int] = Field(default_factory=list)


def _gallery_pending_total(con: sqlite3.Connection, relay_id: str, gallery_token: str) -> int:
    row = con.execute(
        "SELECT COALESCE(SUM(size), 0) AS total FROM gallery_pending WHERE relay_id=? AND gallery_token=?",
        (relay_id, gallery_token),
    ).fetchone()
    return int(row["total"] or 0)


def _photo_upload_page(relay_id: str, token: str) -> str:
    from urllib.parse import quote
    action = f"/{quote(str(relay_id), safe='')}/photos?t={quote(str(token), safe='')}"
    body = f"""
      <h1>Partagez vos photos</h1>
      <p class="greet">Ajoutez une ou plusieurs photos de la soirée, elles seront envoyées à l'organisateur.</p>
      <p class="hint">📶 Pas besoin du wifi de la salle : ça fonctionne avec votre connexion mobile.</p>
      <form method="post" action="{action}" enctype="multipart/form-data" id="f">
        <input type="file" name="file" accept="image/*" capture="environment" id="file" multiple>
        <button type="submit">Envoyer</button>
      </form>
      <p class="hint" id="statut"></p>
      <script>
        // Envoie chaque fichier sélectionné un par un (le serveur n'accepte
        // qu'un seul fichier par requête), pour rester simple côté serveur.
        var form = document.getElementById('f');
        form.addEventListener('submit', function (ev) {{
          ev.preventDefault();
          var files = document.getElementById('file').files;
          if (!files || !files.length) return;
          var statut = document.getElementById('statut');
          var i = 0, ok = 0;
          function next() {{
            if (i >= files.length) {{
              statut.textContent = ok + ' photo(s) envoyée(s) sur ' + files.length + '.';
              return;
            }}
            statut.textContent = 'Envoi ' + (i + 1) + '/' + files.length + '…';
            var fd = new FormData();
            fd.append('file', files[i]);
            fetch('{action}', {{ method: 'POST', body: fd }})
              .then(function (r) {{ if (r.ok) ok++; i++; next(); }})
              .catch(function () {{ i++; next(); }});
          }}
          next();
        }});
      </script>
    """
    return _rsvp_html_page("Partagez vos photos", body)


# Routes /photos/sync/... déclarées AVANT /{relay_id}/photos : même
# convention que pour la boîte aux lettres RSVP ci-dessus.
@app.get("/photos/sync/{relay_id}")
def gallery_sync(relay_id: str, x_relay_secret: str | None = Header(default=None)) -> dict[str, Any]:
    with _db() as con:
        _require_relay_installation(con, relay_id, x_relay_secret)
        rows = con.execute(
            "SELECT id, gallery_token, size, created_at FROM gallery_pending WHERE relay_id=? ORDER BY id",
            (relay_id,),
        ).fetchall()
        items = [
            {
                "id": int(r["id"]),
                "gallery_token": str(r["gallery_token"]),
                "size": int(r["size"] or 0),
                "created_at": str(r["created_at"]),
            }
            for r in rows
        ]
        return {"ok": True, "items": items}


@app.get("/photos/sync/{relay_id}/{photo_id}")
def gallery_sync_download(relay_id: str, photo_id: int, x_relay_secret: str | None = Header(default=None)) -> Response:
    with _db() as con:
        _require_relay_installation(con, relay_id, x_relay_secret)
        row = con.execute(
            "SELECT blob, content_type FROM gallery_pending WHERE relay_id=? AND id=?",
            (relay_id, photo_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Photo inconnue.")
        return Response(
            content=bytes(row["blob"] or b""),
            media_type=str(row["content_type"] or "application/octet-stream"),
        )


@app.post("/photos/sync/{relay_id}/ack")
def gallery_sync_ack(relay_id: str, payload: GalleryAckRequest, x_relay_secret: str | None = Header(default=None)) -> dict[str, Any]:
    with _db() as con:
        _require_relay_installation(con, relay_id, x_relay_secret)
        ids = []
        for i in (payload.ids or []):
            try:
                ids.append(int(i))
            except Exception:
                continue
        deleted = 0
        for i in ids:
            cur = con.execute("DELETE FROM gallery_pending WHERE relay_id=? AND id=?", (relay_id, i))
            deleted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        return {"ok": True, "deleted": deleted}


# Chemin /{relay_id}/photos (jeton de galerie en paramètre de requête
# ?t=...), même format que /{relay_id}/rsvp ci-dessus.
@app.get("/{relay_id}/photos", response_class=HTMLResponse)
def gallery_upload_page(relay_id: str, t: str = "") -> HTMLResponse:
    token = str(t or "").strip()
    with _db() as con:
        installation = con.execute(
            "SELECT 1 FROM rsvp_installations WHERE relay_id=?", (str(relay_id or "").strip(),)
        ).fetchone()
        if installation is None:
            return HTMLResponse(_rsvp_invalid_page("Ce lien ne correspond à aucun événement connu."), status_code=404)
        if not token:
            return HTMLResponse(_rsvp_invalid_page("Lien incomplet (jeton manquant)."), status_code=400)
    return HTMLResponse(_photo_upload_page(relay_id, token))


@app.post("/{relay_id}/photos")
async def gallery_upload_submit(relay_id: str, t: str = "", file: UploadFile = File(...)) -> dict[str, Any]:
    token = str(t or "").strip()
    now = _utc_now()
    with _db() as con:
        installation = con.execute(
            "SELECT 1 FROM rsvp_installations WHERE relay_id=?", (str(relay_id or "").strip(),)
        ).fetchone()
        if installation is None:
            raise HTTPException(status_code=404, detail="Ce lien ne correspond à aucun événement connu.")
        if not token:
            raise HTTPException(status_code=400, detail="Lien incomplet (jeton manquant).")
        data = await file.read()
        if not data:
            raise HTTPException(status_code=400, detail="Photo vide.")
        if len(data) > MAX_GALLERY_PHOTO_BYTES:
            raise HTTPException(status_code=413, detail="Photo trop volumineuse pour être envoyée ainsi.")
        total = _gallery_pending_total(con, relay_id, token)
        if total + len(data) > MAX_GALLERY_PENDING_BYTES:
            raise HTTPException(
                status_code=413,
                detail=(
                    "Trop de photos en attente pour cette galerie — demandez à l'organisateur de se "
                    "reconnecter pour les récupérer avant d'en envoyer d'autres."
                ),
            )
        con.execute(
            """
            INSERT INTO gallery_pending(relay_id, gallery_token, filename, content_type, size, blob, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                relay_id, token, str(file.filename or "photo.jpg"),
                str(file.content_type or "application/octet-stream"),
                len(data), data, _iso(now),
            ),
        )
        _log_event(
            "gallery_photo_received",
            details={"relay_id": relay_id, "gallery_token": token, "size": len(data)},
            con=con,
        )
        return {"ok": True, "size": len(data)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "license_server:app",
        host="0.0.0.0",
        port=8010,
        reload=False,
    )
