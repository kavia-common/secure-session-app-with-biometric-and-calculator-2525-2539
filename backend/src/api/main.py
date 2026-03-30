from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# -------------------------
# Minimal demo auth system
# -------------------------
#
# Design goals:
# - No DB required
# - No external auth dependencies required (demo-friendly)
# - Access token + refresh token
# - Refresh tokens stored in-memory (per-process) so logout/rotation works
# - Tokens are signed (HMAC) so the backend can verify integrity


def _env_int(name: str, default: int) -> int:
    """Read an int from env with a safe fallback."""
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


APP_TITLE = "Secure Session Demo API"
APP_VERSION = "0.2.0"
APP_DESCRIPTION = (
    "Minimal demo API providing session auth endpoints for a Swift iOS client.\n\n"
    "Auth flow:\n"
    "1) POST /auth/login -> returns access_token + refresh_token\n"
    "2) Use `Authorization: Bearer <access_token>` for protected routes (e.g., GET /me)\n"
    "3) When access_token expires, POST /auth/refresh with refresh_token -> new access_token (+ rotated refresh_token)\n"
    "4) POST /auth/logout with refresh_token -> revoke refresh token\n\n"
    "Notes:\n"
    "- Refresh tokens are stored in-memory (lost on process restart).\n"
    "- Access tokens are stateless and expire based on `exp`.\n"
)

openapi_tags = [
    {"name": "System", "description": "Health and system endpoints."},
    {"name": "Auth", "description": "Login/refresh/logout and session information."},
]

# Token configuration (demo defaults)
ACCESS_TOKEN_TTL_SECONDS = _env_int("ACCESS_TOKEN_TTL_SECONDS", 15 * 60)  # 15 min
REFRESH_TOKEN_TTL_SECONDS = _env_int("REFRESH_TOKEN_TTL_SECONDS", 7 * 24 * 60 * 60)  # 7 days

# Secret used to sign access tokens.
# IMPORTANT: Set ACCESS_TOKEN_SIGNING_SECRET in .env for production-like usage.
_ACCESS_TOKEN_SIGNING_SECRET = os.getenv("ACCESS_TOKEN_SIGNING_SECRET", "dev-insecure-secret-change-me")
_SIGNING_KEY_BYTES = _ACCESS_TOKEN_SIGNING_SECRET.encode("utf-8")

# In-memory refresh token store:
# refresh_token -> {sub, exp, session_id}
_REFRESH_STORE: Dict[str, Dict[str, Any]] = {}


def _b64url_encode(raw: bytes) -> str:
    """Base64-url encode without padding."""
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    """Base64-url decode (adding padding if required)."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("utf-8"))


def _sign(message: bytes) -> str:
    """Compute base64url(HMAC-SHA256(message))."""
    digest = hmac.new(_SIGNING_KEY_BYTES, message, hashlib.sha256).digest()
    return _b64url_encode(digest)


def _make_access_token(sub: str, session_id: str, ttl_seconds: int) -> str:
    """
    Create a compact signed token: base64url(payload_json) + '.' + signature

    Payload fields:
      - sub: subject (user id / username)
      - sid: session id (ties to refresh session conceptually)
      - exp: unix epoch seconds
      - typ: "access"
    """
    payload = {
        "sub": sub,
        "sid": session_id,
        "exp": int(time.time()) + ttl_seconds,
        "typ": "access",
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    encoded_payload = _b64url_encode(payload_json)
    sig = _sign(encoded_payload.encode("utf-8"))
    return f"{encoded_payload}.{sig}"


def _verify_access_token(token: str) -> Dict[str, Any]:
    """Verify signature and expiry of an access token; return decoded payload."""
    try:
        encoded_payload, sig = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format") from exc

    expected_sig = _sign(encoded_payload.encode("utf-8"))
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature")

    try:
        payload = json.loads(_b64url_decode(encoded_payload))
    except Exception as exc:  # noqa: BLE001 - broad decode errors should map to 401
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload") from exc

    if payload.get("typ") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type")

    exp = payload.get("exp")
    if not isinstance(exp, int) or exp <= int(time.time()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    sub = payload.get("sub")
    sid = payload.get("sid")
    if not isinstance(sub, str) or not isinstance(sid, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")

    return payload


def _make_refresh_token() -> str:
    """Create an opaque refresh token."""
    return secrets.token_urlsafe(48)


def _issue_refresh_token(sub: str, session_id: str, ttl_seconds: int) -> Tuple[str, int]:
    """Create and store refresh token with expiry; return (token, exp)."""
    token = _make_refresh_token()
    exp = int(time.time()) + ttl_seconds
    _REFRESH_STORE[token] = {"sub": sub, "sid": session_id, "exp": exp}
    return token, exp


def _validate_refresh_token(refresh_token: str) -> Dict[str, Any]:
    """Validate refresh token exists in store and not expired; return record."""
    record = _REFRESH_STORE.get(refresh_token)
    if not record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    if int(record.get("exp", 0)) <= int(time.time()):
        # Expired: remove and reject
        _REFRESH_STORE.pop(refresh_token, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    return record


def _revoke_refresh_token(refresh_token: str) -> None:
    """Remove refresh token from store if present."""
    _REFRESH_STORE.pop(refresh_token, None)


def _rotate_refresh_token(refresh_token: str) -> Tuple[Dict[str, Any], str, int]:
    """Revoke an existing refresh token and issue a new one for the same session."""
    record = _validate_refresh_token(refresh_token)
    _revoke_refresh_token(refresh_token)
    new_token, new_exp = _issue_refresh_token(record["sub"], record["sid"], REFRESH_TOKEN_TTL_SECONDS)
    return record, new_token, new_exp


# -------------------------
# API models
# -------------------------


class LoginRequest(BaseModel):
    username: str = Field(..., description="Demo username. For demo purposes any username is accepted.")
    password: str = Field(..., description="Demo password. For demo purposes any password is accepted.")


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="Signed access token to use in Authorization: Bearer <token>.")
    access_token_expires_in: int = Field(..., description="Seconds until access token expiry.")
    refresh_token: str = Field(..., description="Opaque refresh token used with /auth/refresh and /auth/logout.")
    refresh_token_expires_in: int = Field(..., description="Seconds until refresh token expiry.")
    token_type: str = Field("bearer", description='Token type. Always "bearer".')


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="The refresh token previously returned by /auth/login or /auth/refresh.")


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token to revoke (logout).")


class MeResponse(BaseModel):
    username: str = Field(..., description="Authenticated username (from access token).")
    session_id: str = Field(..., description="Session id (sid claim from access token).")
    access_expires_at: int = Field(..., description="Unix epoch seconds when the current access token expires.")


security = HTTPBearer(auto_error=False)


def _require_bearer_token(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    """Dependency to enforce Bearer auth and return validated token payload."""
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    return _verify_access_token(creds.credentials)


# -------------------------
# FastAPI app
# -------------------------

app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # demo-friendly; tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["System"])
# PUBLIC_INTERFACE
def health_check() -> Dict[str, str]:
    """Health check endpoint used by deployment/runtime monitors."""
    return {"message": "Healthy"}


@app.post(
    "/auth/login",
    response_model=TokenResponse,
    tags=["Auth"],
    summary="Login and issue access+refresh tokens",
    description="Demo login endpoint. Accepts any username/password and returns tokens with expiry.",
)
# PUBLIC_INTERFACE
def login(payload: LoginRequest) -> TokenResponse:
    """Login endpoint that issues access+refresh tokens for demo usage."""
    # Demo: accept any credentials. In real systems verify against DB/IdP.
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username required")

    session_id = secrets.token_urlsafe(16)

    access_token = _make_access_token(username, session_id, ACCESS_TOKEN_TTL_SECONDS)
    refresh_token, _ = _issue_refresh_token(username, session_id, REFRESH_TOKEN_TTL_SECONDS)

    return TokenResponse(
        access_token=access_token,
        access_token_expires_in=ACCESS_TOKEN_TTL_SECONDS,
        refresh_token=refresh_token,
        refresh_token_expires_in=REFRESH_TOKEN_TTL_SECONDS,
        token_type="bearer",
    )


@app.post(
    "/auth/refresh",
    response_model=TokenResponse,
    tags=["Auth"],
    summary="Refresh access token (and rotate refresh token)",
    description=(
        "Exchanges a valid refresh token for a new access token. "
        "For demo safety, refresh tokens are rotated: the old refresh token is revoked and a new one is issued."
    ),
)
# PUBLIC_INTERFACE
def refresh(payload: RefreshRequest) -> TokenResponse:
    """Refresh endpoint that validates+rotates refresh token and returns new tokens."""
    record, new_refresh_token, _ = _rotate_refresh_token(payload.refresh_token)

    sub = record["sub"]
    sid = record["sid"]
    new_access_token = _make_access_token(sub, sid, ACCESS_TOKEN_TTL_SECONDS)

    return TokenResponse(
        access_token=new_access_token,
        access_token_expires_in=ACCESS_TOKEN_TTL_SECONDS,
        refresh_token=new_refresh_token,
        refresh_token_expires_in=REFRESH_TOKEN_TTL_SECONDS,
        token_type="bearer",
    )


@app.post(
    "/auth/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Auth"],
    summary="Logout (revoke refresh token)",
    description="Revokes the provided refresh token from the in-memory store. Access tokens remain valid until expiry.",
)
# PUBLIC_INTERFACE
def logout(payload: LogoutRequest) -> Response:
    """Logout endpoint that revokes refresh token."""
    _revoke_refresh_token(payload.refresh_token)
    # Always return 204 to avoid leaking whether token existed.
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get(
    "/me",
    response_model=MeResponse,
    tags=["Auth"],
    summary="Get current user (protected)",
    description="Protected endpoint. Requires Authorization: Bearer <access_token>.",
)
# PUBLIC_INTERFACE
def me(token_payload: Dict[str, Any] = Depends(_require_bearer_token)) -> MeResponse:
    """Protected endpoint returning current user information derived from the access token."""
    return MeResponse(
        username=token_payload["sub"],
        session_id=token_payload["sid"],
        access_expires_at=token_payload["exp"],
    )
