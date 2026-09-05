from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import hashlib
import hmac
import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_der_public_key,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

PORT = int(os.environ.get("SOSYNC_COMPANION_PORT", "8765"))
DEFAULT_HOME_ASSISTANT_URL = "http://127.0.0.1:8123"
DEFAULT_COMPANION_URL = "http://127.0.0.1:8765"
REMOTE_PREFIX = "/remote/ha"
SIGNED_REMOTE_PREFIX = "/remote/signed"
SIGNED_REMOTE_PATTERN = re.compile(r"^/remote/signed/([0-9]{10,})/([A-Za-z0-9_-]{16,})/([A-Za-z0-9_-]{20,})/ha(/.*)?$")
SIGNED_ROUTE_MAX_TTL_SECONDS = 300
DATA_DIR = os.environ.get("SOSYNC_DATA_DIR", "/data")
REMOTE_TOKEN_FILE = os.path.join(DATA_DIR, "sosync_remote_token")
HA_UPSTREAM_FILE = os.path.join(DATA_DIR, "sosync_ha_upstream")
SERVER_ID_FILE = os.path.join(DATA_DIR, "sosync_server_id")
REMOTE_URL_FILE = os.path.join(DATA_DIR, "sosync_remote_url")
HOME_PROFILE_FILE = os.path.join(DATA_DIR, "sosync_home_profile.json")
ADDON_OPTIONS_FILE = os.path.join(DATA_DIR, "options.json")
COMPANION_IDENTITY_FILE = os.path.join(DATA_DIR, "sosync_companion_identity.json")
PAIRINGS_FILE = os.path.join(DATA_DIR, "sosync_pairings.json")
E2EE_IDENTITY_FILE = os.path.join(DATA_DIR, "sosync_e2ee_identity.json")
E2EE_PAIRINGS_FILE = os.path.join(DATA_DIR, "sosync_e2ee_pairings.json")
SECURE_REMOTE_BINDING_FILE = os.path.join(DATA_DIR, "sosync_secure_remote_binding.json")
SECURE_REMOTE_TUNNEL_TOKEN_FILE = os.path.join(DATA_DIR, "sosync_secure_remote_tunnel_token")
SECURE_REMOTE_TUNNEL_STDERR_FILE = os.path.join(DATA_DIR, "sosync_secure_remote_cloudflared_stderr.log")
CONSUMED_PACKAGES_FILE = os.path.join(DATA_DIR, "sosync_consumed_setup_packages.json")
HOME_CONFIGURATION_FILE = os.path.join(DATA_DIR, "sosync_home_configuration.json")
REMOTE_TOKEN_HEADER = "X-SoSync-Remote-Token"
LOCAL_PAIRING_TOKEN_HEADER = "X-SoSync-Local-Pairing-Token"
LEGACY_LOCAL_PAIRING_TOKEN_HEADER = "X-BeSmart-Local-Pairing-Token"
HOME_PROFILE_PATH = "/sosync/home-profile"
LEGACY_HOME_PROFILE_PATH = "/besmart/home-profile"
HOME_CONFIGURATION_PATH = "/sosync/home-config"
HOME_CONFIGURATION_MUTATION_PATH = "/sosync/home-config/mutate"
MAX_HOME_PROFILE_BYTES = 512 * 1024
MAX_HOME_CONFIGURATION_BYTES = 512 * 1024
HOME_PROFILE_WRITE_LOCK = threading.Lock()
HOME_CONFIGURATION_WRITE_LOCK = threading.RLock()
PAIRING_TTL_SECONDS = 120
E2EE_PROTOCOL_VERSION = 1
SETUP_PACKAGE_INFO = b"sosync-remote-setup-package-v1"
SETUP_PACKAGE_ENCRYPTION_ALG = "HPKE-X25519-HKDF-SHA256-CHACHA20-POLY1305"
SETUP_PACKAGE_SIGNATURE_ALG = "Ed25519"
RUNTIME_INSTANCE_ID = str(uuid.uuid4())
RUNTIME_STARTED_AT = datetime.now(timezone.utc).isoformat()
SOSYNC_COMPANION_VERSION = os.environ.get("SOSYNC_COMPANION_VERSION", "development")
SOSYNC_COMPANION_BUILD = os.environ.get("SOSYNC_COMPANION_BUILD", "development")
SECURE_REMOTE_TUNNEL_CONFIRMATION_SECONDS = float(os.environ.get("SOSYNC_TUNNEL_CONFIRMATION_SECONDS", "1.0"))
SECURE_REMOTE_CONNECTOR_CONFIRMATION_SECONDS = float(os.environ.get("SOSYNC_CONNECTOR_CONFIRMATION_SECONDS", "0.8"))
SECURE_REMOTE_TUNNEL_LOCK = threading.Lock()
SECURE_REMOTE_TUNNEL_PROCESS = None
SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY = None
SECURE_REMOTE_TUNNEL_STARTING = False
SECURE_REMOTE_DATAPLANE_SESSIONS = {}
SECURE_REMOTE_DATAPLANE_LOCK = threading.Lock()
SECURE_REMOTE_DATAPLANE_REVOCATION_POLL_SECONDS = 1.0
SECURE_REMOTE_BINDING_STATS = {
    "bindingChecks": 0,
    "diskReads": 0,
    "cacheHits": 0,
    "revocationPolls": 0,
    "lastSummaryAt": time.monotonic()
}
SECURE_REMOTE_BINDING_STATS_LOCK = threading.Lock()
SECURE_REMOTE_WS_LOG_COUNTS = {}
SECURE_REMOTE_WS_LOG_LOCK = threading.Lock()
COMPANION_REQUEST_LOCK = threading.Lock()
COMPANION_JSON_WRITE_LOCK = threading.Lock()
COMPANION_IDENTITY_LOCK = threading.Lock()
E2EE_IDENTITY_LOCK = threading.Lock()
COMPANION_CACHE_LOCK = threading.Lock()
COMPANION_ACTIVE_HTTP_REQUESTS = 0
COMPANION_ACTIVE_WEBSOCKETS = 0
COMPANION_REQUEST_SEQUENCE = 0
COMPANION_E2EE_SESSION_CORRELATION = {}
COMPANION_RUNTIME_HEARTBEAT_STOP = threading.Event()
COMPANION_IDENTITY_CACHE = None
E2EE_IDENTITY_CACHE = None
E2EE_PUBLIC_KEY_NORMALIZATION_CACHE = {}
E2EE_PUBLIC_KEY_NORMALIZATION_LOCK = threading.Lock()
COMPANION_JSON_READ_CACHE = {}
CLOUDFLARED_RUNTIME_STATUS_CACHE = None
CLOUDFLARED_RUNTIME_STATUS_CACHE_EXPIRES_AT = 0
SECURE_REMOTE_CONNECTOR_STATUS_CACHE = None
SECURE_REMOTE_CONNECTOR_STATUS_CACHE_EXPIRES_AT = 0
print(
    f"[SOSYNC-E2EE-COMPANION] runtimeGlobalsInitialized runtimeInstance={RUNTIME_INSTANCE_ID} build={SOSYNC_COMPANION_BUILD}",
    flush=True
)
print(
    f"[SOSYNC-E2EE-COMPANION] companionBuild marker={SOSYNC_COMPANION_BUILD} version={SOSYNC_COMPANION_VERSION}",
    flush=True
)


def companion_path_class(path):
    request_path = urlparse(path or "/").path
    if request_path == "/identity":
        return "identity"
    if request_path == "/health":
        return "health"
    if request_path.startswith("/secure-remote/data-plane/e2ee/ws"):
        return "secureRemoteEncryptedWebSocket"
    if request_path.startswith("/secure-remote/data-plane/e2ee/session"):
        return "secureRemoteEncryptedSession"
    if request_path.startswith("/secure-remote/data-plane/e2ee/rest"):
        return "secureRemoteEncryptedREST"
    if request_path.startswith("/secure-remote/data-plane"):
        return "secureRemoteDataPlane"
    if request_path.startswith("/secure-remote"):
        return "secureRemoteControlPlane"
    if request_path.startswith("/security/e2ee"):
        return "e2eeControlPlane"
    if is_home_configuration_path(request_path) or is_home_configuration_mutation_path(request_path):
        return "homeConfiguration"
    if request_path.startswith("/remote/"):
        return "legacyRemoteProxy"
    return "other"


def is_home_profile_path(path):
    request_path = urlparse(path or "/").path
    return request_path in (HOME_PROFILE_PATH, LEGACY_HOME_PROFILE_PATH)


def is_home_configuration_path(path):
    request_path = urlparse(path or "/").path
    return request_path == HOME_CONFIGURATION_PATH


def is_home_configuration_mutation_path(path):
    request_path = urlparse(path or "/").path
    return request_path == HOME_CONFIGURATION_MUTATION_PATH


def local_pairing_token_contract(headers):
    canonical = str(headers.get(LOCAL_PAIRING_TOKEN_HEADER) or "").strip()
    legacy = str(headers.get(LEGACY_LOCAL_PAIRING_TOKEN_HEADER) or "").strip()
    if canonical and legacy:
        return ("both", canonical)
    if canonical:
        return ("soSyncCanonical", canonical)
    if legacy:
        return ("legacyBeSmart", legacy)
    return ("missing", "")


def safe_pairing_payload_schema_version(data):
    if isinstance(data, dict):
        value = data.get("protocol_version")
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str) and value.strip().isdigit():
            return value.strip()
    return "unknown"


def log_e2ee_pairing_rejection(
    path_class,
    header_contract,
    payload_schema_version,
    rejection_class,
    missing_fields=None,
    invalid_fields=None,
    decoded_public_key_bytes="unknown",
    token_authorized=False,
    syntactically_valid_home_id="unknown",
    home_binding_matches="unknown",
):
    missing_fields = missing_fields or []
    invalid_fields = invalid_fields or []
    token_authorized_value = str(bool(token_authorized)).lower()
    print(
        "[SOSYNC-E2EE-COMPANION] pairingRequestRejected "
        f"pathClass={path_class} "
        f"headerContract={header_contract} "
        f"payloadSchemaVersion={payload_schema_version} "
        f"rejectionClass={rejection_class} "
        f"missingFields={','.join(missing_fields) or 'none'} "
        f"invalidFields={','.join(invalid_fields) or 'none'} "
        f"decodedPublicKeyBytes={decoded_public_key_bytes} "
        f"tokenAuthorized={token_authorized_value} "
        f"syntacticallyValidHomeID={syntactically_valid_home_id} "
        f"homeBindingMatches={home_binding_matches}",
        flush=True
    )
    print(
        "[SOSYNC-E2EE-COMPANION] e2eePairValidation "
        f"result=rejected "
        f"reason={rejection_class} "
        f"missingFields={','.join(missing_fields) or 'none'} "
        f"invalidFields={','.join(invalid_fields) or 'none'} "
        f"schemaVersion={payload_schema_version} "
        f"decodedPublicKeyBytes={decoded_public_key_bytes} "
        f"tokenAuthorized={token_authorized_value} "
        f"syntacticallyValidHomeID={syntactically_valid_home_id} "
        f"homeBindingMatches={home_binding_matches}",
        flush=True
    )


def log_e2ee_pairing_acceptance(
    payload_schema_version,
    decoded_public_key_bytes,
    home_binding_matches,
):
    print(
        "[SOSYNC-E2EE-COMPANION] e2eePairValidation "
        "result=accepted "
        "reason=validated "
        "missingFields=none "
        "invalidFields=none "
        f"schemaVersion={payload_schema_version} "
        f"decodedPublicKeyBytes={decoded_public_key_bytes} "
        "tokenAuthorized=true "
        "syntacticallyValidHomeID=true "
        f"homeBindingMatches={home_binding_matches}",
        flush=True
    )


def companion_request_started(method, path):
    global COMPANION_ACTIVE_HTTP_REQUESTS
    global COMPANION_REQUEST_SEQUENCE
    with COMPANION_REQUEST_LOCK:
        COMPANION_REQUEST_SEQUENCE += 1
        request_id = COMPANION_REQUEST_SEQUENCE
        COMPANION_ACTIVE_HTTP_REQUESTS += 1
        active_http = COMPANION_ACTIVE_HTTP_REQUESTS
        active_websockets = COMPANION_ACTIVE_WEBSOCKETS
    print(
        "[SOSYNC-COMPANION-REQUEST] "
        f"stage=started requestID={request_id} method={method} "
        f"pathClass={companion_path_class(path)} activeHTTP={active_http} "
        f"activeWebSockets={active_websockets} thread={threading.get_ident()}",
        flush=True
    )
    return request_id


def companion_client_scope(client_address):
    host = "unknown"
    if isinstance(client_address, tuple) and client_address:
        host = str(client_address[0] or "unknown")
    if host.startswith("127.") or host == "::1":
        return "loopback"
    if host.startswith("10.") or host.startswith("192.168."):
        return "privateLAN"
    if host.startswith("172."):
        parts = host.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return "privateLAN"
    if host.startswith("169.254.") or host.lower().startswith("fe80:"):
        return "linkLocal"
    if ":" in host:
        return "ipv6"
    return "publicOrUnknown"


def companion_listener_address_summary(server):
    try:
        bind_host, bind_port = server.server_address[:2]
    except (AttributeError, TypeError, ValueError):
        return "bindAddress=unknown port=unknown"
    parts = [
        f"bindAddress={bind_host}",
        f"port={bind_port}",
        f"family={getattr(server, 'address_family', 'unknown')}",
        f"socketName={safe_listener_socket_name(server)}",
    ]
    return " ".join(parts)


def safe_listener_socket_name(server):
    try:
        socket_name = server.socket.getsockname()
    except OSError:
        return "unavailable"
    if not isinstance(socket_name, tuple) or len(socket_name) < 2:
        return "unknown"
    return f"{socket_name[0]}:{socket_name[1]}"


def companion_request_completed(request_id, method, path, started_at):
    global COMPANION_ACTIVE_HTTP_REQUESTS
    elapsed_ms = int((time.monotonic() - started_at) * 1000)
    with COMPANION_REQUEST_LOCK:
        COMPANION_ACTIVE_HTTP_REQUESTS = max(0, COMPANION_ACTIVE_HTTP_REQUESTS - 1)
        active_http = COMPANION_ACTIVE_HTTP_REQUESTS
        active_websockets = COMPANION_ACTIVE_WEBSOCKETS
    print(
        "[SOSYNC-COMPANION-REQUEST] "
        f"stage=completed requestID={request_id} method={method} "
        f"pathClass={companion_path_class(path)} activeHTTP={active_http} "
        f"activeWebSockets={active_websockets} elapsedMs={elapsed_ms} "
        f"thread={threading.get_ident()}",
        flush=True
    )


def companion_websocket_started(route_id, session_id):
    global COMPANION_ACTIVE_WEBSOCKETS
    with COMPANION_REQUEST_LOCK:
        COMPANION_ACTIVE_WEBSOCKETS += 1
        active_http = COMPANION_ACTIVE_HTTP_REQUESTS
        active_websockets = COMPANION_ACTIVE_WEBSOCKETS
    print(
        "[SOSYNC-COMPANION-REQUEST] "
        f"stage=webSocketStarted route={safe_fingerprint(route_id)} "
        f"session={safe_fingerprint(session_id)} activeHTTP={active_http} "
        f"activeWebSockets={active_websockets} thread={threading.get_ident()}",
        flush=True
    )


def companion_websocket_completed(route_id, session_id, started_at):
    global COMPANION_ACTIVE_WEBSOCKETS
    elapsed_ms = int((time.monotonic() - started_at) * 1000)
    with COMPANION_REQUEST_LOCK:
        COMPANION_ACTIVE_WEBSOCKETS = max(0, COMPANION_ACTIVE_WEBSOCKETS - 1)
        active_http = COMPANION_ACTIVE_HTTP_REQUESTS
        active_websockets = COMPANION_ACTIVE_WEBSOCKETS
    print(
        "[SOSYNC-COMPANION-REQUEST] "
        f"stage=webSocketCompleted route={safe_fingerprint(route_id)} "
        f"session={safe_fingerprint(session_id)} activeHTTP={active_http} "
        f"activeWebSockets={active_websockets} elapsedMs={elapsed_ms} "
        f"thread={threading.get_ident()}",
        flush=True
    )


def elapsed_ms_since(started_at):
    return int((time.monotonic() - started_at) * 1000)


def companion_runtime_counts_unlocked():
    return COMPANION_ACTIVE_HTTP_REQUESTS, COMPANION_ACTIVE_WEBSOCKETS


def companion_perf_log(event, **fields):
    active_http, active_websockets = companion_runtime_counts_unlocked()
    parts = [
        "[SOSYNC-COMPANION-PERF]",
        f"event={event}",
        f"thread={threading.get_ident()}",
        f"activeHTTP={active_http}",
        f"activeWebSockets={active_websockets}",
    ]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    print(" ".join(parts), flush=True)


def companion_identity_server_perf(phase, request_id, started_at, **fields):
    parts = [
        "[SOSYNC-COMPANION-IDENTITY-SERVER-PERF]",
        f"phase={phase}",
        f"requestID={request_id}",
        f"elapsedMs={elapsed_ms_since(started_at)}",
        f"runtimeInstance={RUNTIME_INSTANCE_ID}",
        f"thread={threading.get_ident()}",
    ]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    print(" ".join(parts), flush=True)


def start_companion_runtime_heartbeat(interval_seconds=0.5, stall_threshold_ms=1500):
    def heartbeat():
        previous = time.monotonic()
        while not COMPANION_RUNTIME_HEARTBEAT_STOP.wait(interval_seconds):
            now = time.monotonic()
            gap_ms = int((now - previous) * 1000)
            previous = now
            if gap_ms >= stall_threshold_ms:
                companion_perf_log("runtimeStallDetected", gapMs=gap_ms)

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    return thread


def companion_perf_log_if_slow(event, elapsed_ms, threshold_ms=25, **fields):
    if elapsed_ms >= threshold_ms:
        companion_perf_log(event, elapsedMs=elapsed_ms, **fields)


def companion_dataplane_checkpoint(event, request_id, started_at, **fields):
    started_at = started_at or time.monotonic()
    active_http, active_websockets = companion_runtime_counts_unlocked()
    parts = [
        "[SOSYNC-COMPANION-DATAPLANE-TIMING]",
        f"event={event}",
        f"requestID={request_id}",
        f"correlationID={e2ee_session_correlation(request_id)}",
        f"elapsedMs={elapsed_ms_since(started_at)}",
        f"thread={threading.get_ident()}",
        f"activeHTTP={active_http}",
        f"activeWebSockets={active_websockets}",
    ]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    print(" ".join(parts), flush=True)


def websocket_age_ms(reference_at):
    if not reference_at:
        return "none"
    return elapsed_ms_since(reference_at)


def secure_remote_websocket_lifecycle(
    event,
    request_id,
    started_at,
    binding,
    session_id,
    first_terminated_direction="none",
    exception=None,
    last_inbound_client_frame_at=None,
    last_outbound_client_frame_at=None,
    last_upstream_ha_frame_at=None,
    last_heartbeat_at=None,
    **fields
):
    started_at = started_at or time.monotonic()
    active_http, active_websockets = companion_runtime_counts_unlocked()
    exception_class = type(exception).__name__ if exception else "none"
    exception_category = "none"
    if exception:
        message = str(exception)
        if isinstance(exception, ConnectionError) and "socket_closed" in message:
            exception_category = "eof"
        elif isinstance(exception, BrokenPipeError):
            exception_category = "brokenPipe"
        elif isinstance(exception, TimeoutError):
            exception_category = "timeout"
        elif isinstance(exception, OSError):
            exception_category = "socketError"
        else:
            exception_category = "handlerException"
    parts = [
        "[SOSYNC-SECURE-REMOTE-WS-LIFECYCLE]",
        f"event={event}",
        f"requestID={request_id}",
        f"correlationID={e2ee_session_correlation(request_id)}",
        f"route={safe_fingerprint(binding.get('route_id'))}",
        f"session={safe_fingerprint(session_id)}",
        f"lifetimeMs={elapsed_ms_since(started_at)}",
        f"lastInboundClientFrameAgeMs={websocket_age_ms(last_inbound_client_frame_at)}",
        f"lastOutboundClientFrameAgeMs={websocket_age_ms(last_outbound_client_frame_at)}",
        f"lastUpstreamHAFrameAgeMs={websocket_age_ms(last_upstream_ha_frame_at)}",
        f"lastHeartbeatAgeMs={websocket_age_ms(last_heartbeat_at)}",
        f"firstTerminatedDirection={first_terminated_direction}",
        f"exceptionClass={exception_class}",
        f"exceptionCategory={exception_category}",
        f"thread={threading.get_ident()}",
        f"activeHTTP={active_http}",
        f"activeWebSockets={active_websockets}",
    ]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    print(" ".join(parts), flush=True)


def set_e2ee_session_correlation(request_id, correlation_id):
    candidate = str(correlation_id or "none").strip()
    if not candidate:
        candidate = "none"
    with COMPANION_REQUEST_LOCK:
        COMPANION_E2EE_SESSION_CORRELATION[request_id] = candidate


def e2ee_session_correlation(request_id):
    with COMPANION_REQUEST_LOCK:
        return COMPANION_E2EE_SESSION_CORRELATION.get(request_id, "none")


def clear_e2ee_session_correlation(request_id):
    with COMPANION_REQUEST_LOCK:
        COMPANION_E2EE_SESSION_CORRELATION.pop(request_id, None)


def note_secure_remote_binding_stat(kind, count=1):
    now = time.monotonic()
    summary = None
    with timed_lock(SECURE_REMOTE_BINDING_STATS_LOCK, "bindingStats", log_threshold_ms=10):
        SECURE_REMOTE_BINDING_STATS[kind] = SECURE_REMOTE_BINDING_STATS.get(kind, 0) + count
        if now - SECURE_REMOTE_BINDING_STATS.get("lastSummaryAt", now) >= 30:
            SECURE_REMOTE_BINDING_STATS["lastSummaryAt"] = now
            summary = {
                "bindingChecks": SECURE_REMOTE_BINDING_STATS.get("bindingChecks", 0),
                "diskReads": SECURE_REMOTE_BINDING_STATS.get("diskReads", 0),
                "cacheHits": SECURE_REMOTE_BINDING_STATS.get("cacheHits", 0),
                "revocationPolls": SECURE_REMOTE_BINDING_STATS.get("revocationPolls", 0)
            }
            SECURE_REMOTE_BINDING_STATS["bindingChecks"] = 0
            SECURE_REMOTE_BINDING_STATS["diskReads"] = 0
            SECURE_REMOTE_BINDING_STATS["cacheHits"] = 0
            SECURE_REMOTE_BINDING_STATS["revocationPolls"] = 0
    if summary:
        companion_perf_log(
            "secureRemoteBindingSummary",
            bindingChecks=summary["bindingChecks"],
            diskReads=summary["diskReads"],
            cacheHits=summary["cacheHits"],
            revocationPolls=summary["revocationPolls"]
        )


@contextmanager
def timed_lock(lock, name, request_id="none", log_threshold_ms=5):
    wait_started_at = time.monotonic()
    lock.acquire()
    acquired_at = time.monotonic()
    wait_ms = elapsed_ms_since(wait_started_at)
    if wait_ms >= log_threshold_ms:
        companion_perf_log("lockWaitCompleted", lock=name, requestID=request_id, waitMs=wait_ms)
    try:
        yield
    finally:
        hold_ms = elapsed_ms_since(acquired_at)
        lock.release()
        if hold_ms >= log_threshold_ms:
            companion_perf_log("lockHoldCompleted", lock=name, requestID=request_id, holdMs=hold_ms)


def copy_json_value(value):
    if isinstance(value, dict):
        return {key: copy_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [copy_json_value(item) for item in value]
    return value


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        print(
            "[SOSYNC-COMPANION-LISTENER] "
            "state=connectionAccepted "
            f"clientScope={companion_client_scope(getattr(self, 'client_address', None))} "
            f"runtimeInstance={RUNTIME_INSTANCE_ID} "
            f"thread={threading.get_ident()}",
            flush=True
        )

    def parse_request(self):
        parsed = super().parse_request()
        if parsed:
            self._sosync_request_started_at = time.monotonic()
            self._sosync_request_id = companion_request_started(self.command, self.path)
            print(
                "[SOSYNC-COMPANION-LISTENER] "
                "state=requestArrived "
                f"requestID={self._sosync_request_id} "
                f"method={self.command} "
                f"pathClass={companion_path_class(self.path)} "
                f"clientScope={companion_client_scope(getattr(self, 'client_address', None))} "
                f"runtimeInstance={RUNTIME_INSTANCE_ID}",
                flush=True
            )
        return parsed

    def handle_one_request(self):
        self._sosync_request_id = None
        self._sosync_request_started_at = None
        try:
            super().handle_one_request()
        finally:
            request_id = getattr(self, "_sosync_request_id", None)
            started_at = getattr(self, "_sosync_request_started_at", None)
            if request_id is not None and started_at is not None:
                companion_request_completed(
                    request_id,
                    getattr(self, "command", "unknown"),
                    getattr(self, "path", "unknown"),
                    started_at
                )
                clear_e2ee_session_correlation(request_id)
                self._sosync_request_id = None
                self._sosync_request_started_at = None

    def _json(self, status, payload, headers=None):
        should_log_session_send = companion_path_class(getattr(self, "path", "")) == "secureRemoteEncryptedSession"
        timing_started_at = self._session_timing_started_at() if should_log_session_send else None
        serialization_started_at = time.monotonic()
        if should_log_session_send:
            self._log_e2ee_session_timing("sendJSONStarted", timing_started_at)
            self._log_e2ee_session_timing("sendJSONBodySerializationStarted", timing_started_at)
        body = json.dumps(payload).encode("utf-8")
        companion_perf_log_if_slow(
            "jsonResponseSerialized",
            elapsed_ms_since(serialization_started_at),
            requestID=self._request_id_for_log(),
            pathClass=companion_path_class(getattr(self, "path", "")),
            bytes=len(body)
        )
        if should_log_session_send:
            self._log_e2ee_session_timing("sendJSONBodySerializationCompleted", timing_started_at)
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if should_log_session_send:
                self._log_e2ee_session_timing("headersWritten", timing_started_at)
                self._log_e2ee_session_timing("bodyWriteStarted", timing_started_at)
            write_started_at = time.monotonic()
            self.wfile.write(body)
            companion_perf_log_if_slow(
                "jsonResponseWrite",
                elapsed_ms_since(write_started_at),
                requestID=self._request_id_for_log(),
                pathClass=companion_path_class(getattr(self, "path", "")),
                bytes=len(body)
            )
            if should_log_session_send:
                self._log_e2ee_session_timing("bodyWriteCompleted", timing_started_at)
                self._log_e2ee_session_timing("sendJSONCompleted", timing_started_at)
        except (BrokenPipeError, ConnectionResetError) as error:
            companion_perf_log(
                "jsonResponseWriteFailed",
                requestID=self._request_id_for_log(),
                pathClass=companion_path_class(getattr(self, "path", "")),
                error=type(error).__name__
            )
            if should_log_session_send:
                self._log_e2ee_session_timing("sendJSONFailedBrokenPipe", timing_started_at)
            print(f"Client disconnected before JSON response status={status}", flush=True)

    def _request_id_for_log(self):
        return getattr(self, "_sosync_request_id", "unknown") or "unknown"

    def _session_timing_started_at(self):
        return getattr(self, "_sosync_request_started_at", None) or time.monotonic()

    def _log_e2ee_session_timing(self, stage, started_at, lock_wait_ms=None):
        message = (
            "[SOSYNC-E2EE-SESSION-TIMING] "
            f"requestID={self._request_id_for_log()} "
            f"correlationID={e2ee_session_correlation(self._request_id_for_log())} "
            f"stage={stage} "
            f"elapsedMs={elapsed_ms_since(started_at)}"
        )
        if lock_wait_ms is not None:
            message += f" lockWaitMs={lock_wait_ms}"
        print(message, flush=True)

    def log_message(self, format, *args):
        print(f"{self.client_address[0]} - {format % args}")

    def do_GET(self):
        if self._reject_public_management_request():
            return
        parsed_request = urlparse(self.path)
        request_path = parsed_request.path

        if request_path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self._handle_secure_remote_dataplane_request(request_path):
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        if is_home_profile_path(self.path):
            self._handle_home_profile_get()
            return

        if is_home_configuration_path(self.path):
            self._handle_home_configuration_get()
            return

        if self.path == "/health":
            tunnel_runtime = cloudflared_runtime_status()
            secure_remote_status = secure_remote_public_status()
            self._json(200, {
                "status": "ok",
                "service": "sosync-companion",
                "companion_version": SOSYNC_COMPANION_VERSION,
                "build": SOSYNC_COMPANION_BUILD,
                "build_marker": SOSYNC_COMPANION_BUILD,
                "runtime_instance_id": RUNTIME_INSTANCE_ID,
                "runtime_started_at": RUNTIME_STARTED_AT,
                "cloudflared_available": tunnel_runtime["available"],
                "cloudflared_version": tunnel_runtime["version"],
                "tunnel_state": secure_remote_status["tunnel_state"],
                "cloudflared_running": secure_remote_status["cloudflared_running"]
            })
            return

        if self.path == "/identity":
            identity_started_at = time.monotonic()
            request_id = self._request_id_for_log()
            companion_identity_server_perf(
                "handlerEntered",
                request_id,
                identity_started_at,
                activeHTTP=COMPANION_ACTIVE_HTTP_REQUESTS,
                activeWebSockets=COMPANION_ACTIVE_WEBSOCKETS
            )
            companion_identity_server_perf("identityLookupStarted", request_id, identity_started_at)
            identity = ensure_companion_identity()
            companion_identity_server_perf("identityLookupCompleted", request_id, identity_started_at)
            companion_identity_server_perf("serverIdentityLookupStarted", request_id, identity_started_at)
            server_id = get_or_create_server_id()
            companion_identity_server_perf("serverIdentityLookupCompleted", request_id, identity_started_at)
            companion_identity_server_perf("remoteURLLookupStarted", request_id, identity_started_at)
            remote_url = read_remote_url()
            companion_identity_server_perf("remoteURLLookupCompleted", request_id, identity_started_at)
            companion_identity_server_perf("cloudflaredStatusStarted", request_id, identity_started_at)
            runtime = cloudflared_runtime_status()
            companion_identity_server_perf("cloudflaredStatusCompleted", request_id, identity_started_at)
            companion_identity_server_perf("secureRemoteStatusSnapshotStarted", request_id, identity_started_at)
            secure_remote_status = secure_remote_identity_snapshot_status()
            companion_identity_server_perf(
                "secureRemoteStatusSnapshotCompleted",
                request_id,
                identity_started_at,
                snapshotSource=secure_remote_status.get("snapshot_source", "unknown")
            )
            companion_perf_log(
                "handlerCheckpoint",
                requestID=request_id,
                pathClass="identity",
                stage="dependenciesLoaded",
                elapsedMs=elapsed_ms_since(identity_started_at)
            )
            companion_identity_server_perf("responseWriteStarted", request_id, identity_started_at)
            self._json(200, {
                "protocol_version": 1,
                "companion_version": SOSYNC_COMPANION_VERSION,
                "build_marker": SOSYNC_COMPANION_BUILD,
                "companion_id": identity["companion_id"],
                "companion_instance_id": identity["companion_instance_id"],
                "signing_public_key": identity["signing_public_key"],
                "encryption_public_key": identity["encryption_public_key"],
                "setup_counter": identity.get("setup_counter", 0),
                "minimum_protocol_version": 1,
                "runtime_instance_id": RUNTIME_INSTANCE_ID,
                "runtime_started_at": RUNTIME_STARTED_AT,
                "build": SOSYNC_COMPANION_BUILD,
                "server_id": server_id,
                "remote_url": remote_url,
                "tailscale_dns_name": None,
                "cloudflared_available": runtime["available"],
                "cloudflared_version": runtime["version"],
                "tunnel_state": secure_remote_status["tunnel_state"],
                "cloudflared_running": secure_remote_status["cloudflared_running"]
            })
            companion_identity_server_perf("handlerExited", request_id, identity_started_at)
            return

        if self.path == "/security/e2ee/identity":
            self._handle_e2ee_identity()
            return

        if self.path == "/security/e2ee/pairing-authorization":
            self._handle_e2ee_pairing_authorization_status()
            return

        if self.path == "/secure-remote/identity":
            self._handle_secure_remote_identity()
            return

        if self.path == "/secure-remote/status":
            self._handle_secure_remote_status()
            return

        if self.path == "/tailscale/status":
            self._json(410, {
                "ok": False,
                "error": "tailscale_retired",
                "replacement": "secure_remote_cloudflare"
            })
            return

        self._json(404, {
            "error": "not_found",
            "service": "sosync-companion",
            "route": "fallback"
        }, headers={
            "X-SoSync-Origin": "companion",
            "X-SoSync-Route": "fallback"
        })

    def do_PUT(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self._handle_secure_remote_dataplane_request(urlparse(self.path).path):
            return

        if is_home_profile_path(self.path):
            self._handle_home_profile_put()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self._json(404, {"error": "not_found"})

    def do_PATCH(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self._handle_secure_remote_dataplane_request(urlparse(self.path).path):
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self._json(404, {"error": "not_found"})

    def do_DELETE(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self._handle_secure_remote_dataplane_request(urlparse(self.path).path):
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self._json(404, {"error": "not_found"})

    def do_HEAD(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self.send_response(404)
        self.end_headers()

    def do_OPTIONS(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self.send_response(204)
        self.send_header("Allow", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        if self.path == "/tailscale/connect":
            self._json(410, {
                "ok": False,
                "error": "tailscale_retired",
                "replacement": "secure_remote_cloudflare"
            })
            return

        if self.path == "/pairing/consume":
            self._handle_pairing_consume()
            return

        if self.path == "/security/e2ee/pair":
            self._handle_e2ee_pair()
            return

        if self.path == "/security/e2ee/recover":
            self._handle_e2ee_recover()
            return

        if self.path == "/security/e2ee/revoke":
            self._handle_e2ee_revoke()
            return

        if self.path == "/secure-remote/provision":
            self._handle_secure_remote_provision()
            return

        if self.path == "/secure-remote/tunnel/install":
            self._handle_secure_remote_tunnel_install()
            return

        if self.path == "/secure-remote/tunnel/rotate":
            self._handle_secure_remote_tunnel_rotate()
            return

        if is_home_configuration_path(self.path):
            self._handle_home_configuration_create()
            return

        if is_home_configuration_mutation_path(self.path):
            self._handle_home_configuration_mutation()
            return

        if self._handle_secure_remote_dataplane_request(urlparse(self.path).path):
            return

        if self.path == "/secure-remote/revoke":
            self._handle_secure_remote_revoke()
            return

        self._json(404, {"error": "not_found"})

    def _handle_secure_remote_dataplane_request(self, request_path):
        if request_path in ("/secure-remote/data-plane/health", "/secure-remote/data-plane/health/"):
            self._handle_secure_remote_dataplane_health()
            return True

        if request_path == "/secure-remote/data-plane/e2ee/session":
            self._handle_secure_remote_dataplane_session()
            return True

        if request_path == "/secure-remote/data-plane/e2ee/rest":
            self._handle_secure_remote_dataplane_rest()
            return True

        if request_path == "/secure-remote/data-plane/e2ee/ws":
            self._handle_secure_remote_dataplane_websocket()
            return True

        if request_path.startswith("/secure-remote/data-plane/ha"):
            self._proxy_secure_remote_home_assistant()
            return True

        return False

    def _authorize_secure_remote_control_plane(self):
        if not self._is_authorized_companion_request():
            self._json(401, {"error": "unauthorized"})
            return False
        if not is_local_client(self.client_address[0]):
            self._json(403, {"error": "local_control_plane_required"})
            return False
        return True

    def _handle_secure_remote_identity(self):
        if not self._authorize_secure_remote_control_plane():
            return
        started_at = time.monotonic()
        identity = ensure_e2ee_identity()
        companion_identity = ensure_companion_identity()
        binding = read_secure_remote_binding()
        runtime = cloudflared_runtime_status()
        secure_status = secure_remote_public_status(binding)
        companion_perf_log(
            "handlerCheckpoint",
            requestID=self._request_id_for_log(),
            pathClass="secureRemoteIdentity",
            stage="dependenciesLoaded",
            elapsedMs=elapsed_ms_since(started_at)
        )
        self._json(200, {
            "protocol_version": 1,
            "companion_version": SOSYNC_COMPANION_VERSION,
            "build_marker": SOSYNC_COMPANION_BUILD,
            "runtime_instance_id": RUNTIME_INSTANCE_ID,
            "runtime_started_at": RUNTIME_STARTED_AT,
            "companion_id": companion_identity["companion_id"],
            "companion_identity_fingerprint": safe_fingerprint(companion_identity["companion_id"]),
            "companion_public_key_fingerprint": safe_fingerprint(identity["public_key"]),
            "key_version": identity["key_version"],
            "secure_remote_configured": bool(binding.get("route_id")),
            "cloudflared_available": runtime["available"],
            "cloudflared_version": runtime["version"],
            "tunnel_state": secure_status["tunnel_state"],
            "cloudflared_running": secure_status["cloudflared_running"]
        })

    def _handle_secure_remote_status(self):
        if not self._authorize_secure_remote_control_plane():
            return
        self._json(200, secure_remote_public_status())

    def _handle_home_configuration_get(self):
        if not self._authorize_secure_remote_control_plane():
            return
        parsed = urlparse(self.path)
        expected_home_identity = parse_qs(parsed.query).get("homeIdentity", [""])[0]
        if not is_valid_home_config_identity(expected_home_identity):
            log_home_config("identityMismatch", operation="load", reason="invalidExpectedIdentity")
            self._json(400, {"error": "invalid_home_identity"})
            return

        log_home_config("loadStarted", homeHash=safe_fingerprint(expected_home_identity))
        try:
            document = read_home_configuration_document()
        except HomeConfigurationPersistenceError as error:
            log_home_config("persistenceFailure", operation="load", reason=error.reason)
            self._json(500, {"error": "home_config_persistence_failure", "reason": error.reason})
            return

        if document is None:
            log_home_config("loadCompleted", result="notFound", homeHash=safe_fingerprint(expected_home_identity))
            self._json(404, {"error": "not_found"})
            return
        if document.get("homeIdentity") != expected_home_identity:
            log_home_config(
                "identityMismatch",
                operation="load",
                expectedHash=safe_fingerprint(expected_home_identity),
                actualHash=safe_fingerprint(str(document.get("homeIdentity") or ""))
            )
            self._json(403, {"error": "home_identity_mismatch"})
            return

        log_home_config(
            "loadCompleted",
            result="success",
            homeHash=safe_fingerprint(expected_home_identity),
            revision=document.get("revision", "unknown"),
            domainRevisions=home_config_domain_revision_summary(document)
        )
        self._json(200, document)

    def _handle_home_configuration_create(self):
        if not self._authorize_secure_remote_control_plane():
            return
        try:
            request = self._read_json_body(MAX_HOME_CONFIGURATION_BYTES)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return
        home_identity = str(request.get("homeIdentity") or "").strip() if isinstance(request, dict) else ""
        if not is_valid_home_config_identity(home_identity):
            log_home_config("identityMismatch", operation="create", reason="invalidHomeIdentity")
            self._json(400, {"error": "invalid_home_identity"})
            return

        log_home_config("createStarted", homeHash=safe_fingerprint(home_identity))
        try:
            document, created = create_home_configuration_if_absent(home_identity)
        except HomeConfigurationIdentityMismatchError as error:
            log_home_config(
                "identityMismatch",
                operation="create",
                expectedHash=safe_fingerprint(error.expected),
                actualHash=safe_fingerprint(error.actual)
            )
            self._json(403, {"error": "home_identity_mismatch"})
            return
        except HomeConfigurationPersistenceError as error:
            log_home_config("persistenceFailure", operation="create", reason=error.reason)
            self._json(500, {"error": "home_config_persistence_failure", "reason": error.reason})
            return

        log_home_config(
            "createCompleted",
            result="created" if created else "alreadyExists",
            homeHash=safe_fingerprint(home_identity),
            revision=document.get("revision", "unknown")
        )
        self._json(201 if created else 200, document)

    def _handle_home_configuration_mutation(self):
        if not self._authorize_secure_remote_control_plane():
            return
        try:
            request = self._read_json_body(MAX_HOME_CONFIGURATION_BYTES)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return
        if not isinstance(request, dict):
            self._json(400, {"error": "body_not_json_object"})
            return

        home_identity = str(request.get("homeIdentity") or "").strip()
        domain = str(request.get("domain") or "").strip()
        base_domain_revision = request.get("baseDomainRevision")
        updated_by_device = request.get("updatedByDeviceIDHash")
        patch = request.get("patch")
        if not is_valid_home_config_identity(home_identity):
            log_home_config("identityMismatch", operation="mutation", reason="invalidHomeIdentity")
            self._json(400, {"error": "invalid_home_identity"})
            return
        if domain not in HOME_CONFIG_DOMAINS:
            self._json(400, {"error": "invalid_domain"})
            return
        if not isinstance(base_domain_revision, int) or base_domain_revision < 0:
            self._json(400, {"error": "invalid_base_domain_revision"})
            return
        if updated_by_device is not None and not isinstance(updated_by_device, str):
            self._json(400, {"error": "invalid_updated_by_device"})
            return

        log_home_config(
            "mutationStarted",
            homeHash=safe_fingerprint(home_identity),
            domain=domain,
            baseDomainRevision=base_domain_revision
        )
        try:
            document = mutate_home_configuration(
                home_identity=home_identity,
                domain=domain,
                base_domain_revision=base_domain_revision,
                patch=patch,
                updated_by_device_hash=updated_by_device
            )
        except HomeConfigurationIdentityMismatchError as error:
            log_home_config(
                "identityMismatch",
                operation="mutation",
                expectedHash=safe_fingerprint(error.expected),
                actualHash=safe_fingerprint(error.actual)
            )
            self._json(403, {"error": "home_identity_mismatch"})
            return
        except HomeConfigurationConflictError as error:
            log_home_config(
                "conflict",
                homeHash=safe_fingerprint(home_identity),
                domain=domain,
                attemptedBaseDomainRevision=error.attempted,
                currentDomainRevision=error.current_domain_revision,
                currentRevision=error.current_revision
            )
            self._json(409, {
                "error": "revision_conflict",
                "domain": domain,
                "currentRevision": error.current_revision,
                "currentDomainRevision": error.current_domain_revision,
                "attemptedBaseDomainRevision": error.attempted
            })
            return
        except HomeConfigurationValidationError as error:
            self._json(400, {"error": error.reason})
            return
        except HomeConfigurationPersistenceError as error:
            log_home_config("persistenceFailure", operation="mutation", reason=error.reason)
            self._json(500, {"error": "home_config_persistence_failure", "reason": error.reason})
            return

        log_home_config(
            "mutationCommitted",
            homeHash=safe_fingerprint(home_identity),
            domain=domain,
            revision=document.get("revision", "unknown"),
            domainRevision=document.get("domainRevisions", {}).get(domain, "unknown")
        )
        self._json(200, document)

    def _handle_secure_remote_provision(self):
        if not self._authorize_secure_remote_control_plane():
            return
        try:
            data = self._read_json_body(64 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return
        if not is_valid_secure_remote_binding_request(data):
            self._json(400, {"error": "invalid_secure_remote_binding"})
            return
        migration_result = migrate_e2ee_pairing_home_for_secure_remote_binding_if_needed(data)
        if not migration_result.get("accepted"):
            self._json(403, {"error": "e2ee_pairing_migration_rejected"})
            return
        stop_secure_remote_tunnel()
        remove_secure_file(secure_remote_tunnel_token_file())
        binding = make_secure_remote_binding(data)
        write_json_file_secure(SECURE_REMOTE_BINDING_FILE, binding)
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] bindingPrepared route={safe_fingerprint(binding.get('route_id'))} credentialVersion={binding.get('credential_version')} staleCredentialCleared=true",
            flush=True
        )
        self._json(200, secure_remote_public_status(binding))

    def _handle_secure_remote_tunnel_install(self):
        if not self._authorize_secure_remote_control_plane():
            return
        try:
            data = self._read_json_body(128 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return
        binding = read_secure_remote_binding()
        if not binding.get("route_id"):
            self._json(409, {"error": "secure_remote_not_provisioned"})
            return
        if data.get("route_id") != binding.get("route_id"):
            self._json(403, {"error": "route_mismatch"})
            return
        credential_version = int(data.get("credential_version") or binding.get("credential_version") or 0)
        if credential_version < int(binding.get("credential_version") or 0):
            self._json(409, {"error": "stale_credential_version"})
            return
        # The connector credential is accepted only for local connector runtime use.
        # It is never returned by identity/status and never logged.
        credential_present = isinstance(data.get("tunnel_credential"), str) and bool(str(data.get("tunnel_credential")).strip())
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelConfigurationStarted route={safe_fingerprint(binding.get('route_id'))} credentialVersion={credential_version}",
            flush=True
        )
        binding["credential_version"] = credential_version
        if credential_present:
            write_secure_text_file(secure_remote_tunnel_token_file(), str(data.get("tunnel_credential")).strip())
            print(
                f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelCredentialInstalled route={safe_fingerprint(binding.get('route_id'))} credentialVersion={credential_version}",
                flush=True
            )
            start_result = start_secure_remote_tunnel(binding)
            connector_healthy = bool(start_result.get("connector_healthy"))
            process_running = bool(start_result.get("running"))
            binding["tunnel_configured"] = connector_healthy
            binding["tunnel_state"] = "active" if connector_healthy else ("connectorStarting" if process_running else "failed")
            binding["failure_stage"] = start_result.get("stage") if not connector_healthy else None
            binding["failure_reason"] = start_result.get("reason") if not connector_healthy else None
            if connector_healthy:
                binding["last_connected_at"] = binding.get("last_connected_at") or iso_now()
        else:
            binding["tunnel_configured"] = False
            binding["tunnel_state"] = "failed"
            binding["failure_stage"] = "credential"
            binding["failure_reason"] = "credentialMissing"
        binding["updated_at"] = iso_now()
        write_json_file_secure(SECURE_REMOTE_BINDING_FILE, binding)
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelInstall route={safe_fingerprint(binding.get('route_id'))} credentialVersion={credential_version} credentialPresent={credential_present}",
            flush=True
        )
        public_status = secure_remote_public_status(binding)
        process_running = bool(public_status.get("cloudflared_running") or public_status.get("cloudflared_process_alive"))
        connector_starting = process_running and public_status.get("tunnel_state") == "connectorStarting"
        http_status = 200 if binding["tunnel_configured"] or connector_starting else 503
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelInstallResponse route={safe_fingerprint(binding.get('route_id'))} httpStatus={http_status} processRunning={process_running} connectorState={public_status.get('connector_state') or 'unknown'} connectorHealthy={public_status.get('connector_healthy')} bindingGeneration={credential_version}",
            flush=True
        )
        self._json(http_status, public_status)

    def _handle_secure_remote_tunnel_rotate(self):
        if not self._authorize_secure_remote_control_plane():
            return
        try:
            data = self._read_json_body(128 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return
        binding = read_secure_remote_binding()
        if not binding.get("route_id") or data.get("route_id") != binding.get("route_id"):
            self._json(403, {"error": "route_mismatch"})
            return
        credential_version = int(data.get("credential_version") or 0)
        if credential_version <= int(binding.get("credential_version") or 0):
            self._json(409, {"error": "stale_credential_version"})
            return
        binding["credential_version"] = credential_version
        credential_present = isinstance(data.get("tunnel_credential"), str) and bool(str(data.get("tunnel_credential")).strip())
        if credential_present:
            write_secure_text_file(secure_remote_tunnel_token_file(), str(data.get("tunnel_credential")).strip())
            print(
                f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelCredentialInstalled route={safe_fingerprint(binding.get('route_id'))} credentialVersion={credential_version}",
                flush=True
            )
            start_result = start_secure_remote_tunnel(binding)
            connector_healthy = bool(start_result.get("connector_healthy"))
            binding["tunnel_configured"] = connector_healthy
            binding["tunnel_state"] = "active" if connector_healthy else ("connectorStarting" if start_result["running"] else "failed")
            binding["failure_stage"] = start_result.get("stage") if not connector_healthy else None
            binding["failure_reason"] = start_result.get("reason") if not connector_healthy else None
            if connector_healthy:
                binding["last_connected_at"] = binding.get("last_connected_at") or iso_now()
        else:
            binding["tunnel_configured"] = False
            binding["tunnel_state"] = "failed"
            binding["failure_stage"] = "credential"
            binding["failure_reason"] = "credentialMissing"
        binding["updated_at"] = iso_now()
        write_json_file_secure(SECURE_REMOTE_BINDING_FILE, binding)
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelRotate route={safe_fingerprint(binding.get('route_id'))} credentialVersion={credential_version}",
            flush=True
        )
        self._json(200 if binding["tunnel_configured"] else 503, secure_remote_public_status(binding))

    def _handle_secure_remote_revoke(self):
        if not self._authorize_secure_remote_control_plane():
            return
        try:
            data = self._read_json_body(16 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return
        binding = read_secure_remote_binding()
        print(
            f"[SOSYNC-SECURE-REMOTE-REVOCATION] stage=companionRevokeReceived routeIDHash={safe_fingerprint(data.get('route_id') or binding.get('route_id'))}",
            flush=True
        )
        if binding.get("route_id") and data.get("route_id") not in (None, binding.get("route_id")):
            print(
                f"[SOSYNC-SECURE-REMOTE-REVOCATION] stage=companionRevokeRejected reason=routeMismatch routeIDHash={safe_fingerprint(data.get('route_id'))} currentRouteIDHash={safe_fingerprint(binding.get('route_id'))}",
                flush=True
            )
            self._json(403, {"error": "route_mismatch"})
            return
        binding["status"] = "revoked"
        binding["revoked_at"] = iso_now()
        binding["tunnel_state"] = "revoked"
        write_json_file_secure(SECURE_REMOTE_BINDING_FILE, binding)
        stop_secure_remote_tunnel()
        print(
            f"[SOSYNC-SECURE-REMOTE-REVOCATION] stage=companionBindingRevoked routeIDHash={safe_fingerprint(binding.get('route_id'))} tunnelState=revoked failClosed=true",
            flush=True
        )
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] revoked route={safe_fingerprint(binding.get('route_id'))}",
            flush=True
        )
        self._json(200, secure_remote_public_status(binding))

    def _authorize_secure_remote_dataplane(self, timing_started_at=None):
        request_id = self._request_id_for_log()
        if timing_started_at is not None:
            companion_dataplane_checkpoint("bindingReadStart", request_id, timing_started_at)
        binding = read_secure_remote_binding()
        if timing_started_at is not None:
            companion_dataplane_checkpoint("bindingReadComplete", request_id, timing_started_at)
            companion_dataplane_checkpoint("authOriginValidationStart", request_id, timing_started_at)
        if not binding.get("route_id") or binding.get("status") == "revoked":
            print(
                f"[SOSYNC-SECURE-REMOTE-REVOCATION] stage=companionDataPlaneRejected reason={'deviceRevoked' if binding.get('status') == 'revoked' else 'notBound'} routeIDHash={safe_fingerprint(binding.get('route_id'))} httpStatus=403 failClosed=true",
                flush=True
            )
            print(
                "[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionOriginValidation routeValidationPassed=false originTokenValidationPassed=false reason=notBound",
                flush=True
            )
            self._json(403, {"error": "secure_remote_not_bound"})
            return None
        route = self.headers.get("X-SoSync-Secure-Remote-Route")
        token = self.headers.get("X-SoSync-Secure-Remote-Origin-Token")
        stored_token = str(binding.get("origin_access_token") or "").strip()
        route_ok = hmac.compare_digest(str(route or ""), str(binding.get("tunnel_binding_id") or ""))
        token_ok = bool(stored_token) and hmac.compare_digest(str(token or ""), stored_token)
        print(
            f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionOriginValidation route={safe_fingerprint(binding.get('route_id'))} tunnelBinding={safe_fingerprint(binding.get('tunnel_binding_id'))} routeValidationPassed={route_ok} originTokenValidationPassed={token_ok}",
            flush=True
        )
        if timing_started_at is not None:
            companion_dataplane_checkpoint("authOriginValidationComplete", request_id, timing_started_at, routeOK=str(route_ok).lower(), tokenOK=str(token_ok).lower())
        if not route_ok or not token_ok:
            self._json(401, {"error": "unauthorized"}, headers={
                "X-SoSync-Origin": "companion",
                "X-SoSync-Route": "auth"
            })
            return None
        return binding

    def _handle_secure_remote_dataplane_session(self):
        timing_started_at = self._session_timing_started_at()
        request_id = self._request_id_for_log()
        correlation_header = self.headers.get("X-SoSync-E2EE-Session-Correlation")
        set_e2ee_session_correlation(request_id, correlation_header)
        companion_dataplane_checkpoint(
            "sessionCorrelationReceived",
            request_id,
            timing_started_at,
            headerPresent=str(bool(correlation_header)).lower()
        )
        companion_dataplane_checkpoint("requestEntered", request_id, timing_started_at)
        companion_dataplane_checkpoint("dependenciesLoadStart", request_id, timing_started_at)
        companion_dataplane_checkpoint("dependenciesLoadComplete", request_id, timing_started_at)
        binding = self._authorize_secure_remote_dataplane(timing_started_at=timing_started_at)
        if not binding:
            return
        self._log_e2ee_session_timing("afterOriginValidation", timing_started_at)
        try:
            companion_dataplane_checkpoint("requestBodyReadStart", request_id, timing_started_at)
            data = self._read_json_body(16 * 1024)
            companion_dataplane_checkpoint("requestBodyReadComplete", request_id, timing_started_at)
            self._log_e2ee_session_timing("bodyParseCompleted", timing_started_at)
            session = create_secure_remote_dataplane_session(
                binding,
                data,
                request_id=self._request_id_for_log(),
                timing_started_at=timing_started_at
            )
            print(
                f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionEncryptedSessionReady route={safe_fingerprint(binding.get('route_id'))} session={safe_fingerprint(session['session_id'])} encryptedDataPlane=true companionDecryption=true replayProtection=true maxRevocationEnforcementSeconds=60",
                flush=True
            )
            self._log_e2ee_session_timing("responseSerializationStarted", timing_started_at)
            response_payload = {
                "protocol_version": 1,
                "route_id": binding.get("route_id"),
                "session_id": session["session_id"],
                "companion_ephemeral_public_key": session["companion_ephemeral_public_key"],
                "expires_in_seconds": session["expires_in_seconds"]
            }
            self._log_e2ee_session_timing("responseSerializationCompleted", timing_started_at)
            self._log_e2ee_session_timing("beforeSendJSON", timing_started_at)
            self._json(200, response_payload)
            self._log_e2ee_session_timing("afterSendJSON", timing_started_at)
        except ValueError as error:
            self._log_e2ee_session_timing("beforeErrorSendJSON", timing_started_at)
            self._json(400, {"error": str(error)})
            self._log_e2ee_session_timing("afterErrorSendJSON", timing_started_at)
        except Exception as error:
            print(f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionEncryptedSessionRejected reason={type(error).__name__}", flush=True)
            self._log_e2ee_session_timing("beforeErrorSendJSON", timing_started_at)
            self._json(403, {"error": "encrypted_session_rejected"})
            self._log_e2ee_session_timing("afterErrorSendJSON", timing_started_at)

    def _handle_secure_remote_dataplane_rest(self):
        binding = self._authorize_secure_remote_dataplane()
        if not binding:
            return
        try:
            envelope = self._read_json_body(256 * 1024)
            plain = decrypt_secure_remote_dataplane_envelope(binding, envelope, "client_to_companion")
            request = json.loads(plain.decode("utf-8"))
            ha_path = str(request.get("path") or "/")
            method = str(request.get("method") or "GET").upper()
            if not is_allowed_ha_path(ha_path) and not (ha_path == "/auth/token" and method == "POST"):
                self._json(403, {"error": "route_not_allowed"})
                return
            response = perform_secure_remote_dataplane_rest(method, ha_path, request.get("headers") or {}, request.get("body_base64url"))
            response_plain = json.dumps(response, separators=(",", ":")).encode("utf-8")
            response_envelope = encrypt_secure_remote_dataplane_envelope(binding, envelope.get("session_id"), response_plain, "companion_to_client", f"rest-response-{uuid.uuid4()}")
            print(
                f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionEncryptedRESTComplete route={safe_fingerprint(binding.get('route_id'))} pathClass={ha_path_class_for_log(ha_path)} upstreamStatus={response.get('status')} companionDecryption=true plaintextHATokenAtWorker=false",
                flush=True
            )
            self._json(200, response_envelope)
        except Exception as error:
            print(f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionEncryptedRESTRejected reason={type(error).__name__}", flush=True)
            self._json(403, {"error": "encrypted_dataplane_rejected"})

    def _handle_secure_remote_dataplane_websocket(self):
        timing_started_at = self._session_timing_started_at()
        request_id = self._request_id_for_log()
        set_e2ee_session_correlation(request_id, self.headers.get("x-sosync-e2ee-session-correlation"))
        companion_dataplane_checkpoint("encryptedWebSocketRequestEntered", request_id, timing_started_at)
        binding = self._authorize_secure_remote_dataplane(timing_started_at=timing_started_at)
        if not binding:
            return
        if not is_websocket_upgrade(self.headers):
            self._json(400, {"error": "websocket_upgrade_required"})
            return
        session_id = parse_qs(urlparse(self.path).query).get("session_id", [""])[0]
        companion_dataplane_checkpoint("encryptedWebSocketSessionLookupStart", request_id, timing_started_at, session=safe_fingerprint(session_id))
        if not secure_remote_dataplane_session(binding, session_id):
            self._json(403, {"error": "encrypted_session_required"})
            return
        companion_dataplane_checkpoint("encryptedWebSocketSessionLookupComplete", request_id, timing_started_at, session=safe_fingerprint(session_id))
        upstream = urlparse(read_ha_upstream())
        upstream_host = upstream.hostname or "127.0.0.1"
        upstream_port = upstream.port or 8123
        try:
            companion_dataplane_checkpoint("upstreamHAWebSocketConnectStart", request_id, timing_started_at, session=safe_fingerprint(session_id), host=upstream_host, port=upstream_port)
            with socket.create_connection((upstream_host, upstream_port), timeout=10) as upstream_socket:
                companion_dataplane_checkpoint("upstreamHAWebSocketConnected", request_id, timing_started_at, session=safe_fingerprint(session_id))
                upstream_socket.settimeout(None)
                self.connection.settimeout(None)
                companion_dataplane_checkpoint("upstreamHAWebSocketUpgradeRequestWriteStart", request_id, timing_started_at, session=safe_fingerprint(session_id))
                upstream_socket.sendall(self._websocket_upgrade_request("/api/websocket", upstream_host, upstream_port))
                companion_dataplane_checkpoint("upstreamHAWebSocketUpgradeRequestWriteComplete", request_id, timing_started_at, session=safe_fingerprint(session_id))
                response = read_http_headers(upstream_socket)
                if not response or not response.startswith((b"HTTP/1.1 101", b"HTTP/1.0 101")):
                    self._json(502, {"error": "websocket_upstream_rejected"})
                    return
                companion_dataplane_checkpoint("webSocketUpgradeCompleted", request_id, timing_started_at, session=safe_fingerprint(session_id))
                self.connection.sendall(response)
                print(
                    f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionEncryptedWebSocketConnected route={safe_fingerprint(binding.get('route_id'))} encryptedDataPlane=true companionDecryption=true",
                    flush=True
                )
                websocket_started_at = time.monotonic()
                companion_websocket_started(binding.get("route_id"), session_id)
                try:
                    bridge_secure_remote_dataplane_websocket(self.connection, upstream_socket, binding, session_id, request_id=request_id, timing_started_at=timing_started_at)
                finally:
                    companion_websocket_completed(binding.get("route_id"), session_id, websocket_started_at)
        except Exception as error:
            print(
                f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionEncryptedWebSocketClosed "
                f"reason={type(error).__name__} requestID={request_id} "
                f"correlationID={e2ee_session_correlation(request_id)}",
                flush=True
            )
            try:
                self._json(502, {"error": "encrypted_websocket_failed"})
            except Exception:
                pass

    def _handle_secure_remote_dataplane_health(self):
        request_path = urlparse(self.path).path
        print(
            f"[SOSYNC-SECURE-REMOTE-DATAPLANE] method={self.command} pathname={request_path} handlerReached=true",
            flush=True
        )
        binding = read_secure_remote_binding()
        if not binding.get("route_id") or binding.get("status") == "revoked":
            print(
                f"[SOSYNC-SECURE-REMOTE-REVOCATION] stage=companionHealthRejected reason={'deviceRevoked' if binding.get('status') == 'revoked' else 'notBound'} routeIDHash={safe_fingerprint(binding.get('route_id'))} httpStatus=403 failClosed=true",
                flush=True
            )
            self._json(403, {
                "protocol_version": 1,
                "status": "unbound",
                "service": "sosync-companion-secure-remote",
                "tunnel_state": "unconfigured",
                "route_id_fingerprint": safe_fingerprint(binding.get("route_id")),
                "tunnel_binding_fingerprint": safe_fingerprint(binding.get("tunnel_binding_id"))
            }, headers={
                "X-SoSync-Origin": "companion",
                "X-SoSync-Route": "health"
            })
            return
        process_running = is_secure_remote_tunnel_running()
        connector_status = secure_remote_connector_runtime_status(process_running)
        print(
            f"[SOSYNC-SECURE-REMOTE-DATAPLANE] health method={self.command} path={request_path} route={safe_fingerprint(binding.get('route_id'))} tunnelBinding={safe_fingerprint(binding.get('tunnel_binding_id'))} tunnelState={binding.get('tunnel_state') or 'unconfigured'} cloudflaredRunning={process_running} connectorState={connector_status['connector_state']} connectorHealthy={connector_status['connector_healthy']} connectorConnectionCount={connector_status['connector_connection_count']} lastErrorClass={connector_status['last_error_class']}",
            flush=True
        )
        if connector_status["connector_healthy"]:
            binding["tunnel_state"] = "active"
            binding["last_healthy_at"] = iso_now()
            binding["last_connected_at"] = binding.get("last_connected_at") or iso_now()
            binding["updated_at"] = iso_now()
            write_json_file_secure(SECURE_REMOTE_BINDING_FILE, binding)
        self._json(200 if connector_status["connector_healthy"] else 503, {
            "protocol_version": 1,
            "status": "ok" if connector_status["connector_healthy"] else "unavailable",
            "service": "sosync-companion-secure-remote",
            "tunnel_state": "active" if connector_status["connector_healthy"] else ("connectorStarting" if process_running else "unconfigured"),
            "cloudflared_process_alive": process_running,
            "connector_state": connector_status["connector_state"],
            "connector_healthy": connector_status["connector_healthy"],
            "connector_connection_count": connector_status["connector_connection_count"],
            "last_error_class": connector_status["last_error_class"],
            "route_id_fingerprint": safe_fingerprint(binding.get("route_id")),
            "tunnel_binding_fingerprint": safe_fingerprint(binding.get("tunnel_binding_id"))
        }, headers={
            "X-SoSync-Origin": "companion",
            "X-SoSync-Route": "health"
        })

    def _proxy_secure_remote_home_assistant(self):
        parsed_remote_path = urlparse(self.path)
        ha_path = parsed_remote_path.path[len("/secure-remote/data-plane/ha"):] or "/"
        print(
            f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionHAHandlerReached method={self.command} pathClass={ha_path_class_for_log(ha_path)} websocketUpgradeAttempted={is_websocket_upgrade(self.headers)}",
            flush=True
        )
        binding = self._authorize_secure_remote_dataplane()
        if not binding:
            return
        is_oauth_token_refresh = ha_path == "/auth/token" and self.command == "POST"
        allowed_ha_path = is_allowed_ha_path(ha_path)
        allowed = allowed_ha_path or is_oauth_token_refresh
        print(
            f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionHAPathPolicy method={self.command} pathClass={ha_path_class_for_log(ha_path)} isAllowedHAPath={allowed_ha_path} haAuthEndpointReached={is_oauth_token_refresh} allowed={allowed}",
            flush=True
        )
        if not allowed:
            self._json(403, {"error": "route_not_allowed"})
            return
        print(
            f"[SOSYNC-SECURE-REMOTE-DATAPLANE] companionProxy method={self.command} upstreamPath={sanitize_ha_path_for_log(ha_path)}",
            flush=True
        )
        self._proxy_home_assistant_path(ha_path, parsed_remote_path.query)

    def _handle_e2ee_identity(self):
        identity = ensure_e2ee_identity()
        self._json(200, {
            "protocol_version": E2EE_PROTOCOL_VERSION,
            "companion_public_key": identity["public_key"],
            "key_version": identity["key_version"]
        })

    def _handle_e2ee_pairing_authorization_status(self):
        self._json(200, e2ee_pairing_authorization_status())

    def _handle_e2ee_pair(self):
        header_contract, _ = local_pairing_token_contract(self.headers)
        if not has_local_e2ee_pairing_authorization(self.headers):
            log_e2ee_pairing_rejection(
                "e2eePair",
                header_contract,
                "unknown",
                "local_pairing_authorization_required",
                token_authorized=False
            )
            self._json(401, {"error": "local_pairing_authorization_required"})
            return

        try:
            data = self._read_json_body(16 * 1024)
        except ValueError as error:
            log_e2ee_pairing_rejection(
                "e2eePair",
                header_contract,
                "unknown",
                "json_decode_failure",
                token_authorized=True
            )
            self._json(400, {"error": str(error)})
            return

        if not isinstance(data, dict):
            log_e2ee_pairing_rejection(
                "e2eePair",
                header_contract,
                safe_pairing_payload_schema_version(data),
                "body_not_json_object",
                invalid_fields=["body"],
                token_authorized=True
            )
            self._json(400, {"error": "invalid_pairing_request"})
            return

        protocol_version = data.get("protocol_version")
        if not isinstance(protocol_version, int):
            missing = ["protocol_version"] if protocol_version is None else []
            invalid = [] if protocol_version is None else ["protocol_version"]
            log_e2ee_pairing_rejection(
                "e2eePair",
                header_contract,
                safe_pairing_payload_schema_version(data),
                "missing_protocol_version" if missing else "invalid_protocol_version",
                missing_fields=missing,
                invalid_fields=invalid,
                token_authorized=True
            )
            self._json(400, {"error": "invalid_pairing_request"})
            return

        if protocol_version != E2EE_PROTOCOL_VERSION:
            log_e2ee_pairing_rejection(
                "e2eePair",
                header_contract,
                safe_pairing_payload_schema_version(data),
                "unsupported_protocol_version",
                invalid_fields=["protocol_version"],
                token_authorized=True
            )
            self._json(426, {"error": "unsupported_protocol_version"})
            return

        home_id, device_id, device_public_key, missing_fields, invalid_fields, decoded_public_key_bytes = validate_e2ee_pairing_request(data)
        if missing_fields or invalid_fields:
            rejection_class = "missing_required_field" if missing_fields else "invalid_field"
            syntactically_valid_home_id = "false" if "home_id" in missing_fields or "home_id" in invalid_fields else "true"
            log_e2ee_pairing_rejection(
                "e2eePair",
                header_contract,
                safe_pairing_payload_schema_version(data),
                rejection_class,
                missing_fields=missing_fields,
                invalid_fields=invalid_fields,
                decoded_public_key_bytes=decoded_public_key_bytes,
                token_authorized=True,
                syntactically_valid_home_id=syntactically_valid_home_id
            )
            self._json(400, {"error": "invalid_pairing_request"})
            return

        identity = ensure_e2ee_identity()
        pairings = read_e2ee_pairings()
        existing = pairings.get("devices", {}).get(device_id)
        if isinstance(existing, dict) and existing.get("status") != "revoked":
            home_binding_matches = existing.get("home_id") == home_id
            if not home_binding_matches:
                log_e2ee_pairing_rejection(
                    "e2eePair",
                    header_contract,
                    safe_pairing_payload_schema_version(data),
                    "home_binding_mismatch",
                    decoded_public_key_bytes=decoded_public_key_bytes,
                    token_authorized=True,
                    syntactically_valid_home_id="true",
                    home_binding_matches="false"
                )
                self._json(409, {"error": "invalid_pairing_request"})
                return
        if existing and existing.get("status") == "revoked":
            log_e2ee_pairing_rejection(
                "e2eePair",
                header_contract,
                safe_pairing_payload_schema_version(data),
                "device_revoked",
                decoded_public_key_bytes=decoded_public_key_bytes,
                token_authorized=True,
                syntactically_valid_home_id="true",
                home_binding_matches=str(existing.get("home_id") == home_id).lower() if isinstance(existing, dict) else "unknown"
            )
            self._json(403, {"error": "device_revoked"})
            return

        log_e2ee_pairing_acceptance(
            safe_pairing_payload_schema_version(data),
            decoded_public_key_bytes,
            "true" if isinstance(existing, dict) else "notApplicable"
        )

        record = make_e2ee_pairing_record(
            home_id=home_id,
            device_id=device_id,
            device_public_key=device_public_key,
            companion_public_key=identity["public_key"],
            key_version=identity["key_version"]
        )
        pairings.setdefault("devices", {})[device_id] = record
        write_json_file_secure(E2EE_PAIRINGS_FILE, pairings)
        clear_e2ee_pairing_authorization()
        print(f"[SOSYNC-E2EE] pairingCompleted deviceID={device_id[:8]}", flush=True)
        print("[SOSYNC-E2EE] pairingPersisted local=false companion=true", flush=True)
        self._json(200, {
            "protocol_version": E2EE_PROTOCOL_VERSION,
            "home_id": record["home_id"],
            "device_id": record["device_id"],
            "companion_public_key": record["companion_public_key"],
            "key_version": record["key_version"],
            "status": record["status"]
        })

    def _handle_e2ee_recover(self):
        try:
            data = self._read_json_body(16 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return

        if data.get("protocol_version") != E2EE_PROTOCOL_VERSION:
            self._json(426, {"error": "unsupported_protocol_version"})
            return

        device_id = opaque_e2ee_identifier(data.get("device_id"))
        device_public_key = normalized_e2ee_public_key(data.get("device_public_key"))
        client_nonce = str(data.get("client_nonce") or "").strip()
        device_proof = str(data.get("device_proof") or "").strip()
        if not device_id or not device_public_key or not client_nonce or not device_proof:
            self._json(400, {"error": "invalid_recovery_request"})
            return

        pairings = read_e2ee_pairings()
        record = pairings.get("devices", {}).get(device_id)
        recognized = bool(
            isinstance(record, dict) and
            record.get("status") == "active" and
            record.get("device_public_key") == device_public_key
        )
        print(
            f"[SOSYNC-E2EE-RECOVERY] companionPairingLookup recognized={recognized} "
            f"deviceID={device_id[:8] if device_id else 'none'}",
            flush=True
        )
        if not recognized:
            self._json(200, {
                "protocol_version": E2EE_PROTOCOL_VERSION,
                "recognized": False,
                "reason": "pairing_not_found"
            })
            return

        identity = ensure_e2ee_identity()
        key = e2ee_recovery_shared_key(identity["private_key"], device_public_key)
        expected_device_proof = e2ee_recovery_proof(
            key,
            "device",
            device_id,
            device_public_key,
            identity["public_key"],
            client_nonce
        )
        device_verified = hmac.compare_digest(device_proof, expected_device_proof)
        print(f"[SOSYNC-E2EE-RECOVERY] deviceProof verified={device_verified}", flush=True)
        if not device_verified:
            self._json(401, {"error": "device_proof_rejected"})
            return

        companion_nonce = base64url_encode(os.urandom(32))
        companion_proof = e2ee_recovery_proof(
            key,
            "companion",
            device_id,
            device_public_key,
            identity["public_key"],
            client_nonce,
            companion_nonce,
            str(record.get("home_id") or ""),
            str(record.get("key_version") or identity["key_version"])
        )
        self._json(200, {
            "protocol_version": E2EE_PROTOCOL_VERSION,
            "recognized": True,
            "device_id": device_id,
            "home_id": record["home_id"],
            "device_public_key": device_public_key,
            "companion_public_key": identity["public_key"],
            "key_version": record.get("key_version") or identity["key_version"],
            "status": record["status"],
            "companion_nonce": companion_nonce,
            "companion_proof": companion_proof
        })

    def _handle_e2ee_revoke(self):
        if not has_local_e2ee_pairing_authorization(self.headers):
            self._json(401, {"error": "local_pairing_authorization_required"})
            return

        try:
            data = self._read_json_body(8 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return

        device_id = opaque_e2ee_identifier(data.get("device_id"))
        pairings = read_e2ee_pairings()
        existing = pairings.get("devices", {}).get(device_id) if device_id else None
        if not existing:
            self._json(404, {"error": "pairing_not_found"})
            return

        existing = dict(existing)
        existing["status"] = "revoked"
        existing["revoked_at"] = iso_now()
        pairings.setdefault("devices", {})[device_id] = existing
        write_json_file_secure(E2EE_PAIRINGS_FILE, pairings)
        self._json(200, {
            "protocol_version": E2EE_PROTOCOL_VERSION,
            "device_id": device_id,
            "status": "revoked"
        })

    def _handle_pairing_consume(self):
        try:
            data = self._read_json_body(16 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return

        ingest_remote_pairing_from_supervisor_config()
        pairings = read_json_file(PAIRINGS_FILE, {})
        pairing_id = str(data.get("pairing_id") or "")
        pairing = pairings.get(pairing_id)
        identity = ensure_companion_identity()

        if not pairing or pairing.get("status") != "pending":
            self._json(404, {"error": "pairing_not_found"})
            return

        if is_expired_iso(pairing.get("expires_at")):
            pairing["status"] = "expired"
            write_json_file_secure(PAIRINGS_FILE, pairings)
            self._json(401, {"error": "pairing_expired"})
            return

        if pairing.get("backend_challenge_id") != data.get("backend_challenge_id"):
            self._json(401, {"error": "pairing_challenge_mismatch"})
            return

        if pairing.get("app_attest_key_id") != data.get("app_attest_key_id"):
            self._json(401, {"error": "pairing_app_attest_key_mismatch"})
            return

        if pairing.get("companion_id") != identity.get("companion_id"):
            self._json(401, {"error": "pairing_companion_mismatch"})
            return

        now = iso_now()
        pairing["status"] = "consumed"
        pairing["consumed_at"] = now
        write_json_file_secure(PAIRINGS_FILE, pairings)

        receipt = {
            "protocol_version": 1,
            "pairing_id": pairing["pairing_id"],
            "backend_challenge_id": pairing["backend_challenge_id"],
            "companion_id": identity["companion_id"],
            "companion_instance_id": identity["companion_instance_id"],
            "setup_counter": identity.get("setup_counter", 0),
            "issued_at": now,
            "expires_at": iso_from_now(PAIRING_TTL_SECONDS),
            "pairing_secret_hash": pairing["pairing_secret_hash"],
            "app_attest_key_id": pairing["app_attest_key_id"],
            "backend_nonce_hash": pairing["backend_nonce_hash"],
            "signature": ""
        }
        receipt["signature"] = sign_ed25519_base64url(
            identity["signing_private_key"],
            canonical_bytes(receipt_canonical_payload(receipt))
        )
        self._json(200, receipt)

    def _reject_public_management_request(self):
        if self.path.startswith(REMOTE_PREFIX):
            return False
        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            return False
        if is_home_profile_path(self.path):
            return False

        return False

    def _handle_home_profile_get(self):
        if not self._is_authorized_companion_request():
            self._json(401, {"error": "unauthorized"})
            return

        profile = read_home_profile()
        if not profile:
            self._json(404, {"error": "profile_not_found"})
            return

        self._json(200, profile)

    def _handle_home_profile_put(self):
        if not self._is_authorized_companion_request():
            self._json(401, {"error": "unauthorized"})
            return

        try:
            profile = self._read_json_body(MAX_HOME_PROFILE_BYTES)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return

        if not is_valid_home_profile(profile):
            self._json(400, {"error": "invalid_home_profile"})
            return

        store_home_profile(profile)
        self._json(200, {
            "ok": True,
            "updated_at": profile.get("updatedAt")
        })

    def _proxy_home_assistant(self):
        print("[SOSYNC-SECURE-REMOTE-DATAPLANE] event=legacyRemoteProxyRejected legacyRemoteDataPlaneEnabled=false", flush=True)
        self._json(410, {"error": "legacy_remote_disabled"})
        return
        stored_token = read_remote_token()
        request_token = self.headers.get(REMOTE_TOKEN_HEADER)
        if not stored_token or not request_token or request_token != stored_token:
            self._json(401, {"error": "unauthorized"})
            return

        parsed_remote_path = urlparse(self.path)
        ha_path = parsed_remote_path.path[len(REMOTE_PREFIX):] or "/"

        is_oauth_token_refresh = (
            ha_path == "/auth/token"
            and self.command == "POST"
        )

        if not is_allowed_ha_path(ha_path) and not is_oauth_token_refresh:
            self._json(403, {"error": "route_not_allowed"})
            return

        self._proxy_home_assistant_path(ha_path, parsed_remote_path.query)

    def _proxy_signed_home_assistant(self):
        print("[SOSYNC-SECURE-REMOTE-DATAPLANE] event=legacySignedRemoteProxyRejected legacyRemoteDataPlaneEnabled=false", flush=True)
        self._json(410, {"error": "legacy_remote_disabled"})
        return
        parsed_remote_path = urlparse(self.path)
        signed_route = validate_signed_remote_route(parsed_remote_path.path)
        if not signed_route.get("ok"):
            print(f"[REMOTE-HTTP] signedRouteRejected reason={signed_route.get('error')}", flush=True)
            self._json(signed_route.get("status", 401), {"error": signed_route.get("error", "unauthorized")})
            return

        ha_path = signed_route["ha_path"]
        if not is_allowed_ha_path(ha_path):
            self._json(403, {"error": "forbidden"})
            return

        if is_websocket_upgrade(self.headers):
            print(f"[REMOTE-WS] upgradePath={sanitize_signed_path(parsed_remote_path.path)}", flush=True)
            print("[REMOTE-WS] signatureValid=true", flush=True)
            print(f"[REMOTE-WS] upstreamPath={ha_path}", flush=True)
        else:
            print(f"[REMOTE-HTTP] signedRouteAccepted upstreamPath={ha_path}", flush=True)

        self._proxy_home_assistant_path(ha_path, parsed_remote_path.query)

    def _proxy_home_assistant_path(self, ha_path, query):
        if is_websocket_upgrade(self.headers):
            print(
                f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionWebSocketUpgradeAttempted method={self.command} pathClass={ha_path_class_for_log(ha_path)}",
                flush=True
            )
            self._proxy_home_assistant_websocket(ha_path, query)
            return

        target_url = f"{read_ha_upstream()}{ha_path}"
        if query:
            target_url = f"{target_url}?{query}"
        body = None
        if self.command in ("POST", "PUT", "PATCH", "DELETE"):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else None

        headers = {}
        for header in ("Authorization", "Content-Type", "Accept", "User-Agent"):
            value = self.headers.get(header)
            if value:
                headers[header] = value

        print(
            f"[REMOTE-HTTP] method={self.command} route=ha upstreamPath={sanitize_ha_path_for_log(ha_path)}",
            flush=True
        )
        print(
            f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionUpstreamHARequestStarted method={self.command} pathClass={ha_path_class_for_log(ha_path)} haAuthEndpointReached={ha_path == '/auth/token'}",
            flush=True
        )

        request = urllib.request.Request(
            target_url,
            data=body,
            headers=headers,
            method=self.command
        )

        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                response_body = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(response_body)
                print(
                    f"[REMOTE-HTTP] method={self.command} upstreamStatus={response.status} upstreamPath={sanitize_ha_path_for_log(ha_path)}",
                    flush=True
                )
                print(
                    f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionUpstreamHAResponse method={self.command} pathClass={ha_path_class_for_log(ha_path)} upstreamResponseStatus={response.status}",
                    flush=True
                )
        except urllib.error.HTTPError as error:
            response_body = error.read()
            self.send_response(error.code)
            self.send_header("Content-Type", error.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response_body)
            print(
                f"[REMOTE-HTTP] method={self.command} upstreamStatus={error.code} upstreamPath={sanitize_ha_path_for_log(ha_path)}",
                flush=True
            )
            print(
                f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionUpstreamHAResponse method={self.command} pathClass={ha_path_class_for_log(ha_path)} upstreamResponseStatus={error.code}",
                flush=True
            )
        except BrokenPipeError:
            print(f"Client disconnected while proxying {ha_path}", flush=True)
        except Exception as error:
            try:
                self._json(502, {"error": str(error)})
            except BrokenPipeError:
                print(f"Client disconnected before proxy error response {ha_path}: {error}", flush=True)

    def _proxy_home_assistant_websocket(self, ha_path, query):
        upstream = urlparse(read_ha_upstream())
        upstream_host = upstream.hostname or "127.0.0.1"
        upstream_port = upstream.port or 8123
        upstream_path = ha_path
        if query:
            upstream_path = f"{upstream_path}?{query}"

        try:
            print(f"[REMOTE-WS] proxy upstreamPath={ha_path}", flush=True)
            print(
                f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionWebSocketUpstreamStarted pathClass={ha_path_class_for_log(ha_path)}",
                flush=True
            )
            with socket.create_connection((upstream_host, upstream_port), timeout=10) as upstream_socket:
                upstream_socket.settimeout(None)
                self.connection.settimeout(None)
                upstream_socket.sendall(self._websocket_upgrade_request(upstream_path, upstream_host, upstream_port))

                response = read_http_headers(upstream_socket)
                if not response:
                    print("WebSocket upstream returned no response", flush=True)
                    self._json(502, {"error": "websocket_upstream_no_response"})
                    return

                status_line = response.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                print(f"WebSocket upstream response: {status_line}", flush=True)
                self.connection.sendall(response)
                if not response.startswith(b"HTTP/1.1 101") and not response.startswith(b"HTTP/1.0 101"):
                    return

                print("[REMOTE-WS] upgradeAccepted", flush=True)
                print(
                    f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionWebSocketUpstreamConnected pathClass={ha_path_class_for_log(ha_path)} websocketUpgradeAccepted=true",
                    flush=True
                )
                tunnel_sockets(self.connection, upstream_socket)
                print("WebSocket proxy closed", flush=True)
        except Exception as error:
            print(f"WebSocket proxy error: {error}", flush=True)
            try:
                self._json(502, {"error": str(error)})
            except Exception:
                pass

    def _websocket_upgrade_request(self, upstream_path, upstream_host, upstream_port):
        headers = [
            f"GET {upstream_path} HTTP/1.1",
            f"Host: {upstream_host}:{upstream_port}",
            "Connection: Upgrade",
            "Upgrade: websocket",
        ]

        forwarded_headers = (
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Protocol",
            "Sec-WebSocket-Extensions",
            "Origin"
        )
        for header in forwarded_headers:
            value = self.headers.get(header)
            if value:
                headers.append(f"{header}: {value}")

        missing_headers = [
            header
            for header in ("Sec-WebSocket-Key", "Sec-WebSocket-Version")
            if not self.headers.get(header)
        ]
        if missing_headers:
            print(f"WebSocket upgrade missing headers={missing_headers}", flush=True)

        headers.extend([
            "",
            ""
        ])
        return "\r\n".join(headers).encode("utf-8")

    def _read_json_body(self, max_bytes):
        length = int(self.headers.get("Content-Length", "0"))
        if length > max_bytes:
            raise ValueError("payload_too_large")

        read_started_at = time.monotonic()
        body = self.rfile.read(length) if length > 0 else b"{}"
        companion_perf_log_if_slow(
            "requestBodyRead",
            elapsed_ms_since(read_started_at),
            requestID=self._request_id_for_log(),
            pathClass=companion_path_class(getattr(self, "path", "")),
            bytes=len(body)
        )
        parse_started_at = time.monotonic()
        try:
            value = json.loads(body.decode("utf-8") or "{}")
            companion_perf_log_if_slow(
                "requestJSONParsed",
                elapsed_ms_since(parse_started_at),
                requestID=self._request_id_for_log(),
                pathClass=companion_path_class(getattr(self, "path", "")),
                bytes=len(body)
            )
            return value
        except json.JSONDecodeError:
            raise ValueError("invalid_json")

    def _is_authorized_companion_request(self):
        stored_token = read_remote_token()
        if not stored_token:
            return True

        request_token = self.headers.get(REMOTE_TOKEN_HEADER)
        if request_token == stored_token:
            return True

        return is_local_client(self.client_address[0])


def log_e2ee_session_timing(request_id, timing_started_at, stage, lock_wait_ms=None):
    if timing_started_at is None:
        return
    active_http, active_websockets = companion_runtime_counts_unlocked()
    message = (
        "[SOSYNC-E2EE-SESSION-TIMING] "
        f"requestID={request_id} "
        f"correlationID={e2ee_session_correlation(request_id)} "
        f"stage={stage} "
        f"thread={threading.get_ident()} "
        f"activeHTTP={active_http} "
        f"activeWebSockets={active_websockets} "
        f"elapsedMs={elapsed_ms_since(timing_started_at)}"
    )
    if lock_wait_ms is not None:
        message += f" lockWaitMs={lock_wait_ms}"
    print(message, flush=True)


def create_secure_remote_dataplane_session(binding, request, request_id="unknown", timing_started_at=None):
    log_e2ee_session_timing(request_id, timing_started_at, "sessionValidationEntered")
    companion_dataplane_checkpoint("sessionProtocolCheckStart", request_id, timing_started_at)
    protocol_matches = request.get("protocol_version") == 1
    companion_dataplane_checkpoint(
        "sessionProtocolCheckComplete",
        request_id,
        timing_started_at,
        protocolMatches=str(protocol_matches).lower()
    )
    if not protocol_matches:
        log_e2ee_session_timing(request_id, timing_started_at, "sessionPairingValidation")
        print(
            "[SOSYNC-E2EE-REMOTE-PAIRING] "
            "stage=sessionPairingValidation "
            "lookupFound=false "
            "deviceIDMatches=false "
            "clientKeyMatches=false "
            "homeBindingMatches=false "
            "companionKeyVersionMatches=false "
            "protocolMatches=false "
            "storedPairingFingerprint=none "
            "requestPairingFingerprint=none "
            "failureField=protocolVersion",
            flush=True
        )
        raise ValueError("unsupported_protocol_version")
    companion_dataplane_checkpoint("sessionFieldExtractionStart", request_id, timing_started_at)
    route_id = str(request.get("route_id") or "")
    session_id = str(request.get("session_id") or "")
    device_id = str(request.get("device_id") or "")
    home_id = str(request.get("home_id") or "")
    companion_dataplane_checkpoint(
        "sessionFieldExtractionComplete",
        request_id,
        timing_started_at,
        hasRouteID=str(bool(route_id)).lower(),
        hasSessionID=str(bool(session_id)).lower(),
        hasDeviceID=str(bool(device_id)).lower(),
        hasHomeID=str(bool(home_id)).lower()
    )
    public_key_started_at = time.monotonic()
    companion_dataplane_checkpoint("sessionDevicePublicKeyNormalizeStart", request_id, timing_started_at)
    device_public_key = normalized_e2ee_public_key(
        request.get("device_public_key"),
        request_id=request_id,
        timing_started_at=timing_started_at,
        label="sessionDevicePublicKey"
    )
    companion_dataplane_checkpoint(
        "sessionDevicePublicKeyNormalizeComplete",
        request_id,
        timing_started_at,
        segmentElapsedMs=elapsed_ms_since(public_key_started_at),
        valid=str(bool(device_public_key)).lower()
    )
    ephemeral_key_started_at = time.monotonic()
    companion_dataplane_checkpoint("sessionEphemeralPublicKeyNormalizeStart", request_id, timing_started_at)
    device_ephemeral_public_key = normalized_e2ee_public_key(
        request.get("device_ephemeral_public_key"),
        request_id=request_id,
        timing_started_at=timing_started_at,
        label="sessionEphemeralPublicKey"
    )
    companion_dataplane_checkpoint(
        "sessionEphemeralPublicKeyNormalizeComplete",
        request_id,
        timing_started_at,
        segmentElapsedMs=elapsed_ms_since(ephemeral_key_started_at),
        valid=str(bool(device_ephemeral_public_key)).lower()
    )
    log_e2ee_session_timing(request_id, timing_started_at, "sessionBindingParsed")
    if route_id != binding.get("route_id") or not session_id or not device_id or not device_public_key or not device_ephemeral_public_key:
        log_e2ee_session_timing(request_id, timing_started_at, "sessionPairingValidation")
        print(
            "[SOSYNC-E2EE-REMOTE-PAIRING] "
            "stage=sessionPairingValidation "
            "lookupFound=false "
            "deviceIDMatches=false "
            "clientKeyMatches=false "
            "homeBindingMatches=false "
            "companionKeyVersionMatches=false "
            "protocolMatches=true "
            "storedPairingFingerprint=none "
            f"requestPairingFingerprint={safe_fingerprint('|'.join([home_id, device_id, device_public_key or 'none']))} "
            "failureField=sessionBinding",
            flush=True
        )
        raise ValueError("invalid_dataplane_session")

    log_e2ee_session_timing(request_id, timing_started_at, "pairingLookupStarted")
    log_e2ee_session_timing(request_id, timing_started_at, "pairingFileReadStarted")
    pairings = read_e2ee_pairings().get("devices", {})
    log_e2ee_session_timing(request_id, timing_started_at, "pairingFileReadCompleted")
    pairing = pairings.get(device_id)
    log_e2ee_session_timing(request_id, timing_started_at, "pairingLookupCompleted")
    log_e2ee_session_timing(request_id, timing_started_at, "identityLookupStarted")
    identity = ensure_e2ee_identity(request_id=request_id, timing_started_at=timing_started_at)
    log_e2ee_session_timing(request_id, timing_started_at, "identityLookupCompleted")
    lookup_found = bool(pairing)
    status_active = lookup_found and pairing.get("status") == "active"
    device_id_matches = lookup_found and pairing.get("device_id") == device_id
    client_key_matches = lookup_found and pairing.get("device_public_key") == device_public_key
    home_binding_matches = lookup_found and pairing.get("home_id") == home_id
    companion_key_version_matches = lookup_found and int(pairing.get("key_version") or 0) == int(identity.get("key_version") or 0)
    stored_pairing_fingerprint = "none"
    if lookup_found:
        stored_pairing_fingerprint = safe_fingerprint("|".join([
            str(pairing.get("home_id") or ""),
            str(pairing.get("device_id") or ""),
            str(pairing.get("device_public_key") or ""),
            str(pairing.get("companion_public_key") or ""),
            str(pairing.get("key_version") or "")
        ]))
    request_pairing_fingerprint = safe_fingerprint("|".join([
        home_id,
        device_id,
        device_public_key,
        str(identity.get("public_key") or ""),
        str(identity.get("key_version") or "")
    ]))
    failure_field = "none"
    if not lookup_found:
        failure_field = "lookup"
    elif not status_active:
        failure_field = "status"
    elif not home_binding_matches:
        failure_field = "homeBinding"
    elif not client_key_matches:
        failure_field = "clientPublicKey"
    elif not device_id_matches:
        failure_field = "deviceID"
    elif not companion_key_version_matches:
        failure_field = "companionKeyVersion"
    log_e2ee_session_timing(request_id, timing_started_at, "sessionPairingValidation")
    print(
        "[SOSYNC-E2EE-REMOTE-PAIRING] "
        "stage=sessionPairingValidation "
        f"lookupFound={str(lookup_found).lower()} "
        f"deviceIDMatches={str(device_id_matches).lower()} "
        f"clientKeyMatches={str(client_key_matches).lower()} "
        f"homeBindingMatches={str(home_binding_matches).lower()} "
        f"companionKeyVersionMatches={str(companion_key_version_matches).lower()} "
        "protocolMatches=true "
        f"storedPairingFingerprint={stored_pairing_fingerprint} "
        f"requestPairingFingerprint={request_pairing_fingerprint} "
        f"failureField={failure_field}",
        flush=True
    )
    if not pairing or pairing.get("status") != "active":
        raise ValueError("pairing_not_active")
    if pairing.get("home_id") != home_id or pairing.get("device_public_key") != device_public_key:
        raise ValueError("pairing_mismatch")

    log_e2ee_session_timing(request_id, timing_started_at, "cryptoKeyDerivationStarted")
    crypto_started_at = time.monotonic()
    companion_ephemeral = x25519.X25519PrivateKey.generate()
    companion_ephemeral_public_key = base64url_encode(companion_ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    shared = x25519.X25519PrivateKey.from_private_bytes(base64url_decode(identity["private_key"])).exchange(
        x25519.X25519PublicKey.from_public_bytes(base64url_decode(device_public_key))
    )
    context = secure_remote_dataplane_context(
        route_id,
        session_id,
        pairing.get("home_id"),
        pairing.get("device_id"),
        pairing.get("device_public_key"),
        identity.get("public_key"),
        device_ephemeral_public_key,
        companion_ephemeral_public_key
    )
    log_e2ee_session_timing(request_id, timing_started_at, "cryptoKeyDerivationCompleted")
    companion_perf_log("cryptoCompleted", operation="sessionKeyDerivation", requestID=request_id, elapsedMs=elapsed_ms_since(crypto_started_at))
    log_e2ee_session_timing(request_id, timing_started_at, "sessionObjectCreationStarted")
    session = {
        "session_id": session_id,
        "route_id": route_id,
        "home_id": home_id,
        "device_id": device_id,
        "companion_ephemeral_public_key": companion_ephemeral_public_key,
        "client_key": hkdf_dataplane_key(shared, context, b"|client_to_companion"),
        "companion_key": hkdf_dataplane_key(shared, context, b"|companion_to_client"),
        "highest_client_sequence": 0,
        "next_companion_sequence": 1,
        "expires_at": time.time() + 60,
        "expires_in_seconds": 60
    }
    log_e2ee_session_timing(request_id, timing_started_at, "sessionObjectCreationCompleted")
    lock_started_at = time.monotonic()
    log_e2ee_session_timing(request_id, timing_started_at, "dataplaneSessionLockWaitStarted")
    with timed_lock(SECURE_REMOTE_DATAPLANE_LOCK, "dataplaneSessionStore", request_id=request_id, log_threshold_ms=1):
        lock_wait_ms = elapsed_ms_since(lock_started_at)
        log_e2ee_session_timing(request_id, timing_started_at, "dataplaneSessionLockAcquired", lock_wait_ms=lock_wait_ms)
        log_e2ee_session_timing(request_id, timing_started_at, "dataplaneSessionStoreStarted")
        SECURE_REMOTE_DATAPLANE_SESSIONS[(route_id, session_id)] = session
        log_e2ee_session_timing(request_id, timing_started_at, "dataplaneSessionStoreCompleted")
    return session


def secure_remote_dataplane_session(binding, session_id, enforce_expiry=True):
    key = (binding.get("route_id"), str(session_id or ""))
    with timed_lock(SECURE_REMOTE_DATAPLANE_LOCK, "dataplaneSessionLookup", log_threshold_ms=10):
        session = SECURE_REMOTE_DATAPLANE_SESSIONS.get(key)
        if not session or (enforce_expiry and session.get("expires_at", 0) < time.time()):
            SECURE_REMOTE_DATAPLANE_SESSIONS.pop(key, None)
            return None
        return session


def secure_remote_dataplane_context(route_id, session_id, home_id, device_id, device_public_key, companion_public_key, device_ephemeral_public_key, companion_ephemeral_public_key):
    return "|".join([
        "protocol_version=1",
        f"route_id={route_id}",
        f"home_id={home_id}",
        f"device_id={device_id}",
        f"session_id={session_id}",
        f"device_public_key={device_public_key}",
        f"companion_public_key={companion_public_key}",
        f"device_ephemeral_public_key={device_ephemeral_public_key}",
        f"companion_ephemeral_public_key={companion_ephemeral_public_key}"
    ]).encode("utf-8")


def hkdf_dataplane_key(shared_secret, context, direction_suffix):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"sosync-secure-remote-dataplane-v1",
        info=context + direction_suffix,
    ).derive(shared_secret)


def secure_remote_dataplane_aad(route_id, session_id, device_id, direction, sequence, message_id):
    return f"v=1|route={route_id}|session={session_id}|device={device_id}|direction={direction}|sequence={sequence}|message={message_id}".encode("utf-8")


def decrypt_secure_remote_dataplane_envelope(binding, envelope, expected_direction, enforce_expiry=True):
    decrypt_started_at = time.monotonic()
    session_lookup_started_at = time.monotonic()
    session = secure_remote_dataplane_session(binding, envelope.get("session_id"), enforce_expiry=enforce_expiry)
    session_lookup_ms = elapsed_ms_since(session_lookup_started_at)
    if not session:
        raise ValueError("encrypted_session_required")
    if (
        envelope.get("protocol_version") != 1
        or envelope.get("route_id") != binding.get("route_id")
        or envelope.get("device_id") != session.get("device_id")
        or envelope.get("direction") != expected_direction
    ):
        raise ValueError("invalid_envelope_binding")
    sequence = int(envelope.get("sequence") or 0)
    if sequence <= int(session.get("highest_client_sequence") or 0):
        raise ValueError("replay_rejected")
    nonce = base64url_decode(envelope.get("nonce") or "")
    ciphertext = base64url_decode(envelope.get("ciphertext") or "")
    aad = secure_remote_dataplane_aad(binding.get("route_id"), session["session_id"], session["device_id"], expected_direction, sequence, str(envelope.get("message_id") or ""))
    crypto_core_started_at = time.monotonic()
    plaintext = ChaCha20Poly1305(session["client_key"]).decrypt(nonce, ciphertext, aad)
    crypto_core_ms = elapsed_ms_since(crypto_core_started_at)
    session_update_started_at = time.monotonic()
    with timed_lock(SECURE_REMOTE_DATAPLANE_LOCK, "dataplaneSessionUpdate", log_threshold_ms=10):
        session["highest_client_sequence"] = sequence
        SECURE_REMOTE_DATAPLANE_SESSIONS[(binding.get("route_id"), session["session_id"])] = session
    session_update_ms = elapsed_ms_since(session_update_started_at)
    companion_perf_log_if_slow(
        "cryptoCompleted",
        elapsed_ms_since(decrypt_started_at),
        operation="decryptEnvelope",
        session=safe_fingerprint(session.get("session_id")),
        sequence=sequence,
        sessionLookupMs=session_lookup_ms,
        cryptoCoreMs=crypto_core_ms,
        sessionUpdateMs=session_update_ms,
        ciphertextBytes=len(ciphertext),
        plaintextBytes=len(plaintext)
    )
    return plaintext


def encrypt_secure_remote_dataplane_envelope(binding, session_id, plaintext, direction, message_id, enforce_expiry=True):
    encrypt_started_at = time.monotonic()
    session_lookup_started_at = time.monotonic()
    session = secure_remote_dataplane_session(binding, session_id, enforce_expiry=enforce_expiry)
    session_lookup_ms = elapsed_ms_since(session_lookup_started_at)
    if not session:
        raise ValueError("encrypted_session_required")
    sequence = int(session.get("next_companion_sequence") or 1)
    session["next_companion_sequence"] = sequence + 1
    nonce = os.urandom(12)
    aad = secure_remote_dataplane_aad(binding.get("route_id"), session["session_id"], session["device_id"], direction, sequence, message_id)
    crypto_core_started_at = time.monotonic()
    ciphertext = ChaCha20Poly1305(session["companion_key"]).encrypt(nonce, plaintext, aad)
    crypto_core_ms = elapsed_ms_since(crypto_core_started_at)
    session_update_started_at = time.monotonic()
    with timed_lock(SECURE_REMOTE_DATAPLANE_LOCK, "dataplaneSessionUpdate", log_threshold_ms=10):
        SECURE_REMOTE_DATAPLANE_SESSIONS[(binding.get("route_id"), session["session_id"])] = session
    session_update_ms = elapsed_ms_since(session_update_started_at)
    envelope_started_at = time.monotonic()
    envelope = {
        "protocol_version": 1,
        "route_id": binding.get("route_id"),
        "session_id": session["session_id"],
        "device_id": session["device_id"],
        "direction": direction,
        "sequence": sequence,
        "message_id": message_id,
        "nonce": base64url_encode(nonce),
        "ciphertext": base64url_encode(ciphertext)
    }
    envelope_ms = elapsed_ms_since(envelope_started_at)
    companion_perf_log_if_slow(
        "cryptoCompleted",
        elapsed_ms_since(encrypt_started_at),
        operation="encryptEnvelope",
        session=safe_fingerprint(session.get("session_id")),
        sequence=sequence,
        sessionLookupMs=session_lookup_ms,
        cryptoCoreMs=crypto_core_ms,
        sessionUpdateMs=session_update_ms,
        envelopeMs=envelope_ms,
        plaintextBytes=len(plaintext),
        ciphertextBytes=len(ciphertext)
    )
    return envelope


def websocket_opcode_class(opcode):
    if opcode == 0x0:
        return "continuation"
    if opcode == 0x1:
        return "text"
    if opcode == 0x2:
        return "binary"
    if opcode == 0x8:
        return "close"
    if opcode == 0x9:
        return "ping"
    if opcode == 0xA:
        return "pong"
    if opcode is None:
        return "none"
    return "unsupported"


def log_encrypted_websocket_outbound(binding, session_id, opcode, plaintext_bytes, envelope=None, envelope_bytes=0, classification="data"):
    sequence = envelope.get("sequence") if isinstance(envelope, dict) else "none"
    envelope_version = envelope.get("protocol_version") if isinstance(envelope, dict) else "none"
    route_fingerprint = safe_fingerprint(binding.get("route_id"))
    session_fingerprint = safe_fingerprint(session_id)
    with timed_lock(SECURE_REMOTE_WS_LOG_LOCK, "webSocketLog", log_threshold_ms=10):
        counter_key = (route_fingerprint, session_fingerprint, classification)
        count = SECURE_REMOTE_WS_LOG_COUNTS.get(counter_key, 0) + 1
        SECURE_REMOTE_WS_LOG_COUNTS[counter_key] = count
    should_log = classification != "data" or count <= 3 or count % 50 == 0
    if not should_log:
        return
    print(
        "[SOSYNC-SECURE-REMOTE-DATAPLANE] "
        f"event=encryptedWebSocketOutbound messageType={websocket_opcode_class(opcode)} "
        f"envelopeVersion={envelope_version} session={session_fingerprint} "
        f"sequence={sequence} plaintextBytes={plaintext_bytes} envelopeBytes={envelope_bytes} "
        f"classification={classification} sampleCount={count}",
        flush=True
    )


def companion_command_latency(stage, request_id, command_id, ha_command_id, started_at, **fields):
    parts = [
        "[SOSYNC-COMMAND-LATENCY]",
        f"side=companion",
        f"phase={stage}",
        f"requestID={request_id}",
        f"correlationID={e2ee_session_correlation(request_id)}",
        f"commandID={command_id or 'none'}",
        f"haCommandID={ha_command_id if ha_command_id is not None else 'none'}",
        f"elapsedMs={elapsed_ms_since(started_at)}",
    ]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    print(" ".join(parts), flush=True)


def ha_call_service_target_count(decoded_client_object):
    if not isinstance(decoded_client_object, dict):
        return 0
    target = decoded_client_object.get("target")
    if not isinstance(target, dict):
        return 0
    entity_id = target.get("entity_id")
    if isinstance(entity_id, list):
        return len([value for value in entity_id if isinstance(value, str) and value.strip()])
    if isinstance(entity_id, str) and entity_id.strip():
        return 1
    return 0


def perform_secure_remote_dataplane_rest(method, ha_path, headers, body_base64url):
    target_url = f"{read_ha_upstream()}{ha_path}"
    request_body = base64url_decode(body_base64url) if body_base64url else None
    forwarded_headers = {}
    for header in ("Authorization", "Content-Type", "Accept", "User-Agent"):
        value = headers.get(header) if isinstance(headers, dict) else None
        if value:
            forwarded_headers[header] = value
    request = urllib.request.Request(target_url, data=request_body, headers=forwarded_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read()
            return {
                "status": response.status,
                "headers": {"Content-Type": response.headers.get("Content-Type", "application/json")},
                "body_base64url": base64url_encode(body) if body else None
            }
    except urllib.error.HTTPError as error:
        body = error.read()
        return {
            "status": error.code,
            "headers": {"Content-Type": error.headers.get("Content-Type", "application/json")},
            "body_base64url": base64url_encode(body) if body else None
        }


def bridge_secure_remote_dataplane_websocket(client_socket, upstream_socket, binding, session_id, request_id="unknown", timing_started_at=None):
    sockets = [client_socket, upstream_socket]
    bridge_started_at = time.monotonic()
    last_inbound_client_frame_at = None
    last_outbound_client_frame_at = None
    last_upstream_ha_frame_at = None
    last_heartbeat_at = None
    first_terminated_direction = "none"
    next_revocation_check_at = 0
    did_log_first_upstream_frame = False
    did_log_first_encrypted_outbound = False
    did_log_first_encrypted_outbound_write = False
    did_log_first_client_frame = False
    did_log_first_client_decrypt = False
    did_log_first_upstream_auth_write = False
    did_log_first_upstream_auth_written = False
    command_timings = {}
    secure_remote_websocket_lifecycle(
        "relayStarted",
        request_id,
        bridge_started_at,
        binding,
        session_id
    )
    try:
        while True:
            now = time.monotonic()
            if now >= next_revocation_check_at:
                note_secure_remote_binding_stat("revocationPolls")
                revocation_started_at = time.monotonic()
                current_binding = read_secure_remote_binding()
                session_present = secure_remote_dataplane_session(binding, session_id, enforce_expiry=False)
                companion_perf_log_if_slow(
                    "webSocketRevocationPollCompleted",
                    elapsed_ms_since(revocation_started_at),
                    threshold_ms=10,
                    route=safe_fingerprint(binding.get("route_id")),
                    session=safe_fingerprint(session_id)
                )
                next_revocation_check_at = now + SECURE_REMOTE_DATAPLANE_REVOCATION_POLL_SECONDS
                if current_binding.get("status") == "revoked" or not session_present:
                    first_terminated_direction = "companionRevocation"
                    secure_remote_websocket_lifecycle(
                        "relayTerminating",
                        request_id,
                        bridge_started_at,
                        binding,
                        session_id,
                        first_terminated_direction=first_terminated_direction,
                        last_inbound_client_frame_at=last_inbound_client_frame_at,
                        last_outbound_client_frame_at=last_outbound_client_frame_at,
                        last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                        last_heartbeat_at=last_heartbeat_at,
                        reason="revocationOrSessionMissing"
                    )
                    print(
                        f"[SOSYNC-SECURE-REMOTE-DATAPLANE] event=companionEncryptedWebSocketRevocationClosed route={safe_fingerprint(binding.get('route_id'))} maxRevocationEnforcementSeconds=60",
                        flush=True
                    )
                    return
            readable, _, _ = select.select(sockets, [], [], 0.5)
            for source in readable:
                if source is client_socket:
                    try:
                        opcode, payload = read_websocket_frame(client_socket)
                    except Exception as error:
                        first_terminated_direction = "downstreamClientRead"
                        secure_remote_websocket_lifecycle(
                            "relayTerminated",
                            request_id,
                            bridge_started_at,
                            binding,
                            session_id,
                            first_terminated_direction=first_terminated_direction,
                            exception=error,
                            last_inbound_client_frame_at=last_inbound_client_frame_at,
                            last_outbound_client_frame_at=last_outbound_client_frame_at,
                            last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                            last_heartbeat_at=last_heartbeat_at
                        )
                        raise
                    last_inbound_client_frame_at = time.monotonic()
                    if not did_log_first_client_frame:
                        did_log_first_client_frame = True
                        companion_dataplane_checkpoint("firstEncryptedInboundClientFrameReceived", request_id, timing_started_at, session=safe_fingerprint(session_id), opcode=websocket_opcode_class(opcode), bytes=len(payload))
                    if opcode in (0x8, None):
                        first_terminated_direction = "downstreamClientClose"
                        secure_remote_websocket_lifecycle(
                            "relayTerminated",
                            request_id,
                            bridge_started_at,
                            binding,
                            session_id,
                            first_terminated_direction=first_terminated_direction,
                            last_inbound_client_frame_at=last_inbound_client_frame_at,
                            last_outbound_client_frame_at=last_outbound_client_frame_at,
                            last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                            last_heartbeat_at=last_heartbeat_at,
                            opcode=websocket_opcode_class(opcode)
                        )
                        return
                    if opcode == 0x9:
                        last_heartbeat_at = time.monotonic()
                        try:
                            write_websocket_frame(client_socket, 0xA, payload, mask=False)
                        except Exception as error:
                            first_terminated_direction = "downstreamClientWrite"
                            secure_remote_websocket_lifecycle(
                                "relayTerminated",
                                request_id,
                                bridge_started_at,
                                binding,
                                session_id,
                                first_terminated_direction=first_terminated_direction,
                                exception=error,
                                last_inbound_client_frame_at=last_inbound_client_frame_at,
                                last_outbound_client_frame_at=last_outbound_client_frame_at,
                                last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                                last_heartbeat_at=last_heartbeat_at,
                                attemptedWrite="pongToClient"
                            )
                            raise
                        continue
                    if opcode == 0xA:
                        last_heartbeat_at = time.monotonic()
                        continue
                    if opcode != 0x1:
                        raise ValueError(f"unsupported_client_websocket_opcode_{websocket_opcode_class(opcode)}")
                    envelope = json.loads(payload.decode("utf-8"))
                    command_id = envelope.get("message_id") if isinstance(envelope, dict) else None
                    decrypt_started_at = time.monotonic()
                    plaintext = decrypt_secure_remote_dataplane_envelope(binding, envelope, "client_to_companion", enforce_expiry=False)
                    try:
                        decoded_client_object = json.loads(plaintext.decode("utf-8"))
                    except Exception:
                        decoded_client_object = {}
                    ha_command_id = decoded_client_object.get("id") if isinstance(decoded_client_object, dict) else None
                    ha_type = decoded_client_object.get("type") if isinstance(decoded_client_object, dict) else None
                    if ha_type == "call_service":
                        target_count = ha_call_service_target_count(decoded_client_object)
                        command_timings[ha_command_id] = {
                            "command_id": command_id,
                            "started_at": decrypt_started_at,
                            "target_count": target_count,
                        }
                        companion_command_latency(
                            "companionInboundFrameDecrypted",
                            request_id,
                            command_id,
                            ha_command_id,
                            decrypt_started_at,
                            segmentMs=elapsed_ms_since(decrypt_started_at),
                            plaintextBytes=len(plaintext),
                            targetCount=target_count,
                        )
                    if not did_log_first_client_decrypt:
                        did_log_first_client_decrypt = True
                        companion_dataplane_checkpoint("firstInboundFrameDecrypted", request_id, timing_started_at, session=safe_fingerprint(session_id), bytes=len(plaintext))
                    if not did_log_first_upstream_auth_write:
                        did_log_first_upstream_auth_write = True
                        companion_dataplane_checkpoint("firstUpstreamHAAuthFrameWriteStart", request_id, timing_started_at, session=safe_fingerprint(session_id), bytes=len(plaintext))
                    try:
                        if ha_type == "call_service":
                            target_count = command_timings[ha_command_id].get("target_count", 0)
                            upstream_write_started_at = time.monotonic()
                            command_timings[ha_command_id]["upstream_write_started_at"] = upstream_write_started_at
                            companion_command_latency(
                                "upstreamHAWriteStart",
                                request_id,
                                command_id,
                                ha_command_id,
                                command_timings[ha_command_id]["started_at"],
                                bytes=len(plaintext),
                                targetCount=target_count,
                            )
                        write_websocket_frame(upstream_socket, 0x1, plaintext, mask=False)
                        if ha_type == "call_service":
                            target_count = command_timings[ha_command_id].get("target_count", 0)
                            upstream_write_started_at = command_timings[ha_command_id].get("upstream_write_started_at", time.monotonic())
                            companion_command_latency(
                                "upstreamHAWriteComplete",
                                request_id,
                                command_id,
                                ha_command_id,
                                command_timings[ha_command_id]["started_at"],
                                bytes=len(plaintext),
                                segmentMs=elapsed_ms_since(upstream_write_started_at),
                                targetCount=target_count,
                            )
                    except Exception as error:
                        first_terminated_direction = "upstreamHAWrite"
                        secure_remote_websocket_lifecycle(
                            "relayTerminated",
                            request_id,
                            bridge_started_at,
                            binding,
                            session_id,
                            first_terminated_direction=first_terminated_direction,
                            exception=error,
                            last_inbound_client_frame_at=last_inbound_client_frame_at,
                            last_outbound_client_frame_at=last_outbound_client_frame_at,
                            last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                            last_heartbeat_at=last_heartbeat_at,
                            attemptedWrite="plaintextToUpstreamHA"
                        )
                        raise
                    if not did_log_first_upstream_auth_written:
                        did_log_first_upstream_auth_written = True
                        companion_dataplane_checkpoint("firstUpstreamHAAuthFrameWritten", request_id, timing_started_at, session=safe_fingerprint(session_id), bytes=len(plaintext))
                else:
                    try:
                        opcode, payload = read_websocket_frame(upstream_socket)
                    except Exception as error:
                        first_terminated_direction = "upstreamHARead"
                        secure_remote_websocket_lifecycle(
                            "relayTerminated",
                            request_id,
                            bridge_started_at,
                            binding,
                            session_id,
                            first_terminated_direction=first_terminated_direction,
                            exception=error,
                            last_inbound_client_frame_at=last_inbound_client_frame_at,
                            last_outbound_client_frame_at=last_outbound_client_frame_at,
                            last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                            last_heartbeat_at=last_heartbeat_at
                        )
                        raise
                    last_upstream_ha_frame_at = time.monotonic()
                    if not did_log_first_upstream_frame:
                        did_log_first_upstream_frame = True
                        companion_dataplane_checkpoint("firstUpstreamHAFrameReceived", request_id, timing_started_at, session=safe_fingerprint(session_id), opcode=websocket_opcode_class(opcode), bytes=len(payload))
                    if opcode in (0x8, None):
                        first_terminated_direction = "upstreamHAClose"
                        secure_remote_websocket_lifecycle(
                            "relayTerminated",
                            request_id,
                            bridge_started_at,
                            binding,
                            session_id,
                            first_terminated_direction=first_terminated_direction,
                            last_inbound_client_frame_at=last_inbound_client_frame_at,
                            last_outbound_client_frame_at=last_outbound_client_frame_at,
                            last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                            last_heartbeat_at=last_heartbeat_at,
                            opcode=websocket_opcode_class(opcode)
                        )
                        return
                    if opcode == 0x9:
                        last_heartbeat_at = time.monotonic()
                        log_encrypted_websocket_outbound(binding, session_id, opcode, len(payload), classification="heartbeatSkipped")
                        try:
                            write_websocket_frame(upstream_socket, 0xA, payload, mask=False)
                        except Exception as error:
                            first_terminated_direction = "upstreamHAWrite"
                            secure_remote_websocket_lifecycle(
                                "relayTerminated",
                                request_id,
                                bridge_started_at,
                                binding,
                                session_id,
                                first_terminated_direction=first_terminated_direction,
                                exception=error,
                                last_inbound_client_frame_at=last_inbound_client_frame_at,
                                last_outbound_client_frame_at=last_outbound_client_frame_at,
                                last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                                last_heartbeat_at=last_heartbeat_at,
                                attemptedWrite="pongToUpstreamHA"
                            )
                            raise
                        continue
                    if opcode == 0xA:
                        last_heartbeat_at = time.monotonic()
                        log_encrypted_websocket_outbound(binding, session_id, opcode, len(payload), classification="heartbeatSkipped")
                        continue
                    if opcode != 0x1:
                        log_encrypted_websocket_outbound(binding, session_id, opcode, len(payload), classification="unsupportedControl")
                        raise ValueError(f"unsupported_upstream_websocket_opcode_{websocket_opcode_class(opcode)}")
                    response_command_id = None
                    response_started_at = time.monotonic()
                    response_ha_command_id = None
                    try:
                        upstream_object = json.loads(payload.decode("utf-8"))
                    except Exception:
                        upstream_object = {}
                    if isinstance(upstream_object, dict) and upstream_object.get("type") == "result":
                        response_ha_command_id = upstream_object.get("id")
                        timing = command_timings.get(response_ha_command_id)
                        if timing:
                            response_command_id = timing.get("command_id")
                            response_started_at = timing.get("started_at") or response_started_at
                            response_target_count = timing.get("target_count", 0)
                            companion_command_latency(
                                "upstreamHAResultReceived",
                                request_id,
                                response_command_id,
                                response_ha_command_id,
                                response_started_at,
                                success=upstream_object.get("success", "unknown"),
                                bytes=len(payload),
                                targetCount=response_target_count,
                            )
                            companion_command_latency(
                                "companionResponseEncryptStart",
                                request_id,
                                response_command_id,
                                response_ha_command_id,
                                response_started_at,
                                targetCount=response_target_count,
                            )
                            command_timings[response_ha_command_id]["response_encrypt_started_at"] = time.monotonic()
                    response_encrypt_started_at = time.monotonic()
                    envelope = encrypt_secure_remote_dataplane_envelope(binding, session_id, payload, "companion_to_client", f"ws-event-{uuid.uuid4()}", enforce_expiry=False)
                    if response_command_id:
                        response_target_count = command_timings.get(response_ha_command_id, {}).get("target_count", 0)
                        response_encrypt_started_at = command_timings.get(response_ha_command_id, {}).get("response_encrypt_started_at", response_encrypt_started_at)
                        companion_command_latency(
                            "companionResponseEncryptComplete",
                            request_id,
                            response_command_id,
                            response_ha_command_id,
                            response_started_at,
                            envelopeSequence=envelope.get("sequence"),
                            segmentMs=elapsed_ms_since(response_encrypt_started_at),
                            targetCount=response_target_count,
                        )
                    if not did_log_first_encrypted_outbound:
                        did_log_first_encrypted_outbound = True
                        companion_dataplane_checkpoint("firstEncryptedOutboundFrameGenerated", request_id, timing_started_at, session=safe_fingerprint(session_id), sequence=envelope.get("sequence"), plaintextBytes=len(payload))
                    envelope_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
                    log_encrypted_websocket_outbound(binding, session_id, opcode, len(payload), envelope=envelope, envelope_bytes=len(envelope_bytes), classification="data")
                    try:
                        if response_command_id:
                            response_target_count = command_timings.get(response_ha_command_id, {}).get("target_count", 0)
                            response_write_started_at = time.monotonic()
                            command_timings[response_ha_command_id]["response_write_started_at"] = response_write_started_at
                            companion_command_latency(
                                "companionResponseWriteStart",
                                request_id,
                                response_command_id,
                                response_ha_command_id,
                                response_started_at,
                                envelopeBytes=len(envelope_bytes),
                                targetCount=response_target_count,
                            )
                        write_websocket_frame(client_socket, 0x1, envelope_bytes, mask=False)
                        last_outbound_client_frame_at = time.monotonic()
                        if response_command_id:
                            response_target_count = command_timings.get(response_ha_command_id, {}).get("target_count", 0)
                            response_write_started_at = command_timings.get(response_ha_command_id, {}).get("response_write_started_at", time.monotonic())
                            companion_command_latency(
                                "companionResponseWriteComplete",
                                request_id,
                                response_command_id,
                                response_ha_command_id,
                                response_started_at,
                                envelopeBytes=len(envelope_bytes),
                                segmentMs=elapsed_ms_since(response_write_started_at),
                                targetCount=response_target_count,
                            )
                            command_timings.pop(response_ha_command_id, None)
                    except Exception as error:
                        first_terminated_direction = "downstreamClientWrite"
                        secure_remote_websocket_lifecycle(
                            "relayTerminated",
                            request_id,
                            bridge_started_at,
                            binding,
                            session_id,
                            first_terminated_direction=first_terminated_direction,
                            exception=error,
                            last_inbound_client_frame_at=last_inbound_client_frame_at,
                            last_outbound_client_frame_at=last_outbound_client_frame_at,
                            last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                            last_heartbeat_at=last_heartbeat_at,
                            attemptedWrite="encryptedEnvelopeToClient",
                            envelopeBytes=len(envelope_bytes)
                        )
                        raise
                    if not did_log_first_encrypted_outbound_write:
                        did_log_first_encrypted_outbound_write = True
                        companion_dataplane_checkpoint("firstEncryptedOutboundFrameWritten", request_id, timing_started_at, session=safe_fingerprint(session_id), sequence=envelope.get("sequence"), envelopeBytes=len(envelope_bytes))
    except Exception as error:
        if first_terminated_direction == "none":
            first_terminated_direction = "handlerException"
            secure_remote_websocket_lifecycle(
                "relayTerminated",
                request_id,
                bridge_started_at,
                binding,
                session_id,
                first_terminated_direction=first_terminated_direction,
                exception=error,
                last_inbound_client_frame_at=last_inbound_client_frame_at,
                last_outbound_client_frame_at=last_outbound_client_frame_at,
                last_upstream_ha_frame_at=last_upstream_ha_frame_at,
                last_heartbeat_at=last_heartbeat_at
            )
        raise
    finally:
        secure_remote_websocket_lifecycle(
            "relayFinishedCleanup",
            request_id,
            bridge_started_at,
            binding,
            session_id,
            first_terminated_direction=first_terminated_direction,
            last_inbound_client_frame_at=last_inbound_client_frame_at,
            last_outbound_client_frame_at=last_outbound_client_frame_at,
            last_upstream_ha_frame_at=last_upstream_ha_frame_at,
            last_heartbeat_at=last_heartbeat_at
        )
        with timed_lock(SECURE_REMOTE_DATAPLANE_LOCK, "dataplaneSessionRemove", log_threshold_ms=10):
            SECURE_REMOTE_DATAPLANE_SESSIONS.pop((binding.get("route_id"), str(session_id or "")), None)
        route_fingerprint = safe_fingerprint(binding.get("route_id"))
        session_fingerprint = safe_fingerprint(session_id)
        with timed_lock(SECURE_REMOTE_WS_LOG_LOCK, "webSocketLog", log_threshold_ms=10):
            for key in list(SECURE_REMOTE_WS_LOG_COUNTS.keys()):
                if key[0] == route_fingerprint and key[1] == session_fingerprint:
                    SECURE_REMOTE_WS_LOG_COUNTS.pop(key, None)


def read_websocket_frame(sock):
    started_at = time.monotonic()
    header = recv_exact(sock, 2)
    if not header:
        return None, b""
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    length = header[1] & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(sock, 8), "big")
    mask_key = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
    companion_perf_log_if_slow(
        "webSocketFrameRead",
        elapsed_ms_since(started_at),
        opcode=websocket_opcode_class(opcode),
        bytes=len(payload)
    )
    return opcode, payload


def write_websocket_frame(sock, opcode, payload, mask=False):
    started_at = time.monotonic()
    first = 0x80 | (opcode & 0x0F)
    length = len(payload)
    if length < 126:
        header = bytes([first, (0x80 if mask else 0) | length])
    elif length < 65536:
        header = bytes([first, (0x80 if mask else 0) | 126]) + length.to_bytes(2, "big")
    else:
        header = bytes([first, (0x80 if mask else 0) | 127]) + length.to_bytes(8, "big")
    if mask:
        mask_key = os.urandom(4)
        payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
        header += mask_key
    sock.sendall(header + payload)
    companion_perf_log_if_slow(
        "webSocketFrameWrite",
        elapsed_ms_since(started_at),
        opcode=websocket_opcode_class(opcode),
        bytes=len(payload)
    )


def recv_exact(sock, length):
    chunks = []
    remaining = length
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("socket_closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def normalize_companion_target(value):
    if not value:
        return DEFAULT_COMPANION_URL

    target = str(value).strip().rstrip("/")
    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        return DEFAULT_COMPANION_URL

    port = parsed.port or PORT
    return f"http://127.0.0.1:{port}"


def normalize_ha_upstream(value):
    if not value:
        return DEFAULT_HOME_ASSISTANT_URL

    target = str(value).strip().rstrip("/")
    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        return DEFAULT_HOME_ASSISTANT_URL

    port = parsed.port or 8123
    path = parsed.path.rstrip("/")
    return f"http://127.0.0.1:{port}{path}"


def is_allowed_ha_path(path):
    allowed_exact = {
        "/api/",
        "/api/config",
        "/api/states",
        "/api/services",
        "/api/websocket",
        "/api/config/energy"
    }
    allowed_prefixes = (
        "/api/config/automation/config/",
        "/api/config/config_entries",
        "/api/hassio/",
        "/api/history/period/",
        "/api/states/",
        "/api/services/"
    )

    if path in allowed_exact:
        return True

    return any(path.startswith(prefix) for prefix in allowed_prefixes)


def validate_signed_remote_route(path):
    match = SIGNED_REMOTE_PATTERN.match(path)
    if not match:
        return {"ok": False, "status": 404, "error": "signed_route_not_found"}

    stored_token = read_remote_token()
    if not stored_token:
        return {"ok": False, "status": 401, "error": "remote_token_missing"}

    expires_raw, nonce, signature, ha_path = match.groups()
    try:
        expires_at = int(expires_raw)
    except ValueError:
        return {"ok": False, "status": 401, "error": "invalid_expiry"}

    now = int(time.time())
    if expires_at < now:
        return {"ok": False, "status": 401, "error": "signed_route_expired"}

    if expires_at - now > SIGNED_ROUTE_MAX_TTL_SECONDS:
        return {"ok": False, "status": 401, "error": "signed_route_ttl_too_long"}

    signature_input = f"{expires_at}.{nonce}".encode("utf-8")
    digest = hmac.new(stored_token.encode("utf-8"), signature_input, hashlib.sha256).digest()
    expected_signature = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    if not hmac.compare_digest(signature, expected_signature):
        return {"ok": False, "status": 401, "error": "invalid_signature"}

    return {
        "ok": True,
        "ha_path": ha_path or "/"
    }


def sanitize_signed_path(path):
    return SIGNED_REMOTE_PATTERN.sub(
        "/remote/signed/<expires>/<nonce>/<signature>/ha\\4",
        path
    )


def sanitize_ha_path_for_log(path):
    return re.sub(r"/[A-Za-z0-9_-]{12,}", "/<id>", path)


def ha_path_class_for_log(path):
    if path == "/api/websocket":
        return "haWebSocket"
    if path == "/auth/token":
        return "haAuthToken"
    if path in ("/api", "/api/"):
        return "haApiRoot"
    if path.startswith("/api/"):
        return "haApi"
    return "other"


def is_websocket_upgrade(headers):
    connection = headers.get("Connection", "")
    upgrade = headers.get("Upgrade", "")
    return "upgrade" in connection.lower() and upgrade.lower() == "websocket"


def read_http_headers(source_socket):
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = source_socket.recv(4096)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > 65536:
            break
    return buffer


def tunnel_sockets(client_socket, upstream_socket):
    sockets = [client_socket, upstream_socket]
    while True:
        readable, _, exceptional = select.select(sockets, [], sockets, 300)
        if exceptional:
            return
        if not readable:
            return
        for source in readable:
            try:
                data = source.recv(65536)
            except OSError:
                return
            if not data:
                return
            target = upstream_socket if source is client_socket else client_socket
            try:
                target.sendall(data)
            except OSError:
                return


def store_remote_token(token):
    os.makedirs(os.path.dirname(REMOTE_TOKEN_FILE), exist_ok=True)
    with open(REMOTE_TOKEN_FILE, "w", encoding="utf-8") as file:
        file.write(str(token).strip())


def store_server_id(server_id):
    if not server_id:
        return

    os.makedirs(os.path.dirname(SERVER_ID_FILE), exist_ok=True)
    with open(SERVER_ID_FILE, "w", encoding="utf-8") as file:
        file.write(str(server_id).strip())


def read_existing_server_id():
    try:
        with open(SERVER_ID_FILE, "r", encoding="utf-8") as file:
            value = file.read().strip()
            return value or None
    except FileNotFoundError:
        return None


def get_or_create_server_id():
    try:
        with open(SERVER_ID_FILE, "r", encoding="utf-8") as file:
            value = file.read().strip()
            if value:
                return value
    except FileNotFoundError:
        pass

    value = f"srv_{uuid.uuid4().hex[:12]}"
    store_server_id(value)
    return value


def store_remote_url(url):
    os.makedirs(os.path.dirname(REMOTE_URL_FILE), exist_ok=True)
    with open(REMOTE_URL_FILE, "w", encoding="utf-8") as file:
        file.write(str(url).strip())


def read_remote_url():
    try:
        with open(REMOTE_URL_FILE, "r", encoding="utf-8") as file:
            return file.read().strip() or None
    except FileNotFoundError:
        return None


def read_remote_token():
    try:
        with open(REMOTE_TOKEN_FILE, "r", encoding="utf-8") as file:
            return file.read().strip()
    except FileNotFoundError:
        return None


def ensure_companion_identity():
    global COMPANION_IDENTITY_CACHE
    if isinstance(COMPANION_IDENTITY_CACHE, dict):
        return copy_json_value(COMPANION_IDENTITY_CACHE)
    with timed_lock(COMPANION_IDENTITY_LOCK, "companionIdentity", log_threshold_ms=5):
        if isinstance(COMPANION_IDENTITY_CACHE, dict):
            return copy_json_value(COMPANION_IDENTITY_CACHE)
        identity = read_json_file(COMPANION_IDENTITY_FILE, None)
        if (
            isinstance(identity, dict) and
            identity.get("companion_id") and
            identity.get("companion_instance_id") and
            identity.get("signing_public_key") and
            identity.get("signing_private_key") and
            identity.get("encryption_public_key") and
            identity.get("encryption_private_key")
        ):
            COMPANION_IDENTITY_CACHE = copy_json_value(identity)
            return copy_json_value(identity)

        signing_private_key = ed25519.Ed25519PrivateKey.generate()
        signing_public_key = signing_private_key.public_key()
        encryption_private_key = x25519.X25519PrivateKey.generate()
        encryption_public_key = encryption_private_key.public_key()

        identity = {
            "protocol_version": 1,
            "companion_id": str(uuid.uuid4()),
            "companion_instance_id": str(uuid.uuid4()),
            "signing_public_key": base64url_encode(signing_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
            "signing_private_key": base64url_encode(signing_private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())),
            "encryption_public_key": base64url_encode(encryption_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
            "encryption_private_key": base64url_encode(encryption_private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            "setup_counter": 0,
            "minimum_protocol_version": 1,
            "created_at": iso_now()
        }
        write_json_file_secure(COMPANION_IDENTITY_FILE, identity)
        COMPANION_IDENTITY_CACHE = copy_json_value(identity)
        return copy_json_value(identity)


def ensure_e2ee_identity(request_id=None, timing_started_at=None):
    global E2EE_IDENTITY_CACHE
    if isinstance(E2EE_IDENTITY_CACHE, dict):
        if timing_started_at is not None:
            log_e2ee_session_timing(request_id or "unknown", timing_started_at, "identityCacheHit")
        return copy_json_value(E2EE_IDENTITY_CACHE)
    lock_started_at = time.monotonic() if timing_started_at is not None else None
    if timing_started_at is not None:
        log_e2ee_session_timing(request_id or "unknown", timing_started_at, "identityLockWaitStarted")
    with timed_lock(E2EE_IDENTITY_LOCK, "e2eeIdentity", request_id=request_id or "none", log_threshold_ms=5):
        if isinstance(E2EE_IDENTITY_CACHE, dict):
            if timing_started_at is not None:
                log_e2ee_session_timing(request_id or "unknown", timing_started_at, "identityCacheHitAfterLock")
            return copy_json_value(E2EE_IDENTITY_CACHE)
        if timing_started_at is not None and lock_started_at is not None:
            log_e2ee_session_timing(
                request_id or "unknown",
                timing_started_at,
                "identityLockAcquired",
                lock_wait_ms=elapsed_ms_since(lock_started_at)
            )
        if timing_started_at is not None:
            log_e2ee_session_timing(request_id or "unknown", timing_started_at, "identityFileReadStarted")
        identity = read_json_file(E2EE_IDENTITY_FILE, None)
        if timing_started_at is not None:
            log_e2ee_session_timing(request_id or "unknown", timing_started_at, "identityFileReadCompleted")
        if (
            isinstance(identity, dict) and
            identity.get("public_key") and
            identity.get("private_key") and
            identity.get("key_version")
        ):
            E2EE_IDENTITY_CACHE = copy_json_value(identity)
            return copy_json_value(identity)

        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        identity = {
            "protocol_version": E2EE_PROTOCOL_VERSION,
            "algorithm": "X25519",
            "public_key": base64url_encode(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
            "private_key": base64url_encode(private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            "key_version": 1,
            "created_at": iso_now()
        }
        if timing_started_at is not None:
            log_e2ee_session_timing(request_id or "unknown", timing_started_at, "identityFileWriteStarted")
        write_json_file_secure(E2EE_IDENTITY_FILE, identity)
        if timing_started_at is not None:
            log_e2ee_session_timing(request_id or "unknown", timing_started_at, "identityFileWriteCompleted")
        E2EE_IDENTITY_CACHE = copy_json_value(identity)
        return copy_json_value(identity)


def prewarm_e2ee_identity_cache():
    started_at = time.monotonic()
    try:
        identity = ensure_e2ee_identity()
        companion_perf_log(
            "e2eeIdentityPrewarmCompleted",
            elapsedMs=elapsed_ms_since(started_at),
            cacheReady=str(isinstance(E2EE_IDENTITY_CACHE, dict)).lower(),
            keyVersion=str(identity.get("key_version") or "unknown") if isinstance(identity, dict) else "unknown"
        )
    except BaseException as error:
        companion_perf_log(
            "e2eeIdentityPrewarmFailed",
            elapsedMs=elapsed_ms_since(started_at),
            error=type(error).__name__
        )


def read_e2ee_pairings():
    pairings = read_json_file(E2EE_PAIRINGS_FILE, {"devices": {}}, cache_ttl_seconds=0.25)
    if not isinstance(pairings, dict):
        return {"devices": {}}
    if not isinstance(pairings.get("devices"), dict):
        pairings["devices"] = {}
    return pairings


def log_e2ee_pairing_store_loaded():
    pairings = read_e2ee_pairings()
    count = len(pairings.get("devices", {}))
    print(
        f"[SOSYNC-E2EE-COMPANION] pairingStoreLoaded count={count} storage=/data/sosync_e2ee_pairings.json",
        flush=True
    )


def make_e2ee_pairing_record(home_id, device_id, device_public_key, companion_public_key, key_version):
    return {
        "protocol_version": E2EE_PROTOCOL_VERSION,
        "home_id": home_id,
        "device_id": device_id,
        "device_public_key": device_public_key,
        "companion_public_key": companion_public_key,
        "created_at": iso_now(),
        "key_version": key_version,
        "status": "active"
    }


def has_local_e2ee_pairing_authorization(headers):
    options = read_json_file(ADDON_OPTIONS_FILE, {})
    authorization = options.get("e2ee_pairing_authorization") if isinstance(options, dict) else None
    if not isinstance(authorization, dict):
        print("[SOSYNC-E2EE-COMPANION] pairingAuth configured=false rejectionReason=missingConfig", flush=True)
        return False

    expected = str(authorization.get("token") or "").strip()
    expires_at = authorization.get("expires_at")
    expected_fingerprint = token_fingerprint(expected)
    header_contract, received = local_pairing_token_contract(headers)
    received_fingerprint = token_fingerprint(received)
    expires_parse = parse_iso_epoch(expires_at)
    now_epoch = int(time.time())
    expires_epoch = int(expires_parse[1]) if expires_parse[1] is not None else 0
    expired = bool(expires_parse[0] and expires_epoch <= now_epoch)
    print(f"[SOSYNC-E2EE] companionRuntimeAuthorization observed={bool(expected)} tokenFingerprint={expected_fingerprint}", flush=True)
    print(f"[SOSYNC-E2EE-COMPANION] pairingAuth configured=true tokenFingerprint={expected_fingerprint} headerFingerprint={received_fingerprint} headerContract={header_contract} expiresAt=present", flush=True)
    print(f"[SOSYNC-E2EE-COMPANION] pairingAuth expiresParseSuccess={expires_parse[0]} expiresEpoch={expires_epoch} nowEpoch={now_epoch} expired={expired}", flush=True)
    if not expected:
        print("[SOSYNC-E2EE-COMPANION] pairingAuth tokenMatch=false expired=false rejectionReason=missingConfig", flush=True)
        return False
    if not received:
        print("[SOSYNC-E2EE-COMPANION] pairingAuth tokenMatch=false expired=false rejectionReason=missingHeader", flush=True)
        return False
    if not expires_parse[0]:
        print("[SOSYNC-E2EE-COMPANION] pairingAuth tokenMatch=false expired=false rejectionReason=invalidExpiry", flush=True)
        return False
    if expired:
        print("[SOSYNC-E2EE-COMPANION] pairingAuth tokenMatch=false expired=true rejectionReason=expired", flush=True)
        return False

    authorized = bool(received) and hmac.compare_digest(received, expected)
    print(f"[SOSYNC-E2EE-COMPANION] pairingAuth tokenMatch={authorized} expired=false rejectionReason={'none' if authorized else 'tokenMismatch'}", flush=True)
    if authorized:
        print("[SOSYNC-E2EE] pairingAuthorization source=supervisorOptions result=available", flush=True)
    return authorized


def e2ee_pairing_authorization_status():
    options = read_json_file(ADDON_OPTIONS_FILE, {})
    authorization = options.get("e2ee_pairing_authorization") if isinstance(options, dict) else None
    if not isinstance(authorization, dict):
        return {
            "protocol_version": E2EE_PROTOCOL_VERSION,
            "configured": False,
            "token_fingerprint": "none",
            "expires_parse_success": False,
            "expires_epoch": 0,
            "now_epoch": int(time.time()),
            "expired": False
        }

    token = str(authorization.get("token") or "").strip()
    expires_parse = parse_iso_epoch(authorization.get("expires_at"))
    now_epoch = int(time.time())
    expires_epoch = int(expires_parse[1]) if expires_parse[1] is not None else 0
    expired = bool(expires_parse[0] and expires_epoch <= now_epoch)
    return {
        "protocol_version": E2EE_PROTOCOL_VERSION,
        "configured": bool(token),
        "token_fingerprint": token_fingerprint(token),
        "expires_parse_success": bool(expires_parse[0]),
        "expires_epoch": expires_epoch,
        "now_epoch": now_epoch,
        "expired": expired
    }


def log_pairing_authorization_loaded():
    status = e2ee_pairing_authorization_status()
    print(
        "[SOSYNC-E2EE-COMPANION] "
        f"pairingAuthorizationLoaded runtimeInstance={RUNTIME_INSTANCE_ID} "
        f"configured={status['configured']} "
        f"tokenFingerprint={status['token_fingerprint']}",
        flush=True
    )


def token_fingerprint(value):
    candidate = str(value or "").strip()
    if not candidate:
        return "none"
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:12]


def parse_iso_epoch(value):
    try:
        candidate = str(value or "").strip()
        if not candidate:
            return (False, None)
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        parsed = datetime.fromisoformat(candidate)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (True, parsed.timestamp())
    except Exception:
        return (False, None)


def clear_e2ee_pairing_authorization():
    options = read_json_file(ADDON_OPTIONS_FILE, {})
    if not isinstance(options, dict):
        return
    changed = False
    for key in ("e2ee_pairing_authorization", "e2eePairingAuthorization", "localPairingToken", "local_pairing_token"):
        if key in options:
            options.pop(key, None)
            changed = True
    if changed:
        write_json_file_secure(ADDON_OPTIONS_FILE, options)


def e2ee_recovery_shared_key(companion_private_key, device_public_key):
    private_key = x25519.X25519PrivateKey.from_private_bytes(base64url_decode(companion_private_key))
    public_key = x25519.X25519PublicKey.from_public_bytes(base64url_decode(device_public_key))
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"sosync-e2ee-recovery-v1",
        info=b""
    ).derive(private_key.exchange(public_key))


def e2ee_recovery_proof(key, role, device_id, device_public_key, companion_public_key, client_nonce, companion_nonce=None, home_id=None, key_version=None):
    parts = [
        "sosync-e2ee-recovery-v1",
        str(role or ""),
        str(device_id or ""),
        str(device_public_key or ""),
        str(companion_public_key or ""),
        str(client_nonce or "")
    ]
    if role == "companion":
        parts.extend([
            str(companion_nonce or ""),
            str(home_id or ""),
            str(key_version or "")
        ])
    message = "|".join(parts).encode("utf-8")
    return base64url_encode(hmac.new(key, message, hashlib.sha256).digest())


def opaque_e2ee_identifier(value):
    candidate = str(value or "").strip()
    if re.fullmatch(r"[0-9A-Fa-f-]{16,64}", candidate):
        return candidate
    return ""


def canonical_e2ee_home_identifier(value):
    candidate = str(value or "").strip()
    if re.fullmatch(r"srv_[0-9a-f]{12}", candidate):
        return candidate
    if re.fullmatch(r"[0-9A-Fa-f-]{16,64}", candidate):
        return candidate
    if re.fullmatch(r"home_[A-Za-z0-9_-]{32,96}", candidate):
        return candidate
    if re.fullmatch(r"[A-Za-z0-9_-]{32,128}", candidate):
        return candidate
    return ""


def opaque_e2ee_home_identifier(value):
    return canonical_e2ee_home_identifier(value)


def validate_e2ee_pairing_request(data):
    missing_fields = []
    invalid_fields = []
    if not isinstance(data, dict):
        return ("", "", "", ["body"], [], "unknown")

    raw_home_id = data.get("home_id")
    raw_device_id = data.get("device_id")
    raw_device_public_key = data.get("device_public_key")
    for field, value in (
        ("home_id", raw_home_id),
        ("device_id", raw_device_id),
        ("device_public_key", raw_device_public_key),
    ):
        if str(value or "").strip() == "":
            missing_fields.append(field)

    decoded_public_key_bytes = e2ee_public_key_decoded_byte_count(raw_device_public_key)
    home_id = opaque_e2ee_home_identifier(raw_home_id)
    device_id = opaque_e2ee_identifier(raw_device_id)
    device_public_key = normalized_e2ee_public_key(raw_device_public_key)
    if raw_home_id is not None and not home_id:
        invalid_fields.append("home_id")
    if raw_device_id is not None and not device_id:
        invalid_fields.append("device_id")
    if raw_device_public_key is not None and not device_public_key:
        invalid_fields.append("device_public_key")
    return (home_id, device_id, device_public_key, missing_fields, invalid_fields, decoded_public_key_bytes)


def e2ee_public_key_decoded_byte_count(value):
    candidate = str(value or "").strip()
    if not candidate:
        return 0
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", candidate):
        return "invalidAlphabet"
    try:
        return len(base64url_decode(candidate))
    except Exception:
        return "decodeFailed"


def e2ee_public_key_normalization_checkpoint(stage, request_id, timing_started_at, operation_started_at, input_length=0, decoded_length=0, valid=None, **fields):
    active_http, active_websockets = companion_runtime_counts_unlocked()
    parts = [
        "[SOSYNC-E2EE-PUBLIC-KEY-NORMALIZE]",
        f"requestID={request_id}",
        f"correlationID={e2ee_session_correlation(request_id)}",
        f"stage={stage}",
        f"elapsedMs={elapsed_ms_since(timing_started_at or operation_started_at)}",
        f"segmentElapsedMs={elapsed_ms_since(operation_started_at)}",
        f"inputLength={input_length}",
        f"decodedLength={decoded_length}",
        f"thread={threading.get_ident()}",
        f"activeHTTP={active_http}",
        f"activeWebSockets={active_websockets}",
    ]
    if valid is not None:
        parts.append(f"valid={str(bool(valid)).lower()}")
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    print(" ".join(parts), flush=True)


def normalized_e2ee_public_key(value, request_id="unknown", timing_started_at=None, label="publicKey"):
    operation_started_at = time.monotonic()
    e2ee_public_key_normalization_checkpoint(
        f"{label}.inputAcquired",
        request_id,
        timing_started_at,
        operation_started_at,
        input_length=len(str(value or ""))
    )
    candidate = str(value or "").strip()
    e2ee_public_key_normalization_checkpoint(
        f"{label}.trimComplete",
        request_id,
        timing_started_at,
        operation_started_at,
        input_length=len(candidate)
    )
    if not candidate:
        e2ee_public_key_normalization_checkpoint(
            f"{label}.return",
            request_id,
            timing_started_at,
            operation_started_at,
            input_length=0,
            valid=False,
            reason="empty"
        )
        return ""

    cache_wait_started_at = time.monotonic()
    e2ee_public_key_normalization_checkpoint(
        f"{label}.cacheLookupLockWaitStart",
        request_id,
        timing_started_at,
        operation_started_at,
        input_length=len(candidate)
    )
    with timed_lock(E2EE_PUBLIC_KEY_NORMALIZATION_LOCK, "e2eePublicKeyNormalizationCache", request_id=request_id, log_threshold_ms=5):
        cache_wait_ms = elapsed_ms_since(cache_wait_started_at)
        e2ee_public_key_normalization_checkpoint(
            f"{label}.cacheLookupLockAcquired",
            request_id,
            timing_started_at,
            operation_started_at,
            input_length=len(candidate),
            lockWaitMs=cache_wait_ms
        )
        cached = E2EE_PUBLIC_KEY_NORMALIZATION_CACHE.get(candidate)
    e2ee_public_key_normalization_checkpoint(
        f"{label}.cacheLookupComplete",
        request_id,
        timing_started_at,
        operation_started_at,
        input_length=len(candidate),
        cacheHit=str(cached is not None).lower()
    )
    if cached is not None:
        e2ee_public_key_normalization_checkpoint(
            f"{label}.return",
            request_id,
            timing_started_at,
            operation_started_at,
            input_length=len(candidate),
            decoded_length=32,
            valid=True,
            reason="cacheHit"
        )
        return cached

    try:
        decode_started_at = time.monotonic()
        e2ee_public_key_normalization_checkpoint(
            f"{label}.base64DecodeStart",
            request_id,
            timing_started_at,
            operation_started_at,
            input_length=len(candidate)
        )
        raw = base64url_decode(candidate)
        e2ee_public_key_normalization_checkpoint(
            f"{label}.base64DecodeComplete",
            request_id,
            timing_started_at,
            decode_started_at,
            input_length=len(candidate),
            decoded_length=len(raw)
        )
        length_started_at = time.monotonic()
        if len(raw) != 32:
            e2ee_public_key_normalization_checkpoint(
                f"{label}.decodedLengthValidationComplete",
                request_id,
                timing_started_at,
                length_started_at,
                input_length=len(candidate),
                decoded_length=len(raw),
                valid=False
            )
            return ""
        e2ee_public_key_normalization_checkpoint(
            f"{label}.decodedLengthValidationComplete",
            request_id,
            timing_started_at,
            length_started_at,
            input_length=len(candidate),
            decoded_length=len(raw),
            valid=True
        )
        import_started_at = time.monotonic()
        e2ee_public_key_normalization_checkpoint(
            f"{label}.publicKeyImportStart",
            request_id,
            timing_started_at,
            operation_started_at,
            input_length=len(candidate),
            decoded_length=len(raw)
        )
        x25519.X25519PublicKey.from_public_bytes(raw)
        e2ee_public_key_normalization_checkpoint(
            f"{label}.publicKeyImportComplete",
            request_id,
            timing_started_at,
            import_started_at,
            input_length=len(candidate),
            decoded_length=len(raw),
            valid=True
        )
        encode_started_at = time.monotonic()
        e2ee_public_key_normalization_checkpoint(
            f"{label}.canonicalEncodeStart",
            request_id,
            timing_started_at,
            operation_started_at,
            input_length=len(candidate),
            decoded_length=len(raw)
        )
        normalized = base64url_encode(raw)
        e2ee_public_key_normalization_checkpoint(
            f"{label}.canonicalEncodeComplete",
            request_id,
            timing_started_at,
            encode_started_at,
            input_length=len(candidate),
            decoded_length=len(raw),
            valid=True
        )
        store_wait_started_at = time.monotonic()
        e2ee_public_key_normalization_checkpoint(
            f"{label}.cacheStoreLockWaitStart",
            request_id,
            timing_started_at,
            operation_started_at,
            input_length=len(candidate),
            decoded_length=len(raw)
        )
        with timed_lock(E2EE_PUBLIC_KEY_NORMALIZATION_LOCK, "e2eePublicKeyNormalizationCache", request_id=request_id, log_threshold_ms=5):
            store_wait_ms = elapsed_ms_since(store_wait_started_at)
            e2ee_public_key_normalization_checkpoint(
                f"{label}.cacheStoreLockAcquired",
                request_id,
                timing_started_at,
                operation_started_at,
                input_length=len(candidate),
                decoded_length=len(raw),
                lockWaitMs=store_wait_ms
            )
            E2EE_PUBLIC_KEY_NORMALIZATION_CACHE[candidate] = normalized
        e2ee_public_key_normalization_checkpoint(
            f"{label}.return",
            request_id,
            timing_started_at,
            operation_started_at,
            input_length=len(candidate),
            decoded_length=len(raw),
            valid=True,
            reason="normalized"
        )
        return normalized
    except (ValueError, TypeError):
        e2ee_public_key_normalization_checkpoint(
            f"{label}.return",
            request_id,
            timing_started_at,
            operation_started_at,
            input_length=len(candidate),
            valid=False,
            reason="decodeOrImportError"
        )
        return ""


def ingest_remote_pairing_from_supervisor_config():
    options = read_json_file(ADDON_OPTIONS_FILE, {})
    remote_pairing = options.get("remote_pairing") if isinstance(options, dict) else None
    if not isinstance(remote_pairing, dict):
        return

    identity = ensure_companion_identity()
    if remote_pairing.get("companion_id") != identity.get("companion_id") or is_expired_iso(remote_pairing.get("expires_at")):
        options.pop("remote_pairing", None)
        write_json_file_secure(ADDON_OPTIONS_FILE, options)
        return

    pairing_id = str(remote_pairing.get("pairing_id") or "")
    pairing_secret = str(remote_pairing.get("pairing_secret") or "")
    if not pairing_id or not pairing_secret:
        options.pop("remote_pairing", None)
        write_json_file_secure(ADDON_OPTIONS_FILE, options)
        return

    pairings = read_json_file(PAIRINGS_FILE, {})
    if pairing_id not in pairings:
        pairings[pairing_id] = {
            "pairing_id": pairing_id,
            "backend_challenge_id": str(remote_pairing.get("backend_challenge_id") or ""),
            "backend_nonce_hash": str(remote_pairing.get("backend_nonce_hash") or ""),
            "app_attest_key_id": str(remote_pairing.get("app_attest_key_id") or ""),
            "companion_id": str(remote_pairing.get("companion_id") or ""),
            "pairing_secret_hash": sha256_base64url(pairing_secret.encode("utf-8")),
            "created_at": iso_now(),
            "expires_at": str(remote_pairing.get("expires_at") or ""),
            "status": "pending"
        }
        write_json_file_secure(PAIRINGS_FILE, pairings)

    options.pop("remote_pairing", None)
    write_json_file_secure(ADDON_OPTIONS_FILE, options)


def read_consumed_packages():
    consumed = read_json_file(CONSUMED_PACKAGES_FILE, {})
    if not isinstance(consumed, dict):
        consumed = {}
    consumed.setdefault("package_ids", {})
    consumed.setdefault("connect_ids", {})
    return consumed


def read_backend_public_key():
    configured = os.environ.get("SOSYNC_BACKEND_SIGNING_PUBLIC_KEY", "").strip()
    if configured:
        return configured

    options = read_json_file(ADDON_OPTIONS_FILE, {})
    if isinstance(options, dict):
        return str(options.get("backend_signing_public_key") or "").strip()
    return ""


def verify_setup_package_envelope(envelope, backend_public_key):
    if envelope.get("encryption_alg") != SETUP_PACKAGE_ENCRYPTION_ALG:
        return False
    if envelope.get("signature_alg") != SETUP_PACKAGE_SIGNATURE_ALG:
        return False
    signature = envelope.get("backend_signature")
    if not signature:
        return False
    try:
        public_key = load_der_public_key(base64url_decode(backend_public_key))
        public_key.verify(base64url_decode(signature), canonical_bytes(envelope_canonical_payload(envelope)))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def decrypt_setup_package(envelope, encryption_private_key):
    suite = hpke_suite()
    private_key = suite.kem.deserialize_private_key(base64url_decode(encryption_private_key))
    context = suite.create_recipient_context(
        base64url_decode(envelope.get("encapsulated_key") or ""),
        private_key,
        info=SETUP_PACKAGE_INFO
    )
    plaintext = context.open(
        base64url_decode(envelope.get("ciphertext") or ""),
        aad=str(envelope.get("aad") or "").encode("utf-8")
    )
    return json.loads(plaintext.decode("utf-8"))


def hpke_suite():
    return CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.CHACHA20_POLY1305
    )


def sign_ed25519_base64url(private_key_base64url, payload):
    private_key = load_der_private_key(base64url_decode(private_key_base64url), password=None)
    return base64url_encode(private_key.sign(payload))


def canonical_bytes(value):
    return canonicalize(value).encode("utf-8")


def canonicalize(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) or isinstance(value, float):
        if isinstance(value, float) and not value.is_integer():
            return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return str(int(value))
    if isinstance(value, str):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        items = []
        for key in sorted(value.keys()):
            if value[key] is not None:
                items.append(f"{json.dumps(str(key), separators=(',', ':'), ensure_ascii=False)}:{canonicalize(value[key])}")
        return "{" + ",".join(items) + "}"
    raise ValueError("unsupported_json_value")


def receipt_canonical_payload(receipt):
    return {key: value for key, value in receipt.items() if key != "signature"}


def envelope_canonical_payload(envelope):
    return {key: value for key, value in envelope.items() if key != "backend_signature"}


HOME_CONFIG_SCHEMA_VERSION = 1
HOME_CONFIG_DOMAINS = {
    "dashboards",
    "flowMetadata",
    "energy",
    "presentation",
    "remoteAccessPolicy",
    "homeSetup",
    "extensions"
}
HOME_CONFIG_SECURITY_KEY_FRAGMENTS = (
    "secret",
    "token",
    "private_key",
    "privatekey",
    "app_attest",
    "attestation",
    "refresh_token",
    "access_token",
    "pairing_record",
    "secure_remote_route"
)


class HomeConfigurationPersistenceError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class HomeConfigurationIdentityMismatchError(Exception):
    def __init__(self, expected, actual):
        super().__init__("home_identity_mismatch")
        self.expected = expected
        self.actual = actual


class HomeConfigurationConflictError(Exception):
    def __init__(self, current_revision, current_domain_revision, attempted):
        super().__init__("revision_conflict")
        self.current_revision = current_revision
        self.current_domain_revision = current_domain_revision
        self.attempted = attempted


class HomeConfigurationValidationError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def log_home_config(stage, **fields):
    rendered = " ".join(f"{key}={value}" for key, value in fields.items())
    suffix = f" {rendered}" if rendered else ""
    print(f"[SOSYNC-HOME-CONFIG] {stage}{suffix}", flush=True)


def is_valid_home_config_identity(value):
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if len(stripped) < 3 or len(stripped) > 512:
        return False
    return not any(ord(character) < 32 for character in stripped)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def default_home_configuration(home_identity):
    now = utc_now_iso()
    return {
        "schemaVersion": HOME_CONFIG_SCHEMA_VERSION,
        "homeIdentity": home_identity,
        "revision": 0,
        "domainRevisions": {domain: 0 for domain in sorted(HOME_CONFIG_DOMAINS)},
        "updatedAt": now,
        "updatedByDeviceIDHash": None,
        "homeSetup": "notStarted",
        "dashboards": [],
        "dashboardOrder": [],
        "dashboardWidgets": [],
        "flowMetadata": {},
        "energy": {},
        "presentation": {},
        "remoteAccessPolicy": {
            "enabled": True,
            "updatedAt": None
        },
        "extensions": {}
    }


def home_config_domain_revision_summary(document):
    revisions = document.get("domainRevisions", {}) if isinstance(document, dict) else {}
    return ",".join(f"{domain}:{revisions.get(domain, 'missing')}" for domain in sorted(HOME_CONFIG_DOMAINS))


def validate_json_compatible(value, path="root"):
    if value is None or isinstance(value, bool) or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not value == value or value in (float("inf"), float("-inf")):
            raise HomeConfigurationValidationError("invalid_json_value")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_json_compatible(item, f"{path}.{index}")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise HomeConfigurationValidationError("invalid_json_key")
            normalized = key.lower()
            if any(fragment in normalized for fragment in HOME_CONFIG_SECURITY_KEY_FRAGMENTS):
                raise HomeConfigurationValidationError("prohibited_security_field")
            validate_json_compatible(item, f"{path}.{key}")
        return
    raise HomeConfigurationValidationError("invalid_json_value")


def validate_home_configuration_document(document):
    if not isinstance(document, dict):
        raise HomeConfigurationPersistenceError("documentNotObject")
    if document.get("schemaVersion") != HOME_CONFIG_SCHEMA_VERSION:
        raise HomeConfigurationPersistenceError("unsupportedSchemaVersion")
    if not is_valid_home_config_identity(document.get("homeIdentity")):
        raise HomeConfigurationPersistenceError("invalidHomeIdentity")
    if not isinstance(document.get("revision"), int) or document.get("revision") < 0:
        raise HomeConfigurationPersistenceError("invalidRevision")
    domain_revisions = document.get("domainRevisions")
    if not isinstance(domain_revisions, dict):
        raise HomeConfigurationPersistenceError("invalidDomainRevisions")
    for domain in HOME_CONFIG_DOMAINS:
        value = domain_revisions.get(domain)
        if not isinstance(value, int) or value < 0:
            raise HomeConfigurationPersistenceError("invalidDomainRevision")
    validate_json_compatible(document)
    return document


def read_home_configuration_document():
    started_at = time.monotonic()
    try:
        with open(HOME_CONFIGURATION_FILE, "r", encoding="utf-8") as file:
            document = json.load(file)
        validate_home_configuration_document(document)
        log_home_config(
            "loadCompleted",
            source="disk",
            revision=document.get("revision", "unknown"),
            elapsedMs=elapsed_ms_since(started_at)
        )
        return document
    except FileNotFoundError:
        log_home_config("loadCompleted", source="disk", result="absent", elapsedMs=elapsed_ms_since(started_at))
        return None
    except json.JSONDecodeError as error:
        raise HomeConfigurationPersistenceError(f"corruptJSON:{type(error).__name__}")


def write_home_configuration_document(document):
    validate_home_configuration_document(document)
    os.makedirs(os.path.dirname(HOME_CONFIGURATION_FILE), exist_ok=True)
    temporary_file = f"{HOME_CONFIGURATION_FILE}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp"
    started_at = time.monotonic()
    with timed_lock(HOME_CONFIGURATION_WRITE_LOCK, "homeConfigWrite", log_threshold_ms=5):
        try:
            with open(temporary_file, "w", encoding="utf-8") as file:
                json.dump(document, file, separators=(",", ":"))
                file.flush()
                os.fsync(file.fileno())
            os.chmod(temporary_file, 0o600)
            os.replace(temporary_file, HOME_CONFIGURATION_FILE)
            os.chmod(HOME_CONFIGURATION_FILE, 0o600)
            try:
                directory_fd = os.open(os.path.dirname(HOME_CONFIGURATION_FILE), os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        except OSError as error:
            raise HomeConfigurationPersistenceError(type(error).__name__)
        finally:
            try:
                if os.path.exists(temporary_file):
                    os.remove(temporary_file)
            except OSError:
                pass
    log_home_config(
        "persistenceReadback",
        event="writeCompleted",
        revision=document.get("revision", "unknown"),
        elapsedMs=elapsed_ms_since(started_at)
    )
    readback = read_home_configuration_document()
    if readback != document:
        raise HomeConfigurationPersistenceError("readbackMismatch")
    log_home_config(
        "persistenceReadback",
        event="verified",
        revision=document.get("revision", "unknown"),
        domainRevisions=home_config_domain_revision_summary(document)
    )


def create_home_configuration_if_absent(home_identity):
    existing = read_home_configuration_document()
    if existing is not None:
        existing_home_identity = existing.get("homeIdentity")
        if existing_home_identity != home_identity:
            raise HomeConfigurationIdentityMismatchError(home_identity, str(existing_home_identity or ""))
        return copy_json_value(existing), False
    document = default_home_configuration(home_identity)
    write_home_configuration_document(document)
    return copy_json_value(document), True


def apply_home_configuration_patch(document, domain, patch):
    validate_json_compatible(patch)
    if domain == "dashboards":
        if not isinstance(patch, dict):
            raise HomeConfigurationValidationError("invalid_dashboard_patch")
        dashboards = patch.get("dashboards", document.get("dashboards", []))
        dashboard_order = patch.get("dashboardOrder", document.get("dashboardOrder", []))
        dashboard_widgets = patch.get("dashboardWidgets", document.get("dashboardWidgets", []))
        if not isinstance(dashboards, list) or not isinstance(dashboard_order, list) or not isinstance(dashboard_widgets, list):
            raise HomeConfigurationValidationError("invalid_dashboard_patch")
        document["dashboards"] = dashboards
        document["dashboardOrder"] = dashboard_order
        document["dashboardWidgets"] = dashboard_widgets
    elif domain == "homeSetup":
        state = patch.get("state") if isinstance(patch, dict) else patch
        if state not in ("notStarted", "structureConfigured", "dashboardsConfigured", "complete"):
            raise HomeConfigurationValidationError("invalid_home_setup_state")
        document["homeSetup"] = state
    elif domain == "remoteAccessPolicy":
        if not isinstance(patch, dict) or not isinstance(patch.get("enabled"), bool):
            raise HomeConfigurationValidationError("invalid_remote_access_policy")
        document["remoteAccessPolicy"] = {
            "enabled": patch["enabled"],
            "updatedAt": patch.get("updatedAt") if isinstance(patch.get("updatedAt"), str) else utc_now_iso()
        }
    elif domain in ("flowMetadata", "energy", "presentation"):
        if not isinstance(patch, dict):
            raise HomeConfigurationValidationError(f"invalid_{domain}_patch")
        document[domain] = patch
    elif domain == "extensions":
        if not isinstance(patch, dict):
            raise HomeConfigurationValidationError("invalid_extensions_patch")
        document["extensions"] = patch
    else:
        raise HomeConfigurationValidationError("invalid_domain")


def mutate_home_configuration(home_identity, domain, base_domain_revision, patch, updated_by_device_hash=None):
    with timed_lock(HOME_CONFIGURATION_WRITE_LOCK, "homeConfigMutation", log_threshold_ms=5):
        document = read_home_configuration_document()
        if document is None:
            raise HomeConfigurationPersistenceError("notFound")
        existing_home_identity = document.get("homeIdentity")
        if existing_home_identity != home_identity:
            raise HomeConfigurationIdentityMismatchError(home_identity, str(existing_home_identity or ""))
        current_domain_revision = document.get("domainRevisions", {}).get(domain)
        if current_domain_revision != base_domain_revision:
            raise HomeConfigurationConflictError(
                current_revision=document.get("revision", 0),
                current_domain_revision=current_domain_revision,
                attempted=base_domain_revision
            )
        next_document = copy_json_value(document)
        apply_home_configuration_patch(next_document, domain, patch)
        next_document["revision"] = int(document.get("revision", 0)) + 1
        next_document["domainRevisions"][domain] = int(current_domain_revision) + 1
        next_document["updatedAt"] = utc_now_iso()
        next_document["updatedByDeviceIDHash"] = updated_by_device_hash
        write_home_configuration_document(next_document)
        return copy_json_value(next_document)


def read_json_file(path, default, cache_ttl_seconds=0):
    now = time.monotonic()
    if cache_ttl_seconds > 0:
        cache_started_at = time.monotonic()
        with timed_lock(COMPANION_CACHE_LOCK, "companionCache", log_threshold_ms=10):
            cached = COMPANION_JSON_READ_CACHE.get(path)
            if cached and cached.get("expires_at", 0) > now:
                if path == SECURE_REMOTE_BINDING_FILE:
                    note_secure_remote_binding_stat("cacheHits")
                else:
                    companion_perf_log_if_slow(
                        "fileReadCacheHit",
                        elapsed_ms_since(cache_started_at),
                        threshold_ms=5,
                        path=os.path.basename(path)
                    )
                return copy_json_value(cached.get("value"))
    started_at = time.monotonic()
    try:
        with open(path, "r", encoding="utf-8") as file:
            value = json.load(file)
            try:
                byte_count = os.path.getsize(path)
            except OSError:
                byte_count = "unknown"
            read_elapsed_ms = elapsed_ms_since(started_at)
            if path == SECURE_REMOTE_BINDING_FILE:
                note_secure_remote_binding_stat("diskReads")
                companion_perf_log_if_slow("fileReadCompleted", read_elapsed_ms, threshold_ms=25, path=os.path.basename(path), bytes=byte_count)
            else:
                companion_perf_log("fileReadCompleted", path=os.path.basename(path), elapsedMs=read_elapsed_ms, bytes=byte_count)
            if cache_ttl_seconds > 0:
                with timed_lock(COMPANION_CACHE_LOCK, "companionCache", log_threshold_ms=10):
                    COMPANION_JSON_READ_CACHE[path] = {
                        "expires_at": time.monotonic() + cache_ttl_seconds,
                        "value": copy_json_value(value)
                    }
            return value
    except (FileNotFoundError, json.JSONDecodeError):
        companion_perf_log("fileReadDefaulted", path=os.path.basename(path), elapsedMs=elapsed_ms_since(started_at))
        return default


def write_json_file_secure(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary_file = f"{path}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp"
    started_at = time.monotonic()
    with timed_lock(COMPANION_JSON_WRITE_LOCK, "jsonWrite", log_threshold_ms=5):
        try:
            with open(temporary_file, "w", encoding="utf-8") as file:
                json.dump(payload, file, separators=(",", ":"))
            os.chmod(temporary_file, 0o600)
            os.replace(temporary_file, path)
            os.chmod(path, 0o600)
        finally:
            try:
                if os.path.exists(temporary_file):
                    os.remove(temporary_file)
            except OSError:
                pass
    with timed_lock(COMPANION_CACHE_LOCK, "companionCache", log_threshold_ms=10):
        COMPANION_JSON_READ_CACHE.pop(path, None)
    companion_perf_log("fileWriteCompleted", path=os.path.basename(path), elapsedMs=elapsed_ms_since(started_at))


def read_secure_remote_binding():
    note_secure_remote_binding_stat("bindingChecks")
    return read_json_file(SECURE_REMOTE_BINDING_FILE, {}, cache_ttl_seconds=0.25)


def is_opaque_secure_remote_id(value, prefix=None):
    text = str(value or "").strip()
    if len(text) < 16 or len(text) > 160:
        return False
    if prefix and not text.startswith(prefix):
        return False
    if not re.match(r"^[A-Za-z0-9_-]+$", text):
        return False
    lowered = text.lower()
    disallowed = ["@", ".", ":", "/", "\\", "home", "user", "admin", "192", "168", "10-", "172", "local", "duck", "tail", "tsnet", "ha-"]
    return not any(fragment in lowered for fragment in disallowed)


def is_valid_secure_remote_binding_request(data):
    if not isinstance(data, dict):
        return False
    if int(data.get("protocol_version") or 0) != 1:
        return False
    if not is_opaque_secure_remote_id(data.get("route_id"), "r_"):
        return False
    if not is_opaque_secure_remote_id(data.get("tunnel_binding_id"), "tun_"):
        return False
    if data.get("origin_access_token") is not None and not is_opaque_secure_remote_id(data.get("origin_access_token"), "orig_"):
        return False
    required_fingerprints = [
        "home_reference",
        "device_reference",
        "device_public_key_fingerprint",
        "companion_public_key_fingerprint",
        "companion_identity_fingerprint"
    ]
    for key in required_fingerprints:
        value = str(data.get(key) or "").strip()
        if not value or len(value) > 256:
            return False
    try:
        credential_version = int(data.get("credential_version") or 0)
    except (TypeError, ValueError):
        return False
    return credential_version >= 1


def make_secure_remote_binding(data):
    now = iso_now()
    return {
        "protocol_version": 1,
        "route_id": str(data.get("route_id")).strip(),
        "tunnel_binding_id": str(data.get("tunnel_binding_id")).strip(),
        "home_reference": str(data.get("home_reference")).strip(),
        "device_reference": str(data.get("device_reference")).strip(),
        "device_public_key_fingerprint": str(data.get("device_public_key_fingerprint")).strip(),
        "companion_public_key_fingerprint": str(data.get("companion_public_key_fingerprint")).strip(),
        "companion_identity_fingerprint": str(data.get("companion_identity_fingerprint")).strip(),
        "credential_version": int(data.get("credential_version") or 1),
        "origin_access_token": str(data.get("origin_access_token") or "").strip(),
        "public_hostname": str(data.get("public_hostname") or "").strip(),
        "status": "control_plane_bound",
        "tunnel_configured": False,
        "tunnel_state": "pending",
        "created_at": now,
        "updated_at": now,
        "revoked_at": None
    }


def migrate_e2ee_pairing_home_for_secure_remote_binding_if_needed(data):
    target_home_id = str(data.get("home_reference") or "").strip()
    device_id = str(data.get("device_reference") or "").strip()
    device_public_key_fingerprint = str(data.get("device_public_key_fingerprint") or "").strip()
    companion_public_key_fingerprint = str(data.get("companion_public_key_fingerprint") or "").strip()
    companion_identity_fingerprint = str(data.get("companion_identity_fingerprint") or "").strip()
    pairings = read_e2ee_pairings()
    devices = pairings.get("devices", {})
    record = devices.get(device_id)
    identity = ensure_e2ee_identity()
    companion_identity = ensure_companion_identity()
    local_server_identity_available = bool(read_existing_server_id())
    lookup_found = isinstance(record, dict)
    status_active = lookup_found and record.get("status") == "active"
    device_id_matches = lookup_found and record.get("device_id") == device_id
    device_public_key = str(record.get("device_public_key") or "") if lookup_found else ""
    client_key_matches = lookup_found and sha256_base64url(device_public_key.encode("utf-8")) == device_public_key_fingerprint
    companion_key_matches = lookup_found and sha256_base64url(str(record.get("companion_public_key") or "").encode("utf-8")) == companion_public_key_fingerprint
    companion_identity_matches = companion_identity_fingerprint == sha256_base64url(
        f"{E2EE_PROTOCOL_VERSION}|{identity.get('public_key')}|{identity.get('key_version')}".encode("utf-8")
    )
    home_binding_matches = lookup_found and record.get("home_id") == target_home_id
    legacy_home_mismatch = lookup_found and status_active and device_id_matches and client_key_matches and companion_key_matches and companion_identity_matches and not home_binding_matches
    decision = "noop" if home_binding_matches else ("migrate" if legacy_home_mismatch else "reject")
    print(
        "[SOSYNC-E2EE-MIGRATION] "
        "stage=companionPairingHomeMigrationEligibility "
        f"lookupFound={str(lookup_found).lower()} "
        f"statusActive={str(status_active).lower()} "
        f"deviceIDMatches={str(device_id_matches).lower()} "
        f"clientKeyMatches={str(client_key_matches).lower()} "
        f"companionPublicKeyMatches={str(companion_key_matches).lower()} "
        f"companionIdentityMatches={str(companion_identity_matches).lower()} "
        f"homeBindingMatches={str(home_binding_matches).lower()} "
        f"trustedLocalServerIdentityAvailable={str(local_server_identity_available).lower()} "
        f"decision={decision}",
        flush=True
    )
    if not lookup_found:
        print("[SOSYNC-E2EE-MIGRATION] stage=companionPairingHomeMigrationSkipped reason=missingPairing", flush=True)
        return {"accepted": True, "result": "noop", "reason": "missingPairing"}
    if not status_active:
        print("[SOSYNC-E2EE-MIGRATION] stage=companionPairingHomeMigrationSkipped reason=inactivePairing", flush=True)
        return {"accepted": False, "result": "rejected", "reason": "inactivePairing"}
    if not device_id_matches:
        print("[SOSYNC-E2EE-MIGRATION] stage=companionPairingHomeMigrationSkipped reason=deviceMismatch", flush=True)
        return {"accepted": False, "result": "rejected", "reason": "deviceMismatch"}
    if not client_key_matches:
        print("[SOSYNC-E2EE-MIGRATION] stage=companionPairingHomeMigrationSkipped reason=publicKeyMismatch", flush=True)
        return {"accepted": False, "result": "rejected", "reason": "publicKeyMismatch"}
    if not companion_key_matches or not companion_identity_matches:
        print("[SOSYNC-E2EE-MIGRATION] stage=companionPairingHomeMigrationSkipped reason=companionIdentityMismatch", flush=True)
        return {"accepted": False, "result": "rejected", "reason": "companionIdentityMismatch"}
    if legacy_home_mismatch and not local_server_identity_available:
        print("[SOSYNC-E2EE-MIGRATION] stage=companionPairingHomeMigrationSkipped reason=missingTrustedLocalServerIdentity", flush=True)
        return {"accepted": False, "result": "rejected", "reason": "missingTrustedLocalServerIdentity"}
    if home_binding_matches:
        print("[SOSYNC-E2EE-MIGRATION] stage=companionPairingHomeMigrationSkipped reason=alreadyCanonical", flush=True)
        return {"accepted": True, "result": "noop", "reason": "alreadyCanonical"}

    old_home_id = str(record.get("home_id") or "")
    migrated = dict(record)
    migrated["home_id"] = target_home_id
    devices[device_id] = migrated
    pairings["devices"] = devices
    write_json_file_secure(E2EE_PAIRINGS_FILE, pairings)
    readback = read_e2ee_pairings().get("devices", {}).get(device_id)
    if not isinstance(readback, dict) or readback != migrated:
        print("[SOSYNC-E2EE-MIGRATION] stage=companionPairingHomeMigrationSkipped reason=readbackMismatch", flush=True)
        return {"accepted": False, "result": "rejected", "reason": "readbackMismatch"}
    print(
        "[SOSYNC-E2EE-MIGRATION] "
        "stage=companionPairingHomeMigrated "
        f"oldHomeHash={safe_fingerprint(old_home_id)} "
        f"newHomeHash={safe_fingerprint(target_home_id)}",
        flush=True
    )
    return {"accepted": True, "result": "migrated", "reason": "legacyHomeIdentity"}


def secure_remote_public_status(binding=None):
    binding = binding if isinstance(binding, dict) else read_secure_remote_binding()
    has_route = bool(binding.get("route_id")) and binding.get("status") != "revoked"
    has_credential = bool(read_secure_text_file(secure_remote_tunnel_token_file()))
    cloudflared_running = is_secure_remote_tunnel_running()
    connector_status = secure_remote_connector_runtime_status(cloudflared_running)
    if not has_route:
        tunnel_state = "notConfigured"
        tunnel_configured = False
    elif connector_status["connector_healthy"]:
        tunnel_state = "active"
        tunnel_configured = True
    elif cloudflared_running:
        tunnel_state = "connectorStarting"
        tunnel_configured = False
    elif binding.get("tunnel_state") == "failed":
        tunnel_state = "failed"
        tunnel_configured = False
    elif has_credential:
        tunnel_state = "credentialInstalled"
        tunnel_configured = False
    else:
        tunnel_state = "notConfigured"
        tunnel_configured = False
    runtime = cloudflared_runtime_status()
    connector_identity = secure_remote_current_process_connector_identity(cloudflared_running)
    return {
        "protocol_version": 1,
        "configured": has_route,
        "companion_version": SOSYNC_COMPANION_VERSION,
        "build_marker": SOSYNC_COMPANION_BUILD,
        "status": binding.get("status") or "unconfigured",
        "route_id_fingerprint": safe_fingerprint(binding.get("route_id")),
        "tunnel_binding_fingerprint": safe_fingerprint(binding.get("tunnel_binding_id")),
        "credential_version": int(binding.get("credential_version") or 0),
        "tunnel_configured": tunnel_configured,
        "tunnel_state": tunnel_state,
        "cloudflared_available": runtime["available"],
        "cloudflared_version": runtime["version"],
        "failure_stage": binding.get("failure_stage"),
        "failure_reason": binding.get("failure_reason"),
        "last_healthy_at": binding.get("last_healthy_at"),
        "cloudflared_running": cloudflared_running,
        "cloudflared_process_alive": cloudflared_running,
        "connector_state": connector_status["connector_state"],
        "connector_healthy": connector_status["connector_healthy"],
        "connector_connection_count": connector_status["connector_connection_count"],
        "last_connected_at": binding.get("last_connected_at"),
        "last_disconnected_at": binding.get("last_disconnected_at"),
        "last_error_class": connector_status["last_error_class"],
        "cloudflare_connector_tunnel_id_hash": connector_identity["cloudflare_connector_tunnel_id_hash"],
        "connector_tunnel_identity_available": connector_identity["connector_tunnel_identity_available"],
        "connector_tunnel_identity_failure": connector_identity["connector_tunnel_identity_failure"],
        "connector_tunnel_token_format": connector_identity["connector_tunnel_token_format"],
        "updated_at": binding.get("updated_at"),
        "revoked_at": binding.get("revoked_at")
    }


def secure_remote_identity_snapshot_status(binding=None):
    started_at = time.monotonic()
    binding = binding if isinstance(binding, dict) else read_secure_remote_binding()
    has_route = bool(binding.get("route_id")) and binding.get("status") != "revoked"
    cloudflared_running = is_secure_remote_tunnel_running()
    cached_connector = (
        dict(SECURE_REMOTE_CONNECTOR_STATUS_CACHE)
        if SECURE_REMOTE_CONNECTOR_STATUS_CACHE and SECURE_REMOTE_CONNECTOR_STATUS_CACHE_EXPIRES_AT > time.monotonic()
        else None
    )
    if not has_route:
        tunnel_state = "notConfigured"
        snapshot_source = "bindingNoRoute"
    elif cached_connector and cached_connector.get("connector_healthy"):
        tunnel_state = "active"
        snapshot_source = "cachedConnector"
    elif cloudflared_running:
        tunnel_state = binding.get("tunnel_state") or "connectorStarting"
        snapshot_source = "processSnapshot"
    elif binding.get("tunnel_state") == "failed":
        tunnel_state = "failed"
        snapshot_source = "bindingFailure"
    elif binding.get("tunnel_configured"):
        tunnel_state = binding.get("tunnel_state") or "credentialInstalled"
        snapshot_source = "bindingSnapshot"
    else:
        tunnel_state = "notConfigured"
        snapshot_source = "bindingSnapshot"
    companion_perf_log(
        "identitySecureRemoteStatusSnapshot",
        elapsedMs=elapsed_ms_since(started_at),
        snapshotSource=snapshot_source,
        cloudflaredRunning=str(bool(cloudflared_running)).lower()
    )
    return {
        "tunnel_state": tunnel_state,
        "cloudflared_running": cloudflared_running,
        "snapshot_source": snapshot_source
    }


def secure_remote_connector_runtime_status(cloudflared_running):
    global SECURE_REMOTE_CONNECTOR_STATUS_CACHE
    global SECURE_REMOTE_CONNECTOR_STATUS_CACHE_EXPIRES_AT
    if not cloudflared_running:
        return {
            "connector_state": "notRunning",
            "connector_healthy": False,
            "connector_connection_count": 0,
            "last_error_class": "processNotRunning"
        }
    now = time.monotonic()
    if SECURE_REMOTE_CONNECTOR_STATUS_CACHE and SECURE_REMOTE_CONNECTOR_STATUS_CACHE_EXPIRES_AT > now:
        companion_perf_log("connectorStatusCacheHit")
        return dict(SECURE_REMOTE_CONNECTOR_STATUS_CACHE)
    started_at = time.monotonic()
    excerpt = read_secure_remote_tunnel_stderr_excerpt(limit=4096)
    lower = excerpt.lower()
    connected_patterns = [
        "registered tunnel connection",
        "connection registered",
        "registered connection",
        "connected to"
    ]
    disconnected_patterns = [
        "failed to serve tunnel connection",
        "connection closed",
        "disconnected",
        "unable to establish",
        "error"
    ]
    connection_count = sum(lower.count(pattern) for pattern in connected_patterns)
    has_connected = connection_count > 0
    has_disconnected = any(pattern in lower for pattern in disconnected_patterns)
    if "1033" in lower:
        error_class = "tunnelConnectorUnavailable"
    elif "certificate" in lower or "cert" in lower:
        error_class = "tlsOrCertificate"
    elif "unauthorized" in lower or "permission" in lower:
        error_class = "authorization"
    elif has_disconnected and not has_connected:
        error_class = "connectorDisconnected"
    else:
        error_class = "none"
    status = {
        "connector_state": "connected" if has_connected else "starting",
        "connector_healthy": has_connected,
        "connector_connection_count": connection_count,
        "last_error_class": error_class
    }
    SECURE_REMOTE_CONNECTOR_STATUS_CACHE = dict(status)
    SECURE_REMOTE_CONNECTOR_STATUS_CACHE_EXPIRES_AT = time.monotonic() + 0.25
    companion_perf_log("connectorStatusComputed", elapsedMs=elapsed_ms_since(started_at), healthy=status["connector_healthy"])
    return status


def wait_for_secure_remote_connector_health(deadline, process_locked=False):
    while time.time() < deadline:
        if process_locked:
            process_running = SECURE_REMOTE_TUNNEL_PROCESS is not None and SECURE_REMOTE_TUNNEL_PROCESS.poll() is None
        else:
            process_running = is_secure_remote_tunnel_running()
        status = secure_remote_connector_runtime_status(process_running)
        if not process_running or status["connector_healthy"]:
            return status
        time.sleep(0.2)
    if process_locked:
        process_running = SECURE_REMOTE_TUNNEL_PROCESS is not None and SECURE_REMOTE_TUNNEL_PROCESS.poll() is None
    else:
        process_running = is_secure_remote_tunnel_running()
    return secure_remote_connector_runtime_status(process_running)


def secure_remote_current_process_connector_identity(cloudflared_running):
    if not cloudflared_running:
        return {
            "cloudflare_connector_tunnel_id_hash": "none",
            "connector_tunnel_identity_available": False,
            "connector_tunnel_identity_failure": "processNotRunning",
            "connector_tunnel_token_format": "unknown"
        }
    identity = SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY if isinstance(SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY, dict) else None
    if not identity:
        return {
            "cloudflare_connector_tunnel_id_hash": "none",
            "connector_tunnel_identity_available": False,
            "connector_tunnel_identity_failure": "identityNotCaptured",
            "connector_tunnel_token_format": "unknown"
        }
    connector_hash = str(identity.get("cloudflare_connector_tunnel_id_hash") or "none").strip() or "none"
    available = bool(identity.get("available"))
    return {
        "cloudflare_connector_tunnel_id_hash": connector_hash,
        "connector_tunnel_identity_available": available,
        "connector_tunnel_identity_failure": identity.get("failure") or (None if available else "identityUnavailable"),
        "connector_tunnel_token_format": identity.get("connector_token_format") or "unknown"
    }


def cloudflared_runtime_status():
    global CLOUDFLARED_RUNTIME_STATUS_CACHE
    global CLOUDFLARED_RUNTIME_STATUS_CACHE_EXPIRES_AT
    now = time.monotonic()
    if CLOUDFLARED_RUNTIME_STATUS_CACHE and CLOUDFLARED_RUNTIME_STATUS_CACHE_EXPIRES_AT > now:
        companion_perf_log("cloudflaredRuntimeCacheHit")
        return dict(CLOUDFLARED_RUNTIME_STATUS_CACHE)
    started_at = time.monotonic()
    cloudflared_binary = os.environ.get("SOSYNC_CLOUDFLARED_BIN", "cloudflared")
    resolved = shutil.which(cloudflared_binary)
    if not resolved:
        status = {"available": False, "path": None, "version": None}
        CLOUDFLARED_RUNTIME_STATUS_CACHE = dict(status)
        CLOUDFLARED_RUNTIME_STATUS_CACHE_EXPIRES_AT = time.monotonic() + 10
        companion_perf_log("cloudflaredRuntimeComputed", elapsedMs=elapsed_ms_since(started_at), available=False)
        return status
    version = None
    try:
        subprocess_started_at = time.monotonic()
        result = subprocess.run([resolved, "--version"], capture_output=True, text=True, timeout=3)
        companion_perf_log("subprocessCompleted", command="cloudflaredVersion", elapsedMs=elapsed_ms_since(subprocess_started_at))
        if result.returncode == 0:
            version = re.sub(r"\s+", " ", result.stdout.strip())[:160]
    except Exception:
        version = None
    status = {"available": True, "path": resolved, "version": version}
    CLOUDFLARED_RUNTIME_STATUS_CACHE = dict(status)
    CLOUDFLARED_RUNTIME_STATUS_CACHE_EXPIRES_AT = time.monotonic() + 60
    companion_perf_log("cloudflaredRuntimeComputed", elapsedMs=elapsed_ms_since(started_at), available=True)
    return status


def write_secure_text_file(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary_file = f"{path}.tmp"
    started_at = time.monotonic()
    with open(temporary_file, "w", encoding="utf-8") as file:
        file.write(value)
    os.chmod(temporary_file, 0o600)
    os.replace(temporary_file, path)
    os.chmod(path, 0o600)
    companion_perf_log("fileWriteCompleted", path=os.path.basename(path), elapsedMs=elapsed_ms_since(started_at))


def read_secure_text_file(path):
    started_at = time.monotonic()
    try:
        with open(path, "r", encoding="utf-8") as file:
            value = file.read().strip()
            companion_perf_log("fileReadCompleted", path=os.path.basename(path), elapsedMs=elapsed_ms_since(started_at), bytes=len(value))
            return value
    except OSError:
        companion_perf_log("fileReadDefaulted", path=os.path.basename(path), elapsedMs=elapsed_ms_since(started_at))
        return ""


def remove_secure_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError:
        return


def secure_remote_tunnel_token_file():
    return os.path.join(os.path.dirname(SECURE_REMOTE_BINDING_FILE), "sosync_secure_remote_tunnel_token")


def secure_remote_tunnel_stderr_file():
    return os.path.join(os.path.dirname(SECURE_REMOTE_BINDING_FILE), "sosync_secure_remote_cloudflared_stderr.log")


def read_secure_remote_tunnel_stderr_excerpt(limit=1024):
    path = secure_remote_tunnel_stderr_file()
    started_at = time.monotonic()
    try:
        with open(path, "rb") as file:
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(max(0, size - limit), os.SEEK_SET)
            value = file.read(limit).decode("utf-8", errors="replace")
            companion_perf_log_if_slow("fileReadCompleted", elapsed_ms_since(started_at), path=os.path.basename(path), bytes=len(value))
            return value
    except OSError:
        companion_perf_log_if_slow("fileReadDefaulted", elapsed_ms_since(started_at), path=os.path.basename(path))
        return ""


def sanitized_secure_remote_tunnel_stderr(value, token):
    text = str(value or "")
    secret = str(token or "")
    if secret:
        text = text.replace(secret, "[redacted]")
        if len(secret) > 12:
            text = text.replace(secret[:12], "[redacted]")
            text = text.replace(secret[-12:], "[redacted]")
        for component in secret.split("-"):
            if len(component) >= 8:
                text = text.replace(component, "[redacted]")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:300] if text else "empty"


def is_secure_remote_tunnel_running():
    global SECURE_REMOTE_TUNNEL_PROCESS
    with timed_lock(SECURE_REMOTE_TUNNEL_LOCK, "secureRemoteTunnel", log_threshold_ms=5):
        return SECURE_REMOTE_TUNNEL_PROCESS is not None and SECURE_REMOTE_TUNNEL_PROCESS.poll() is None


def start_secure_remote_tunnel(binding=None):
    global SECURE_REMOTE_TUNNEL_PROCESS
    global SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY
    global SECURE_REMOTE_TUNNEL_STARTING
    binding = binding if isinstance(binding, dict) else read_secure_remote_binding()
    token = read_secure_text_file(secure_remote_tunnel_token_file())
    if not token or not binding.get("route_id") or binding.get("status") == "revoked":
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelProcessNotStarted route={safe_fingerprint(binding.get('route_id'))} reason=missingCredentialOrRoute",
            flush=True
        )
        return {"running": False, "stage": "credential", "reason": "missingCredentialOrRoute"}
    with timed_lock(SECURE_REMOTE_TUNNEL_LOCK, "secureRemoteTunnel", log_threshold_ms=5):
        if SECURE_REMOTE_TUNNEL_PROCESS is not None and SECURE_REMOTE_TUNNEL_PROCESS.poll() is None:
            process_identity = SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY or {"available": False, "failure": "identityNotCaptured", "cloudflare_connector_tunnel_id_hash": "none"}
            reused_running = True
        elif SECURE_REMOTE_TUNNEL_STARTING:
            companion_perf_log("tunnelStartJoined", route=safe_fingerprint(binding.get("route_id")))
            return {"running": False, "stage": "starting", "reason": "startInProgress"}
        else:
            SECURE_REMOTE_TUNNEL_STARTING = True
            process_identity = None
            reused_running = False
    if reused_running:
        connector_status = secure_remote_connector_runtime_status(True)
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelProcessConfirmed route={safe_fingerprint(binding.get('route_id'))} running=true reused=true connectorState={connector_status['connector_state']} connectorHealthy={connector_status['connector_healthy']} connectorConnectionCount={connector_status['connector_connection_count']} lastErrorClass={connector_status['last_error_class']}",
            flush=True
        )
        print(
            f"[SOSYNC-SECURE-REMOTE-IDENTITY] cloudflareConnectorTunnelIDHash={process_identity.get('cloudflare_connector_tunnel_id_hash')} connectorTunnelIdentityAvailable={str(bool(process_identity.get('available'))).lower()} connectorTunnelIdentityFailure={process_identity.get('failure') or 'none'} connectorTokenFormat={process_identity.get('connector_token_format') or 'unknown'} tunnelManagementMode=remoteManaged effectiveIngressSource=cloudflareApi cloudflaredRunning=true",
            flush=True
        )
        return {"running": True, "connector_healthy": connector_status["connector_healthy"], "stage": "connectorHealthy" if connector_status["connector_healthy"] else "connectorStarting", "reason": None if connector_status["connector_healthy"] else connector_status["last_error_class"]}
    cloudflared_binary = os.environ.get("SOSYNC_CLOUDFLARED_BIN", "cloudflared")
    cloudflared_path = shutil.which(cloudflared_binary)
    if cloudflared_path is None:
        with timed_lock(SECURE_REMOTE_TUNNEL_LOCK, "secureRemoteTunnel", log_threshold_ms=5):
            SECURE_REMOTE_TUNNEL_STARTING = False
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelProcessFailed route={safe_fingerprint(binding.get('route_id'))} stage=binaryLookup reason=cloudflaredMissing",
            flush=True
        )
        return {"running": False, "stage": "binaryLookup", "reason": "cloudflaredMissing"}
    print(
        f"[SOSYNC-SECURE-REMOTE-COMPANION] cloudflaredBinaryResolved route={safe_fingerprint(binding.get('route_id'))} path={cloudflared_path}",
        flush=True
    )
    env = os.environ.copy()
    try:
        stderr_path = secure_remote_tunnel_stderr_file()
        os.makedirs(os.path.dirname(stderr_path), exist_ok=True)
        with open(stderr_path, "wb") as stderr_file:
            # Worker provisioning returns Cloudflare's connector token from
            # /accounts/:account/cfd_tunnel/:id/token. The companion must
            # launch cloudflared in token mode; the token is never logged.
            command = [cloudflared_path, "--no-autoupdate", "tunnel", "run", "--token", token]
            token_identity = decode_cloudflare_connector_token_identity(token)
            print(
                f"[SOSYNC-SECURE-REMOTE-IDENTITY] cloudflareConnectorTunnelIDHash={token_identity.get('cloudflare_connector_tunnel_id_hash')} connectorTunnelIdentityAvailable={str(bool(token_identity.get('available'))).lower()} connectorTunnelIdentityFailure={token_identity.get('failure') or 'none'} connectorTokenFormat={token_identity.get('connector_token_format') or 'unknown'} connectorTokenSegmentCount={token_identity.get('connector_token_segment_count')} connectorTokenDecodedObject={str(bool(token_identity.get('connector_token_decoded_object'))).lower()} connectorTokenDecodedKeys={','.join(token_identity.get('connector_token_decoded_keys') or [])} tunnelManagementMode=remoteManaged effectiveIngressSource=cloudflareApi cloudflaredRunning=false",
                flush=True
            )
            print(
                f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelProcessSpawnStarted route={safe_fingerprint(binding.get('route_id'))} mode=token tunnelManagementMode=remoteManaged localConfigSupplied=false effectiveIngressSource=cloudflareApi command={cloudflared_path} --no-autoupdate tunnel run --token [redacted]",
                flush=True
            )
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                env=env
            )
        with timed_lock(SECURE_REMOTE_TUNNEL_LOCK, "secureRemoteTunnel", log_threshold_ms=5):
            SECURE_REMOTE_TUNNEL_PROCESS = process
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelProcessStarted route={safe_fingerprint(binding.get('route_id'))} pidPresent={process.pid is not None}",
            flush=True
        )
        deadline = time.time() + SECURE_REMOTE_TUNNEL_CONFIRMATION_SECONDS
        first_exit_code = None
        while time.time() < deadline:
            exit_code = process.poll()
            if exit_code is not None:
                first_exit_code = exit_code
                break
            time.sleep(0.1)
        if first_exit_code is not None:
            stderr_excerpt = sanitized_secure_remote_tunnel_stderr(
                read_secure_remote_tunnel_stderr_excerpt(),
                token
            )
            print(
                f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelProcessFailed route={safe_fingerprint(binding.get('route_id'))} stage=immediateExit reason=exited code={first_exit_code} stderr={stderr_excerpt}",
                flush=True
            )
            with timed_lock(SECURE_REMOTE_TUNNEL_LOCK, "secureRemoteTunnel", log_threshold_ms=5):
                if SECURE_REMOTE_TUNNEL_PROCESS is process:
                    SECURE_REMOTE_TUNNEL_PROCESS = None
                SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY = None
                SECURE_REMOTE_TUNNEL_STARTING = False
            return {"running": False, "stage": "immediateExit", "reason": "processExited"}
        if process.poll() is None:
            connector_status = wait_for_secure_remote_connector_health(time.time() + SECURE_REMOTE_CONNECTOR_CONFIRMATION_SECONDS, process_locked=True)
            with timed_lock(SECURE_REMOTE_TUNNEL_LOCK, "secureRemoteTunnel", log_threshold_ms=5):
                if SECURE_REMOTE_TUNNEL_PROCESS is process:
                    SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY = token_identity
                SECURE_REMOTE_TUNNEL_STARTING = False
            print(
                f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelProcessConfirmed route={safe_fingerprint(binding.get('route_id'))} running=true connectorState={connector_status['connector_state']} connectorHealthy={connector_status['connector_healthy']} connectorConnectionCount={connector_status['connector_connection_count']} lastErrorClass={connector_status['last_error_class']}",
                flush=True
            )
            print(
                f"[SOSYNC-SECURE-REMOTE-IDENTITY] cloudflareConnectorTunnelIDHash={token_identity.get('cloudflare_connector_tunnel_id_hash')} connectorTunnelIdentityAvailable={str(bool(token_identity.get('available'))).lower()} connectorTunnelIdentityFailure={token_identity.get('failure') or 'none'} connectorTokenFormat={token_identity.get('connector_token_format') or 'unknown'} connectorTokenSegmentCount={token_identity.get('connector_token_segment_count')} connectorTokenDecodedObject={str(bool(token_identity.get('connector_token_decoded_object'))).lower()} connectorTokenDecodedKeys={','.join(token_identity.get('connector_token_decoded_keys') or [])} tunnelManagementMode=remoteManaged effectiveIngressSource=cloudflareApi cloudflaredRunning=true",
                flush=True
            )
            return {"running": True, "connector_healthy": connector_status["connector_healthy"], "stage": "connectorHealthy" if connector_status["connector_healthy"] else "connectorStarting", "reason": None if connector_status["connector_healthy"] else connector_status["last_error_class"]}
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelProcessFailed route={safe_fingerprint(binding.get('route_id'))} stage=confirmationTimeout reason=notRunning",
            flush=True
        )
        with timed_lock(SECURE_REMOTE_TUNNEL_LOCK, "secureRemoteTunnel", log_threshold_ms=5):
            if SECURE_REMOTE_TUNNEL_PROCESS is process:
                SECURE_REMOTE_TUNNEL_PROCESS = None
            SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY = None
            SECURE_REMOTE_TUNNEL_STARTING = False
        return {"running": False, "stage": "confirmationTimeout", "reason": "notRunning"}
    except Exception as error:
        print(
            f"[SOSYNC-SECURE-REMOTE-COMPANION] tunnelProcessFailed route={safe_fingerprint(binding.get('route_id'))} stage=processStart reason={type(error).__name__}",
            flush=True
        )
        with timed_lock(SECURE_REMOTE_TUNNEL_LOCK, "secureRemoteTunnel", log_threshold_ms=5):
            SECURE_REMOTE_TUNNEL_PROCESS = None
            SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY = None
            SECURE_REMOTE_TUNNEL_STARTING = False
        return {"running": False, "stage": "processStart", "reason": type(error).__name__}


def stop_secure_remote_tunnel():
    global SECURE_REMOTE_TUNNEL_PROCESS
    global SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY
    with timed_lock(SECURE_REMOTE_TUNNEL_LOCK, "secureRemoteTunnel", log_threshold_ms=5):
        process = SECURE_REMOTE_TUNNEL_PROCESS
        SECURE_REMOTE_TUNNEL_PROCESS = None
        SECURE_REMOTE_TUNNEL_PROCESS_IDENTITY = None
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def base64url_encode(value):
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def base64url_decode(value):
    normalized = str(value or "").replace("-", "+").replace("_", "/")
    padding = "=" * ((4 - len(normalized) % 4) % 4)
    return base64.b64decode(f"{normalized}{padding}")


def sha256_base64url(value):
    return base64url_encode(hashlib.sha256(value).digest())


def remote_token_fingerprint(remote_token):
    return sha256_base64url(str(remote_token).encode("utf-8"))[:16]


def safe_fingerprint(value):
    if not value:
        return "none"
    return sha256_base64url(str(value).encode("utf-8"))[:16]


def decode_cloudflare_connector_token_identity(token):
    classification = classify_cloudflare_connector_token(token)
    try:
        payload = decoded_cloudflare_connector_token_payload(token, classification)
        decoded_keys = safe_json_key_names(payload)
        tunnel_id = first_string_value(payload, ["t", "tunnel_id", "tunnelID", "TunnelID"])
        if not tunnel_id:
            return {
                "available": False,
                "failure": "tunnelIDMissing",
                "cloudflare_connector_tunnel_id_hash": "none",
                "connector_token_format": classification["format"],
                "connector_token_segment_count": classification["segment_count"],
                "connector_token_decoded_object": isinstance(payload, dict),
                "connector_token_decoded_keys": decoded_keys
            }
        return {
            "available": True,
            "failure": None,
            "cloudflare_connector_tunnel_id_hash": safe_fingerprint(tunnel_id),
            "connector_token_format": classification["format"],
            "connector_token_segment_count": classification["segment_count"],
            "connector_token_decoded_object": True,
            "connector_token_decoded_keys": decoded_keys
        }
    except Exception:
        return {
            "available": False,
            "failure": "decodeFailed",
            "cloudflare_connector_tunnel_id_hash": "none",
            "connector_token_format": classification["format"],
            "connector_token_segment_count": classification["segment_count"],
            "connector_token_decoded_object": False,
            "connector_token_decoded_keys": []
        }


def classify_cloudflare_connector_token(token):
    raw = str(token or "").strip()
    segment_count = len(raw.split(".")) if raw else 0
    if segment_count == 3:
        return {"format": "jwtThreeSegment", "segment_count": segment_count}
    if not raw:
        return {"format": "unknown", "segment_count": segment_count}
    if raw.startswith("{"):
        return {"format": "plainJSON", "segment_count": segment_count}
    if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", raw):
        return {"format": "base64urlJSON", "segment_count": segment_count}
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", raw):
        return {"format": "singleBase64", "segment_count": segment_count}
    return {"format": "unknown", "segment_count": segment_count}


def decoded_cloudflare_connector_token_payload(token, classification):
    raw = str(token or "").strip()
    token_format = classification.get("format")
    if token_format == "jwtThreeSegment":
        parts = raw.split(".")
        return json.loads(base64url_decode(parts[1]).decode("utf-8"))
    if token_format == "plainJSON":
        return json.loads(raw)
    if token_format in ("singleBase64", "base64urlJSON"):
        return json.loads(base64url_decode(raw).decode("utf-8"))
    raise ValueError("unsupportedConnectorTokenFormat")


def safe_json_key_names(value):
    if not isinstance(value, dict):
        return []
    return sorted(str(key)[:64] for key in value.keys() if isinstance(key, str))


def compare_cloudflare_tunnel_identity(expected_hash, connector_identity):
    expected = str(expected_hash or "").strip()
    connector_hash = str((connector_identity or {}).get("cloudflare_connector_tunnel_id_hash") or "").strip()
    if not expected:
        return {"can_compare": False, "matches": False, "failure": "expectedMissing"}
    if not (connector_identity or {}).get("available") or not connector_hash or connector_hash == "none":
        return {"can_compare": False, "matches": False, "failure": (connector_identity or {}).get("failure") or "connectorMissing"}
    return {"can_compare": True, "matches": hmac.compare_digest(expected, connector_hash), "failure": None}


def first_string_value(mapping, keys):
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def iso_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def iso_from_now(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


def is_expired_iso(value):
    if not value:
        return True
    try:
        timestamp = time.strptime(str(value).replace(".000Z", "Z"), "%Y-%m-%dT%H:%M:%SZ")
        import calendar
        return calendar.timegm(timestamp) <= time.time()
    except ValueError:
        try:
            normalized = str(value).replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).timestamp() <= datetime.now(timezone.utc).timestamp()
        except Exception:
            return True


def sanitize_hostname(value):
    hostname = re.sub(r"[^a-zA-Z0-9-]", "-", str(value or "").strip().lower())
    hostname = re.sub(r"-+", "-", hostname).strip("-")
    return hostname[:63] or "sosync-home"


def store_ha_upstream(url):
    os.makedirs(os.path.dirname(HA_UPSTREAM_FILE), exist_ok=True)
    with open(HA_UPSTREAM_FILE, "w", encoding="utf-8") as file:
        file.write(str(url).strip().rstrip("/"))


def read_ha_upstream():
    started_at = time.monotonic()
    try:
        with open(HA_UPSTREAM_FILE, "r", encoding="utf-8") as file:
            value = file.read().strip().rstrip("/")
            companion_perf_log_if_slow("fileReadCompleted", elapsed_ms_since(started_at), path=os.path.basename(HA_UPSTREAM_FILE), bytes=len(value))
            return value or DEFAULT_HOME_ASSISTANT_URL
    except FileNotFoundError:
        companion_perf_log_if_slow("fileReadDefaulted", elapsed_ms_since(started_at), path=os.path.basename(HA_UPSTREAM_FILE))
        return DEFAULT_HOME_ASSISTANT_URL


def store_home_profile(profile):
    os.makedirs(os.path.dirname(HOME_PROFILE_FILE), exist_ok=True)
    temporary_file = f"{HOME_PROFILE_FILE}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp"
    started_at = time.monotonic()
    with timed_lock(HOME_PROFILE_WRITE_LOCK, "homeProfileWrite", log_threshold_ms=5):
        existing = read_home_profile()
        if existing == profile:
            companion_perf_log("fileWriteSkipped", path=os.path.basename(HOME_PROFILE_FILE), elapsedMs=elapsed_ms_since(started_at), reason="unchanged")
            return
        with open(temporary_file, "w", encoding="utf-8") as file:
            json.dump(profile, file, separators=(",", ":"))
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_file, HOME_PROFILE_FILE)
    companion_perf_log("fileWriteCompleted", path=os.path.basename(HOME_PROFILE_FILE), elapsedMs=elapsed_ms_since(started_at))


def read_home_profile():
    started_at = time.monotonic()
    try:
        with open(HOME_PROFILE_FILE, "r", encoding="utf-8") as file:
            value = json.load(file)
            companion_perf_log_if_slow("fileReadCompleted", elapsed_ms_since(started_at), path=os.path.basename(HOME_PROFILE_FILE))
            return value
    except FileNotFoundError:
        companion_perf_log_if_slow("fileReadDefaulted", elapsed_ms_since(started_at), path=os.path.basename(HOME_PROFILE_FILE))
        return None
    except json.JSONDecodeError:
        companion_perf_log("fileReadDefaulted", path=os.path.basename(HOME_PROFILE_FILE), elapsedMs=elapsed_ms_since(started_at), reason="jsonDecode")
        return None


def is_valid_home_profile(profile):
    if not isinstance(profile, dict):
        return False
    if profile.get("schemaVersion") != 1:
        return False
    return isinstance(profile.get("values"), dict)


def is_local_client(address):
    return (
        address == "127.0.0.1" or
        address == "::1" or
        address.startswith("10.") or
        address.startswith("192.168.") or
        address.startswith("172.16.") or
        address.startswith("172.17.") or
        address.startswith("172.18.") or
        address.startswith("172.19.") or
        address.startswith("172.20.") or
        address.startswith("172.21.") or
        address.startswith("172.22.") or
        address.startswith("172.23.") or
        address.startswith("172.24.") or
        address.startswith("172.25.") or
        address.startswith("172.26.") or
        address.startswith("172.27.") or
        address.startswith("172.28.") or
        address.startswith("172.29.") or
        address.startswith("172.30.") or
        address.startswith("172.31.")
    )


def main():
    COMPANION_RUNTIME_HEARTBEAT_STOP.clear()
    print(f"[SOSYNC-E2EE-COMPANION] runtimeStarted runtimeInstance={RUNTIME_INSTANCE_ID} build={SOSYNC_COMPANION_BUILD}", flush=True)
    log_e2ee_pairing_store_loaded()
    log_pairing_authorization_loaded()
    prewarm_e2ee_identity_cache()
    binding = read_secure_remote_binding()
    if binding.get("route_id") and read_secure_text_file(secure_remote_tunnel_token_file()):
        start_result = start_secure_remote_tunnel(binding)
        connector_healthy = bool(start_result.get("connector_healthy"))
        binding["tunnel_configured"] = connector_healthy
        binding["tunnel_state"] = "active" if connector_healthy else ("connectorStarting" if start_result["running"] else "failed")
        binding["failure_stage"] = start_result.get("stage") if not connector_healthy else None
        binding["failure_reason"] = start_result.get("reason") if not connector_healthy else None
        if connector_healthy:
            binding["last_connected_at"] = binding.get("last_connected_at") or iso_now()
        binding["updated_at"] = iso_now()
        write_json_file_secure(SECURE_REMOTE_BINDING_FILE, binding)
    elif binding.get("tunnel_configured"):
        binding["tunnel_configured"] = False
        binding["tunnel_state"] = "notConfigured"
        binding["failure_stage"] = "startupRestore"
        binding["failure_reason"] = "missingCredentialOrProcess"
        binding["updated_at"] = iso_now()
        write_json_file_secure(SECURE_REMOTE_BINDING_FILE, binding)
    bind_address = "0.0.0.0"
    print("[SOSYNC-E2EE-COMPANION] serverConstructionStarted", flush=True)
    print(
        f"[SOSYNC-COMPANION-LISTENER] state=starting bindAddress={bind_address} port={PORT} runtimeInstance={RUNTIME_INSTANCE_ID} reason=processStart",
        flush=True
    )
    try:
        server = ThreadingHTTPServer((bind_address, PORT), Handler)
    except BaseException as error:
        print(
            f"[SOSYNC-COMPANION-LISTENER] state=failed bindAddress={bind_address} port={PORT} runtimeInstance={RUNTIME_INSTANCE_ID} reason={type(error).__name__}",
            flush=True
        )
        raise
    print(
        "[SOSYNC-COMPANION-LISTENER] "
        f"state=constructed {companion_listener_address_summary(server)} "
        f"runtimeInstance={RUNTIME_INSTANCE_ID}",
        flush=True
    )
    heartbeat_thread = start_companion_runtime_heartbeat()
    print(f"SoSync Companion listening on port {PORT}")
    print(f"[SOSYNC-E2EE-COMPANION] runtimeListening runtimeInstance={RUNTIME_INSTANCE_ID} port={PORT}", flush=True)
    print(
        f"[SOSYNC-COMPANION-LISTENER] state=listening {companion_listener_address_summary(server)} runtimeInstance={RUNTIME_INSTANCE_ID} reason=serveForeverStarting",
        flush=True
    )
    print("[SOSYNC-E2EE-COMPANION] routesRegistered identity=true pairingAuthorization=true pair=true revoke=true protocol=1", flush=True)
    print("[SOSYNC-HOME-CONFIG] routesRegistered get=true create=true mutate=true path=/sosync/home-config mutationPath=/sosync/home-config/mutate protocol=1", flush=True)
    print("[SOSYNC-SECURE-REMOTE-COMPANION] routesRegistered identity=true status=true provision=true tunnelInstall=true tunnelRotate=true revoke=true dataPlane=true", flush=True)
    try:
        server.serve_forever()
    except BaseException as error:
        print(
            f"[SOSYNC-COMPANION-LISTENER] state=failed bindAddress={bind_address} port={PORT} runtimeInstance={RUNTIME_INSTANCE_ID} reason={type(error).__name__}",
            flush=True
        )
        raise
    finally:
        COMPANION_RUNTIME_HEARTBEAT_STOP.set()
        print(
            f"[SOSYNC-COMPANION-LISTENER] state=stopped bindAddress={bind_address} port={PORT} runtimeInstance={RUNTIME_INSTANCE_ID} reason=serveForeverExited",
            flush=True
        )
        server.server_close()
        heartbeat_thread.join(timeout=1)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        print(
            f"[SOSYNC-E2EE-COMPANION] fatalStartupError type={type(error).__name__} message={error}",
            flush=True
        )
        traceback.print_exc()
        sys.exit(1)
