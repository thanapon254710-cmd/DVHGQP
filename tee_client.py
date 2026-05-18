"""
tee_client.py — Parent-side TEE interface
Replaces simulated tee_cost() with real AWS Nitro Enclave calls via vsock.

Drop-in replacement: import this instead of using tee_cost() directly.
"""

import socket
import json
import struct
import time
from typing import Optional

# ── vsock config ─────────────────────────────────────────
ENCLAVE_CID  = 16      # CID assigned to the enclave (check: nitro-cli describe-enclaves)
ENCLAVE_PORT = 5000    # must match enclave_app.py VSOCK_PORT
TIMEOUT_SEC  = 30      # socket timeout

# ── low-level transport ───────────────────────────────────
def _send_recv(op: str, payload: dict) -> dict:
    """
    Open a vsock connection, send one request, receive one response, close.
    Raises RuntimeError on any failure.
    """
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SEC)
    try:
        sock.connect((ENCLAVE_CID, ENCLAVE_PORT))

        # Send: 4-byte length prefix + JSON body
        body   = json.dumps({"op": op, "payload": payload}).encode()
        header = struct.pack(">I", len(body))
        sock.sendall(header + body)

        # Receive: 4-byte length prefix + JSON body
        raw_len  = _recv_all(sock, 4)
        length   = struct.unpack(">I", raw_len)[0]
        raw_body = _recv_all(sock, length)
        response = json.loads(raw_body.decode())

        if response.get("status") != "ok":
            raise RuntimeError(f"Enclave error: {response.get('message', 'unknown')}")
        return response["result"]

    finally:
        sock.close()


def _recv_all(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("vsock connection closed early")
        buf += chunk
    return buf


# ── Public TEE API ────────────────────────────────────────

def tee_decrypt_adjacency(key: bytes, records: list) -> tuple:
    """
    Decrypt adjacency blobs inside real Nitro Enclave.

    Args:
        key:     AES-GCM key (bytes)
        records: list of {"nid": int, "adj_ct": hex_str}   (from Neo4j)

    Returns:
        neighbors: dict  { nid: [(nbr_id, edge_label), ...] }
        t_tee_ms:  float  measured inside the enclave
    """
    payload = {
        "key_hex": key.hex(),
        "records": records
    }
    result   = _send_recv("decrypt_adjacency", payload)
    # Convert string keys back to int (JSON serialises dict keys as strings)
    neighbors = {int(k): v for k, v in result["neighbors"].items()}
    return neighbors, result["t_tee_ms"]


def tee_decrypt_nodes(key: bytes, records: list) -> tuple:
    """
    Decrypt node ciphertext blobs inside real Nitro Enclave.

    Args:
        key:     AES-GCM key (bytes)
        records: list of {"nid": int, "ct": hex_str}

    Returns:
        nodes:    dict  { nid: {node_data_dict} }
        t_tee_ms: float
    """
    payload = {
        "key_hex": key.hex(),
        "records": records
    }
    result = _send_recv("decrypt_nodes", payload)
    nodes  = {int(k): v for k, v in result["nodes"].items()}
    return nodes, result["t_tee_ms"]


def tee_decrypt_dsse(ke: bytes, entries: list) -> tuple:
    """
    Decrypt DSSE index entries inside real Nitro Enclave.

    Args:
        ke:      Ke key (bytes)
        entries: list of hex-encoded encrypted DSSE blobs

    Returns:
        real_ids: list of decoded real entry lists (dummies filtered out)
        t_tee_ms: float
    """
    payload = {
        "ke_hex":  ke.hex(),
        "entries": entries
    }
    result = _send_recv("decrypt_dsse", payload)
    return result["real_ids"], result["t_tee_ms"]


def tee_attest(user_data: dict = None) -> tuple:
    """
    Request attestation document from Nitro Enclave.

    Returns:
        doc_hex:  hex-encoded attestation document (or test string)
        t_tee_ms: measured latency
        attested: True if real NSM attestation succeeded
    """
    payload = {"user_data": user_data or {}}
    result  = _send_recv("attest", payload)
    return result["attestation_doc"], result["t_tee_ms"], result["attested"]


# ── Enclave health check ──────────────────────────────────
def enclave_ping() -> float:
    """
    Quick connectivity test. Returns round-trip ms or None if unreachable.
    """
    try:
        t0 = time.perf_counter()
        tee_attest()
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return None


# ── Compatibility shim: drop-in for simulated tee_cost() ─
def tee_cost_real(p_r: int, key: bytes, records: list) -> tuple:
    """
    Drop-in replacement for simulated tee_cost(p_r).
    Performs real decryption in enclave and returns (t_tee_ms, neighbors).
    """
    neighbors, t_tee_ms = tee_decrypt_adjacency(key, records)
    return t_tee_ms, neighbors
