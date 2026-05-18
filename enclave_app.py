"""
enclave_app.py — Runs INSIDE the AWS Nitro Enclave
Handles: AES-GCM decryption, adjacency list parsing, attestation
Communicates with parent via vsock (CID=4, PORT=5000)
"""

import socket
import json
import time
import hashlib
import struct
import os
import sys
from Crypto.Cipher import AES

VSOCK_PORT = 5000
RECV_BUF   = 4 * 1024 * 1024  # 4 MB max message size

# ── Crypto helpers (same as parent) ─────────────────────
def aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(plaintext)
    return c.nonce + tag + ct

# ── Request handlers ─────────────────────────────────────

def handle_decrypt_adjacency(payload: dict) -> dict:
    """
    Decrypt one or more adjacency blobs inside TEE.
    Input:  { "key_hex": str, "records": [ {"nid": int, "adj_ct": str}, ... ] }
    Output: { "neighbors": { nid: [(nbr, edge_label), ...] }, "t_tee_ms": float }
    """
    t0 = time.perf_counter()
    key     = bytes.fromhex(payload["key_hex"])
    records = payload["records"]   # list of {"nid": int, "adj_ct": hex_str}

    neighbors = {}
    for rec in records:
        nid     = rec["nid"]
        adj_hex = rec.get("adj_ct", "")
        if not adj_hex:
            continue
        try:
            blob      = bytes.fromhex(adj_hex)
            decrypted = aes_gcm_decrypt(key, blob)
            nbr_list  = json.loads(decrypted.decode())   # list of [nbr_id, edge_label]
            neighbors[nid] = nbr_list
        except Exception as e:
            # Dummy block or corrupted — silently discard
            continue

    t_ms = (time.perf_counter() - t0) * 1000
    return {"neighbors": neighbors, "t_tee_ms": round(t_ms, 4)}


def handle_decrypt_nodes(payload: dict) -> dict:
    """
    Decrypt node ciphertext blobs inside TEE.
    Input:  { "key_hex": str, "records": [ {"nid": int, "ct": str}, ... ] }
    Output: { "nodes": { nid: {node_data} }, "t_tee_ms": float }
    """
    t0  = time.perf_counter()
    key = bytes.fromhex(payload["key_hex"])

    nodes = {}
    for rec in payload["records"]:
        nid = rec["nid"]
        try:
            blob      = bytes.fromhex(rec["ct"])
            decrypted = aes_gcm_decrypt(key, blob)
            node_data = json.loads(decrypted.decode())
            nodes[nid] = node_data
        except Exception:
            continue  # dummy block

    t_ms = (time.perf_counter() - t0) * 1000
    return {"nodes": nodes, "t_tee_ms": round(t_ms, 4)}


def handle_decrypt_dsse(payload: dict) -> dict:
    """
    Decrypt DSSE index entries inside TEE.
    Input:  { "ke_hex": str, "entries": [ hex_str, ... ] }
    Output: { "real_ids": [ [...], ... ], "t_tee_ms": float }
    """
    t0  = time.perf_counter()
    ke  = bytes.fromhex(payload["ke_hex"])

    real_ids = []
    for h in payload["entries"]:
        try:
            blob      = bytes.fromhex(h)
            decrypted = aes_gcm_decrypt(ke, blob)
            parsed    = json.loads(decrypted.decode())
            if isinstance(parsed, list):   # real entry (not dummy string)
                real_ids.append(parsed)
        except Exception:
            continue

    t_ms = (time.perf_counter() - t0) * 1000
    return {"real_ids": real_ids, "t_tee_ms": round(t_ms, 4)}


def handle_attest(payload: dict) -> dict:
    """
    Generate attestation document (real NSM call inside enclave).
    Returns PCR values and timing.
    """
    t0 = time.perf_counter()
    try:
        # Real NSM attestation via /dev/nsm
        import nsm  # available only inside Nitro Enclave
        nonce = os.urandom(32)
        doc   = nsm.get_attestation_doc(
            user_data  = json.dumps(payload.get("user_data", {})).encode(),
            nonce      = nonce,
            public_key = None
        )
        t_ms = (time.perf_counter() - t0) * 1000
        return {
            "attestation_doc": doc.hex(),
            "t_tee_ms": round(t_ms, 4),
            "attested": True
        }
    except ImportError:
        # nsm not available — running in test mode outside enclave
        t_ms = (time.perf_counter() - t0) * 1000
        return {
            "attestation_doc": "nsm_not_available_test_mode",
            "t_tee_ms": round(t_ms, 4),
            "attested": False
        }


HANDLERS = {
    "decrypt_adjacency": handle_decrypt_adjacency,
    "decrypt_nodes":     handle_decrypt_nodes,
    "decrypt_dsse":      handle_decrypt_dsse,
    "attest":            handle_attest,
}

# ── vsock server loop ────────────────────────────────────
def recv_all(conn: socket.socket, length: int) -> bytes:
    """Read exactly `length` bytes from socket."""
    buf = b""
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed mid-message")
        buf += chunk
    return buf


def send_message(conn: socket.socket, data: dict) -> None:
    """Send length-prefixed JSON message."""
    payload = json.dumps(data).encode()
    header  = struct.pack(">I", len(payload))   # 4-byte big-endian length
    conn.sendall(header + payload)


def recv_message(conn: socket.socket) -> dict:
    """Receive length-prefixed JSON message."""
    header  = recv_all(conn, 4)
    length  = struct.unpack(">I", header)[0]
    payload = recv_all(conn, length)
    return json.loads(payload.decode())


def handle_connection(conn: socket.socket, addr):
    """Handle one client connection in its own thread."""
    try:
        request = recv_message(conn)
        op      = request.get("op", "unknown")
        handler = HANDLERS.get(op)

        if handler:
            result = handler(request.get("payload", {}))
            send_message(conn, {"status": "ok", "result": result})
        else:
            send_message(conn, {"status": "error",
                                "message": f"Unknown op: {op}"})
    except Exception as e:
        try:
            send_message(conn, {"status": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        conn.close()


def run_server():
    """
    Concurrent vsock server — spawns one thread per connection so multiple
    Spark workers (one per EMR node) can call the enclave in parallel.
    Each thread handles exactly one request-response cycle then exits.
    """
    import threading

    print(f"[Enclave] Starting vsock server on port {VSOCK_PORT}", flush=True)
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
    # Backlog = 64 so burst of Spark workers doesn't get ECONNREFUSED
    sock.listen(64)
    print("[Enclave] Listening (threaded, backlog=64)...", flush=True)

    while True:
        conn, addr = sock.accept()
        print(f"[Enclave] Connection from CID={addr[0]}", flush=True)
        t = threading.Thread(
            target=handle_connection,
            args=(conn, addr),
            daemon=True,   # exits when main thread exits
        )
        t.start()


if __name__ == "__main__":
    run_server()