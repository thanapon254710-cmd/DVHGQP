#!/bin/bash
# setup_enclave.sh — Build and run the DVH-GQP Nitro Enclave on EC2
# Run this on your m5.2xlarge instance (i-09171fd16d1fd4c4b)

set -e
ENCLAVE_EIF="dvhgqp.eif"
ENCLAVE_MEMORY=2048   # MB
ENCLAVE_CPUS=2

echo "========================================"
echo "  DVH-GQP Nitro Enclave Setup"
echo "========================================"

# ── 1. Verify Nitro Enclaves CLI ─────────────────────────
echo "[1] Checking nitro-cli..."
nitro-cli --version || { echo "ERROR: nitro-cli not found. Run:"; 
    echo "  sudo amazon-linux-extras install aws-nitro-enclaves-cli -y"; exit 1; }

# ── 2. Configure enclave allocator ───────────────────────
echo "[2] Configuring enclave allocator (${ENCLAVE_MEMORY}MB, ${ENCLAVE_CPUS} CPUs)..."
sudo tee /etc/nitro_enclaves/allocator.yaml > /dev/null <<EOF
---
memory_mib: ${ENCLAVE_MEMORY}
cpu_count: ${ENCLAVE_CPUS}
EOF
sudo systemctl restart nitro-enclaves-allocator.service
echo "    Allocator configured."

# ── 3. Build Docker image ─────────────────────────────────
echo "[3] Building Docker image..."
docker build -t dvhgqp-enclave . 
echo "    Docker image built."

# ── 4. Convert to Enclave Image File (.eif) ──────────────
echo "[4] Building Enclave Image File (EIF)..."
nitro-cli build-enclave \
    --docker-uri dvhgqp-enclave:latest \
    --output-file ${ENCLAVE_EIF}
echo "    EIF built: ${ENCLAVE_EIF}"

# ── 5. Terminate any existing enclave ────────────────────
echo "[5] Terminating existing enclaves (if any)..."
EXISTING=$(nitro-cli describe-enclaves | python3 -c \
    "import sys,json; encs=json.load(sys.stdin); \
    [print(e['EnclaveID']) for e in encs if e]" 2>/dev/null || true)
if [ -n "$EXISTING" ]; then
    for EID in $EXISTING; do
        nitro-cli terminate-enclave --enclave-id "$EID"
        echo "    Terminated: $EID"
    done
fi

# ── 6. Launch the enclave ─────────────────────────────────
echo "[6] Launching enclave..."
nitro-cli run-enclave \
    --eif-path ${ENCLAVE_EIF} \
    --memory ${ENCLAVE_MEMORY} \
    --cpu-count ${ENCLAVE_CPUS} \
    --enclave-cid 16 \
    --debug-mode          # remove --debug-mode in production!

# ── 7. Verify and get CID ────────────────────────────────
echo "[7] Enclave status:"
nitro-cli describe-enclaves

echo ""
echo "========================================"
echo "  Enclave is running!"
echo "  CID: 16   PORT: 5000"
echo ""
echo "  To view logs (debug mode only):"
echo "    nitro-cli console --enclave-id <ID>"
echo ""
echo "  To terminate:"
echo "    nitro-cli terminate-enclave --enclave-id <ID>"
echo "========================================"
