# DVH-GQP: Dynamic Volume-Hiding Framework for Secure Graph Query Processing

> Sirindhorn International Institute of Technology, Thammasat University, Thailand

A privacy-preserving graph query system that encrypts graph data using **AES-256-GCM**, stores it in **Neo4j**, and supports secure queries via a **DSSE label index**, **Selective ORAM-padded** BFS traversal, and subgraph matching — all executed inside **AWS Nitro Enclaves (TEE)** with **Apache Spark** distributed processing.

---

## Table of Contents

- [Overview](#overview)
- [Protocol](#protocol)
- [Security Model](#security-model)
- [Query Types](#query-types)
- [Experimental Results](#experimental-results)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Demo](#running-the-demo)
- [Running the Evaluation](#running-the-evaluation)
- [Project Structure](#project-structure)
- [Datasets](#datasets)
- [Firewall Ports](#firewall-ports)
- [Notes](#notes)

---

## Overview

Graph-structured data is increasingly used to model complex relationships in social networks, healthcare, and IoT. Outsourcing graph data to the cloud raises serious privacy concerns — sensitive information may be exposed during query processing.

**DVH-GQP** proposes a novel volume-hiding graph query framework that enables secure and efficient query processing over encrypted graph databases. The key idea is a **dynamic, size-adaptive volume-hiding mechanism** that obscures true query result sizes through tiered proportional padding, reducing information leakage across multiple system layers while maintaining low overhead.

**Key properties:**
- Graph data encrypted with **AES-256-GCM** before any storage — Neo4j never sees plaintext
- **DSSE index** enables sub-linear label/keyword search without revealing the label to the server
- **Adaptive padding P(r)** hides result sizes — server observes only padded counts, not true r
- **Selective ORAM** protects access patterns with only 1.10×–1.20× storage overhead
- **AWS Nitro Enclave** provides hardware-isolated decryption — host OS cannot access plaintext
- **Apache Spark** with dynamic executor scaling (k) distributes query execution across partitions
- Experimental results show end-to-end query latency of **167–1,055 ms** on the SNAP Email-Enron dataset

### Principal Entities

| Entity | Role |
|---|---|
| **Data Owner (DO)** | Client who owns the graph data; holds all secret keys locally |
| **Service Provider (SP)** | Untrusted cloud; stores encrypted graph in Neo4j, hosts Spark and TEE |

### Subsystems

| Subsystem | Description |
|---|---|
| **Neo4j Graph Store** | Stores encrypted property graph — only ciphertext, never plaintext |
| **DSSE Index Layer** | Encrypted inverted index mapping PRF tokens to padded posting lists |
| **Selective ORAM Controller** | Mediates block reads between TEE and Neo4j, always fetching exactly P(r) blocks |
| **TEE Query Evaluator** | AWS Nitro Enclave — isolated, hardware-attested VM sealed from the host OS |
| **Apache Spark Cluster** | Distributes query evaluation across k executor-enclave pairs |

### File Roles

| File | Role |
|---|---|
| `DVHGQP-TeeDemo.py` | Flask web app — interactive demo UI with live Neo4j sync |
| `DVHGQP-Evaluation.py` | Full benchmark script — generates evaluation plots |
| `enclave_app.py` | Runs inside Nitro Enclave — handles all decryption operations |
| `tee_client.py` | vsock client — driver-side communication with the enclave |
| `setup_enclave.sh` | Builds and launches the Nitro Enclave from the EIF image |
| `Dockerfile` | Enclave image (EIF) build configuration |

---

## Protocol

DVH-GQP operates in two phases:

### Phase 1 — Graph Outsourcing (performed once by DO)

**Step 1 — Key Generation**

The DO generates three independent 256-bit secret keys stored locally, never shared with the SP:
- `K` — AES-256-GCM key for encrypting all graph data blocks
- `Ks` — PRF key for deriving DSSE search tokens: `Tw ← PRF(Ks, w)`
- `Ke` — AES-256-GCM key for encrypting posting-list identifiers

**Step 2 — Graph Encryption**

Every vertex and edge is individually encrypted before upload:
```
Cv ← AES-256-GCM-EncK(id(v), label(v), attrs(v))
Ce ← AES-256-GCM-EncK(id(e), label(e), attrs(e))
```
The encrypted adjacency index (`enc_adj`) is also built — each node's neighbor list is AES-encrypted to enable TEE-side BFS without revealing traversal patterns to the SP.

**Step 3 — DVH-GQP Dynamic Index Construction**

For each label keyword `w`, the DO computes the padded posting list using the tiered padding function:

```
P(r) = r + ceil(0.20 * r)   if r < 1,000     (20% padding)
P(r) = r + ceil(0.15 * r)   if r < 5,000     (15% padding)
P(r) = r + ceil(0.10 * r)   if r >= 5,000    (10% padding, always >= 1 dummy)
```

Each entry is encrypted under `Ke`. The SP stores `Tw → Lw` and observes only `P(r)` entries — never the true `r`. Residual leakage: `L(q) = (P(r), access time)`.

**Step 4 — ORAM Initialization**

Every block is assigned a uniformly random server position in Neo4j, recorded in a local position map `PM`. Dummy positions are pre-registered so the TEE can fetch them obliviously at query time.

---

### Phase 2 — Query Execution (per query)

**Step 1** — DO computes `Tw ← PRF(Ks, w)` and sends it to SP. SP returns padded list `Lw` of `P(r)` ciphertexts.

**Step 2** — TEE attestation via AWS KMS. DO establishes end-to-end encrypted channel directly to the enclave, bypassing the host OS.

**Step 3** — DO transmits `K, q, B, dummy-pattern` to TEE over secure channel. TEE computes `P(r)` entirely inside isolated hardware-protected memory.

**Step 4** — TEE fetches all `P(r)` blocks from Neo4j via Selective ORAM. Each block is re-encrypted with a fresh nonce and written to a new random position. SP observes exactly `P(r)` ORAM accesses, not `r`.

**Step 5** — TEE dispatches `r` real blocks across `k` Spark executor-enclave pairs. Dynamic `k` scaling:

| Result size r | Spark executors k |
|---|---|
| r < 500 | k = 1 |
| r < 2,000 | k = 2 |
| r < 5,000 | k = 4 |
| r >= 5,000 | k = 8 |

Cross-shard BFS frontier messages are padded to `F(r) = P(r)/k` slots per level so SP cannot infer BFS expansion sizes.

**Step 6** — Spark Driver aggregates padded partial results. TEE strips padding, encrypts final result for DO, who decrypts locally. DO updates `hist(w) ← r`. SP observes only `(P(r), access time)`.

---

## Security Model

| Property | Mechanism |
|---|---|
| Data confidentiality | AES-256-GCM encryption of all nodes, edges, and adjacency lists |
| Query privacy | DSSE — server sees only `PRF(Ks, w)` tokens, never plaintext labels |
| Result size hiding | Adaptive padding P(r) — server observes padded count, not true r |
| Access pattern | Selective ORAM — always fetches exactly P(r) blocks |
| Decryption isolation | AWS Nitro Enclave — hardware-isolated TEE, sealed from host OS |
| Integrity | GCM authentication tag on every ciphertext block |
| Residual leakage | L(q) = (P(r), access time) — formally characterized |

Keys `K`, `Ks`, `Ke` are held client-side only — the SP never has access to any key.

---

## Query Types

### Natural-Language Queries (Demo)

| Example | Type |
|---|---|
| `How many nodes?` | Node count |
| `How many edges?` | Edge count |
| `How many connections does node 0 have?` | Degree / adjacency |
| `What label is node 0?` | Node label lookup |
| `How many Executive nodes?` | DSSE label count |
| `BFS from node 0 depth 2` | BFS reachability |
| `Can node 0 reach node 500?` | Reachability check |
| `Find Executive REPLY Manager` | Subgraph pattern matching |

### Node Labels (assigned by degree threshold)

| Label | Degree Threshold |
|---|---|
| Executive | > 500 total email degree |
| Manager | > 200 |
| Employee | > 50 |
| External | > 5 |
| Inactive | <= 5 |

### Edge Labels

`SEND`, `REPLY`, `BROADCAST`, `INTERNAL` — assigned based on sender/receiver role combinations.

---

## Experimental Results

All experiments conducted on a single **AWS EC2 m5.2xlarge** (8 vCPUs, 32 GB RAM) with one Nitro Enclave (2 vCPUs, 2,048 MiB). Dataset: **SNAP Email-Enron** (36,692 nodes, 183,831 edges).

### Query Latency

| Query type | Latency |
|---|---|
| Label count — small (e.g. Executive, r=32) | ~167 ms |
| Label count — large (e.g. INTERACTS, r~22,088) | ~1,055 ms |
| BFS depth=1 (any node degree) | ~390–400 ms |
| BFS depth=3 (high-degree node, deg=1,045) | ~1,600 ms |
| Subgraph matching | ~400–637 ms |

TEE attestation contributes a fixed ~68 ms overhead per query. AES decryption remains negligible (< 5 ms) due to AES-NI hardware acceleration. Neo4j encrypted block retrieval is the dominant scalability bottleneck at large result sizes.

### Storage Overhead

| Result size | Padding ratio | Storage overhead |
|---|---|---|
| r < 1,000 | 20% | 1.20× |
| 1,000 <= r < 5,000 | 15% | 1.15× |
| r >= 5,000 | 10% | 1.10× |

Significantly below the O(log² N) amplification of standard ORAM.

### Comparison with Related Work

| Scheme | Data | Access | Vol. | BFS | Subgraph | Storage |
|---|---|---|---|---|---|---|
| **DVH-GQP (Ours)** | ✓ | ✓ | ✓ | ✓ | ✓ | **1.1–1.2×** |
| OblivGM | ✓ | ✓ | ✓ | — | ✓ | 1.5–2.5× |
| Baseline BFS | ✓ | — | — | ✓ | — | 1.00× |
| Baseline Subgraph | ✓ | — | — | — | ✓ | 1.00× |

DVH-GQP is the only scheme simultaneously protecting data content, access patterns across three leakage channels, and supporting both BFS reachability and subgraph matching in a distributed setting.

---

## Requirements

### Hardware
- **AWS EC2** instance with **Nitro Enclaves enabled**
- Evaluated on: `m5.2xlarge` (8 vCPUs, 32 GB RAM)
- Recommended for large datasets: `r5.2xlarge` (8 vCPUs, 64 GB RAM) or `r5.4xlarge` (16 vCPUs, 128 GB RAM)

### Software
- Amazon Linux 2
- Python 3.8+
- Java 21 (Amazon Corretto 21)
- Neo4j 5.26.0
- Apache Spark 3.5.8
- AWS Nitro CLI

### Python Dependencies

```bash
pip install flask pycryptodome python-dotenv neo4j pyspark==3.5.8 numpy pandas matplotlib
```

---

## Installation

### 1. Upload Project Files

```bash
mkdir ~/dvhgqp && cd ~/dvhgqp
# Upload all project files here
```

### 2. Install Java 21 (Amazon Corretto)

```bash
sudo rpm --import https://yum.corretto.aws/corretto.key
sudo curl -L -o /etc/yum.repos.d/corretto.repo https://yum.corretto.aws/corretto.repo
sudo yum install java-21-amazon-corretto-devel -y
java -version   # should show 21
```

### 3. Install Neo4j 5.26.0

```bash
# Add Neo4j GPG key and repo
sudo rpm --import https://debian.neo4j.com/neotechnology.gpg.key
sudo tee /etc/yum.repos.d/neo4j.repo <<EOF
[neo4j]
name=Neo4j RPM Repository
baseurl=https://yum.neo4j.com/stable/5
enabled=1
gpgcheck=1
EOF

# Download and install RPMs directly (bypasses yum Java version conflict on Amazon Linux 2)
wget https://dist.neo4j.org/cypher-shell/cypher-shell-5.26.0-1.noarch.rpm
wget https://dist.neo4j.org/rpm/neo4j-5.26.0-1.noarch.rpm
sudo rpm -ivh --nodeps cypher-shell-5.26.0-1.noarch.rpm
sudo rpm -ivh --nodeps neo4j-5.26.0-1.noarch.rpm

# Set password
sudo neo4j-admin dbms set-initial-password your_password

# Configure Neo4j to use Java 21 and allow external connections
echo "dbms.jvm.additional=-Djava.home=/usr/lib/jvm/java-21-amazon-corretto" | sudo tee -a /etc/neo4j/neo4j.conf
echo "server.default_listen_address=0.0.0.0" | sudo tee -a /etc/neo4j/neo4j.conf
echo "server.bolt.listen_address=0.0.0.0:7687" | sudo tee -a /etc/neo4j/neo4j.conf
echo "server.http.listen_address=0.0.0.0:7474" | sudo tee -a /etc/neo4j/neo4j.conf

# Enable and start
sudo systemctl enable neo4j
sudo systemctl start neo4j

# Verify connection
cypher-shell -u neo4j -p your_password "RETURN 1"
```

### 4. Start the Nitro Enclave

```bash
cd ~/dvhgqp
./setup_enclave.sh

# Verify it is running
nitro-cli describe-enclaves
# Should show "State": "RUNNING"
```

**Auto-start enclave on instance reboot:**

```bash
sudo tee /etc/systemd/system/nitro-enclave.service <<EOF
[Unit]
Description=Nitro Enclave Auto-start
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/ec2-user/dvhgqp
ExecStart=/home/ec2-user/dvhgqp/setup_enclave.sh
User=ec2-user

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable nitro-enclave
```

---

## Configuration

Create a `.env` file in the project directory:

```env
# Neo4j connection (local)
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_password

# Loading and benchmark settings
BATCH_SIZE=5000
REPEAT=10

# Enclave vsock (default values match setup_enclave.sh)
ENCLAVE_CID=16
ENCLAVE_PORT=5000
```

> To use **Neo4j AuraDB** instead of local Neo4j, change `NEO4J_URI` to your AuraDB connection string (e.g. `neo4j+s://xxxx.databases.neo4j.io`). No code changes needed — both `TeeDemo.py` and `Evaluation.py` read all connection settings from `.env`.

### VS Code Configuration

Add to `.vscode/settings.json` to auto-load `.env` in the integrated terminal:

```json
{
  "python.terminal.useEnvFile": true
}
```

---

## Running the Demo

### Start the Flask App

```bash
cd ~/dvhgqp
python DVHGQP-TeeDemo.py
```

Open in browser: `http://your-ec2-ip:5000`

**Steps:**
1. Paste a SNAP dataset URL (e.g. `https://snap.stanford.edu/data/email-Enron.txt.gz`)
2. Click **Load Graph** — data is downloaded, encrypted with AES-256-GCM, and stored in Neo4j
3. Type a natural-language query or click a sample chip
4. Click **Run Query** — query is processed inside the Nitro Enclave via vsock

The **sync banner** at the bottom polls Neo4j every 10 seconds. Any node/edge creates, deletes, or label edits made directly in Neo4j Browser are automatically detected, the DSSE index is rebuilt, and the stats panel updates — no app restart needed.

### Neo4j Browser UI

Access Neo4j browser at: `http://your-ec2-ip:7474`

Login with your credentials to inspect, create, or delete encrypted nodes directly via Cypher.

---

## Running the Evaluation

```bash
cd ~/dvhgqp
python DVHGQP-Evaluation.py
```

Runs the full benchmark across five phases:

| Phase | Description |
|---|---|
| Phase 0 | Download and parse the SNAP Email-Enron dataset |
| Phase 1 | Encrypt all nodes, edges, and build DSSE index |
| Phase 2 | Load encrypted graph into Neo4j (batch ingestion) |
| Phase 3 | Run label, BFS, and subgraph benchmarks with TEE + Spark |
| Phase 4 | Generate comparison plots |

Output plots saved to `outputs/`:
- `dvhgqp_full_evaluation.png` — full system evaluation (latency breakdown, storage overhead, Spark parallelism impact)
- `dvhgqp_vs_related_work.png` — DVH-GQP vs. Baseline and OblivGM (BFS and subgraph matching)

---

## Project Structure

```
dvhgqp/
├── DVHGQP-TeeDemo.py        # Flask web demo with live Neo4j sync
├── DVHGQP-Evaluation.py     # Full benchmark with Neo4j + TEE + Spark + plots
├── enclave_app.py           # TEE enclave application (runs inside Nitro Enclave)
├── tee_client.py            # vsock client for driver-enclave communication
├── setup_enclave.sh         # Builds EIF and launches the enclave
├── Dockerfile               # Enclave image build configuration
├── dvhgqp.eif               # Compiled enclave image file
├── .env                     # Neo4j credentials and config (never commit this)
├── .env.example             # Template with empty values
└── outputs/                 # Generated evaluation figures
    ├── dvhgqp_full_evaluation.png
    └── dvhgqp_vs_related_work.png
```

---

## Datasets

| Dataset | Nodes | Edges | Description | URL |
|---|---|---|---|---|
| **Email-Enron** (default) | 36,692 | 183,831 | Email communication network | https://snap.stanford.edu/data/email-Enron.txt.gz |
| **YouTube** (large-scale) | 1,134,890 | 2,987,624 | Social network for scalability testing | https://snap.stanford.edu/data/com-Youtube.ungraph.txt.gz |

All datasets from [SNAP Stanford](https://snap.stanford.edu/data/). Format: space-separated edge list (`u v` per line, `#` for comments).

---

## Firewall Ports

| Port | Service |
|---|---|
| 22 | SSH |
| 5000 | Flask web app (TeeDemo) |
| 7474 | Neo4j Browser UI (HTTP) |
| 7687 | Neo4j Bolt protocol |

---

## Notes

- The enclave runs in **DEBUG MODE** by default — for production, remove `--debug-mode` from `setup_enclave.sh` to enable full PCR attestation
- If the enclave is not running, the app falls back to **software simulation mode** — all cryptographic operations still execute correctly, just without hardware isolation
- Neo4j stores **only ciphertext** — the `label` property visible in Neo4j Browser is an encrypted hex string, not the plaintext label
- The enclave **does not auto-start** after EC2 stop/start unless the systemd service above is enabled
- In a single-node deployment, increasing Spark `k` introduces scheduling overhead without proportional speedup. In a production EMR cluster with dedicated per-worker enclaves, higher `k` provides near-linear latency reduction — reported overhead should be interpreted as a conservative upper bound for real-world multi-node deployments
