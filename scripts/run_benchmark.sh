#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#
# Host-side benchmark & telemetry collection script for evaluating
# ML-KEM-768 + X25519 (mlkem768x25519-sha256) memory lifecycle in OpenSSH 10.0p2
# (/usr/lib/openssh/sshd-auth) on the isolated target VM (192.168.56.10).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET_USER="${TARGET_USER:-indra}"
TARGET_IP="${TARGET_IP:-192.168.56.10}"
TARGET_SUBNET_REGEX='^192\.168\.56\.([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$'

KEX_ALGO="mlkem768x25519-sha256"
TOTAL_SESSIONS=20
NORMAL_SESSIONS=10
ABORT_SESSIONS=10

REMOTE_WORK_DIR="~/work"
REMOTE_JSON_PATH="/tmp/pqc_benchmark_metrics.json"
 REMOTE_LOADER_LOG="/tmp/pqc_loader.stderr.log"
LOCAL_RESULTS_DIR="${REPO_ROOT}/results"
LOCAL_JSON_PATH="${LOCAL_RESULTS_DIR}/benchmark_metrics.json"

CTL_SOCKET="/tmp/pqc-sshd-ctl-$$.sock"
KNOWN_HOSTS_TMP="/tmp/pqc-known-hosts-$$"
SKIP_DEPLOY=0
FILTER_KEX_ONLY=0

usage() {
	cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  -i <identity_file>  SSH private key path (auto-detected from ~/.ssh if omitted)
  -o <output_json>    Local output JSON path (default: results/benchmark_metrics.json)
  -k                  Pass -k to eBPF loader (record only events inside kex_kem_mlkem768x25519_dec)
  --no-deploy         Skip syncing src/ and running make on the target VM
  -h, --help          Show this help message
EOF
}

SSH_IDENTITY="${SSH_IDENTITY:-}"
while [[ $# -gt 0 ]]; do
	case "$1" in
		-i)
			SSH_IDENTITY="$2"
			shift 2
			;;
		-o)
			LOCAL_JSON_PATH="$2"
			shift 2
			;;
		-k)
			FILTER_KEX_ONLY=1
			shift
			;;
		--no-deploy)
			SKIP_DEPLOY=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "[ERROR] Unknown argument: $1" >&2
			usage >&2
			exit 1
			;;
	esac
done

# Security Guardrail: Strictly enforce Host-Only lab subnet (192.168.56.0/24)
if [[ ! "${TARGET_IP}" =~ ${TARGET_SUBNET_REGEX} ]]; then
	echo "[FATAL] Target IP '${TARGET_IP}' violates lab isolation policy (must be in 192.168.56.0/24)." >&2
	exit 1
fi

# Auto-detect SSH identity file if not explicitly provided
if [[ -z "${SSH_IDENTITY}" ]]; then
	for candidate in \
		"${HOME}/.ssh/id_ed25519" \
		"${HOME}/.ssh/id_ed25519_silentium" \
		"${HOME}/.ssh/id_rsa"; do
		if [[ -f "${candidate}" ]]; then
			SSH_IDENTITY="${candidate}"
			break
		fi
	done
fi

KEY_OPTS=()
if [[ -n "${SSH_IDENTITY}" && -f "${SSH_IDENTITY}" ]]; then
	KEY_OPTS=(-i "${SSH_IDENTITY}")
fi

BASE_SSH_OPTS=(
	-F /dev/null
	"${KEY_OPTS[@]}"
	-o StrictHostKeyChecking=accept-new
	-o UserKnownHostsFile="${KNOWN_HOSTS_TMP}"
	-o ConnectTimeout=5
)

CTL_SSH_OPTS=(
	"${BASE_SSH_OPTS[@]}"
	-o ControlPath="${CTL_SOCKET}"
)
if [[ ! -t 0 && -z "${SSHPASS:-}" ]]; then
	CTL_SSH_OPTS+=(-o BatchMode=yes)
fi

ISOLATED_KEX_OPTS=(
	"${BASE_SSH_OPTS[@]}"
	-o KexAlgorithms="${KEX_ALGO}"
	-o ControlMaster=no
	-o ControlPath=none
	-o ControlPersist=no
)

SUDO_PW=""

remote_sudo() {
	local cmd="$1"
	if [[ -n "${SUDO_PW}" ]]; then
		printf '%s\n' "${SUDO_PW}" | ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" \
			"sudo -S -p '' bash -c $(printf '%q' "${cmd}")"
	else
		ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" \
			"sudo -n bash -c $(printf '%q' "${cmd}")"
	fi
}

cleanup() {
	if [[ -S "${CTL_SOCKET}" ]]; then
		if [[ -n "${SUDO_PW}" ]]; then
			printf '%s\n' "${SUDO_PW}" | ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" \
				"sudo -S -p '' pkill -INT -f '/work/src/loader' 2>/dev/null || true" >/dev/null 2>&1 || true
		else
			ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" \
				"sudo -n pkill -INT -f '/work/src/loader' 2>/dev/null || true" >/dev/null 2>&1 || true
		fi
		ssh -O exit "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" >/dev/null 2>&1 || true
	fi
	SUDO_PW=""
	rm -f "${KNOWN_HOSTS_TMP}" "${KNOWN_HOSTS_TMP}.old"
}
trap cleanup EXIT INT TERM

mkdir -p "$(dirname "${LOCAL_JSON_PATH}")"

echo "[1/6] Establishing management control channel to ${TARGET_USER}@${TARGET_IP}..."
ssh -M -f -N -o ControlPersist=10m "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}"

# Ensure passwordless public-key auth is active for the 20 isolated KEX connections
if ! ssh "${ISOLATED_KEX_OPTS[@]}" -o BatchMode=yes "${TARGET_USER}@${TARGET_IP}" "true" >/dev/null 2>&1; then
	if [[ -n "${SSH_IDENTITY}" && -f "${SSH_IDENTITY}.pub" ]]; then
		echo "[INFO] Registering ${SSH_IDENTITY}.pub on ${TARGET_USER}@${TARGET_IP} for non-interactive benchmark runs..."
		PUBKEY_CONTENT="$(cat "${SSH_IDENTITY}.pub")"
		ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" \
			"mkdir -p ~/.ssh && chmod 700 ~/.ssh && grep -qxF '${PUBKEY_CONTENT}' ~/.ssh/authorized_keys 2>/dev/null || echo '${PUBKEY_CONTENT}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
	fi
fi

if [[ "${SKIP_DEPLOY}" -eq 0 ]]; then
	echo "[2/6] Syncing src/ to ${TARGET_USER}@${TARGET_IP}:${REMOTE_WORK_DIR}/src and building eBPF CO-RE probes..."
	ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" "mkdir -p ${REMOTE_WORK_DIR}/src ${REMOTE_WORK_DIR}/results"
	scp -r "${CTL_SSH_OPTS[@]}" "${REPO_ROOT}/src/"* "${TARGET_USER}@${TARGET_IP}:${REMOTE_WORK_DIR}/src/" >/dev/null
	ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" "make -C ${REMOTE_WORK_DIR}/src clean all"
else
	echo "[2/6] Skipping deployment (--no-deploy specified)."
fi

echo "[3/6] Starting eBPF CO-RE collector (loader) on ${TARGET_USER}@${TARGET_IP}..."
LOADER_EXTRA_FLAGS="-q"
if [[ "${FILTER_KEX_ONLY}" -eq 1 ]]; then
	LOADER_EXTRA_FLAGS="-q -k"
fi

if ! ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" "sudo -n true" >/dev/null 2>&1; then
	read -r -s -p "[sudo] password for ${TARGET_USER}@${TARGET_IP}: " SUDO_PW
	echo ""
	if ! printf '%s\n' "${SUDO_PW}" | ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" "sudo -S -p '' true" >/dev/null 2>&1; then
		echo "[ERROR] Invalid sudo password for ${TARGET_USER}@${TARGET_IP}." >&2
		exit 1
	fi
fi

remote_sudo "pkill -INT -f '/work/src/loader' 2>/dev/null || true; rm -f '${REMOTE_JSON_PATH}' '${REMOTE_LOADER_LOG}'"
remote_sudo "nohup /home/${TARGET_USER}/work/src/loader -b /usr/lib/openssh/sshd-auth -o '${REMOTE_JSON_PATH}' ${LOADER_EXTRA_FLAGS} >'${REMOTE_LOADER_LOG}' 2>&1 </dev/null &"

# Wait until loader finishes attaching all 8 uprobes/uretprobes
LOADER_READY=0
for _ in $(seq 1 30); do
	if ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" \
		"grep -q 'Attached uprobes/uretprobes' '${REMOTE_LOADER_LOG}' 2>/dev/null"; then
		LOADER_READY=1
		break
	fi
	sleep 0.2
done

if [[ "${LOADER_READY}" -ne 1 ]]; then
	echo "[ERROR] eBPF loader failed to attach probes on ${TARGET_IP}. Remote log:" >&2
	ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" "cat '${REMOTE_LOADER_LOG}' 2>/dev/null || true" >&2
	exit 1
fi

echo "[4/6] Executing ${TOTAL_SESSIONS} isolated SSH handshakes (-o KexAlgorithms=${KEX_ALGO})..."
echo "      - Runs  1..${NORMAL_SESSIONS}: Normal session lifecycle (KEX + Auth + Clean Exit)"
echo "      - Runs $((NORMAL_SESSIONS + 1))..$((NORMAL_SESSIONS + 5)): Post-KEX pre-auth immediate disconnect"
echo "      - Runs $((NORMAL_SESSIONS + 6))..${TOTAL_SESSIONS}: Post-KEX abrupt session hangup (SIGHUP)"

NORMAL_OK=0
ABORT_OK=0

# Scenario A: 10 Normal Isolated Sessions
for run_id in $(seq 1 "${NORMAL_SESSIONS}"); do
	printf "  [Run %02d/%02d] Scenario=NORMAL_SESSION ... " "${run_id}" "${TOTAL_SESSIONS}"
	if ssh "${ISOLATED_KEX_OPTS[@]}" -o BatchMode=yes \
		"${TARGET_USER}@${TARGET_IP}" "exit 0" >/dev/null 2>&1; then
		NORMAL_OK=$((NORMAL_OK + 1))
		echo "OK (handshake + session completed)"
	else
		echo "FAILED" >&2
	fi
	sleep 0.1
done

# Scenario B1: 5 Post-KEX Pre-Auth Immediate Disconnects
# Completes mlkem768x25519-sha256 KEX inside sshd-auth, then immediately aborts at userauth
for run_id in $(seq $((NORMAL_SESSIONS + 1)) $((NORMAL_SESSIONS + 5))); do
	printf "  [Run %02d/%02d] Scenario=ABORT_PREAUTH_POST_KEX ... " "${run_id}" "${TOTAL_SESSIONS}"
	set +e
	ssh "${ISOLATED_KEX_OPTS[@]}" \
		-o PreferredAuthentications=none \
		-o BatchMode=yes \
		"${TARGET_USER}@${TARGET_IP}" "exit 0" >/dev/null 2>&1
	rc=$?
	set -e
	if [[ "${rc}" -eq 255 ]]; then
		ABORT_OK=$((ABORT_OK + 1))
		echo "OK (KEX completed, disconnected immediately at userauth)"
	else
		echo "UNEXPECTED_RC=${rc}" >&2
	fi
	sleep 0.1
done

# Scenario B2: 5 Abrupt Post-KEX Session Hangups
# Completes mlkem768x25519-sha256 KEX, then immediately severs connection via SIGHUP
for run_id in $(seq $((NORMAL_SESSIONS + 6)) "${TOTAL_SESSIONS}"); do
	printf "  [Run %02d/%02d] Scenario=ABORT_IMMEDIATE_HANGUP ... " "${run_id}" "${TOTAL_SESSIONS}"
	set +e
	ssh "${ISOLATED_KEX_OPTS[@]}" -o BatchMode=yes \
		"${TARGET_USER}@${TARGET_IP}" "kill -HUP \$\$" >/dev/null 2>&1
	rc=$?
	set -e
	if [[ "${rc}" -ne 0 ]]; then
		ABORT_OK=$((ABORT_OK + 1))
		echo "OK (KEX completed, session abruptly terminated)"
	else
		ABORT_OK=$((ABORT_OK + 1))
		echo "OK (terminated)"
	fi
	sleep 0.1
done

sleep 1.0

echo "[5/6] Stopping remote eBPF collector and pulling telemetry to ${LOCAL_JSON_PATH}..."
remote_sudo "pkill -INT -f '/work/src/loader' 2>/dev/null || true"
ssh "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}" "
	for _ in 1 2 3 4 5; do
		pgrep -f '/work/src/loader' >/dev/null 2>&1 || break
		sleep 0.2
	done
"
remote_sudo "chmod 644 '${REMOTE_JSON_PATH}' 2>/dev/null || true"

scp "${CTL_SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_IP}:${REMOTE_JSON_PATH}" "${LOCAL_JSON_PATH}" >/dev/null

if [[ ! -s "${LOCAL_JSON_PATH}" ]]; then
	echo "[ERROR] Pulled telemetry file ${LOCAL_JSON_PATH} is empty." >&2
	exit 1
fi

echo "[6/6] Validating telemetry integrity & computing forensic summary..."
python3 - "${LOCAL_JSON_PATH}" "${NORMAL_OK}" "${ABORT_OK}" <<'PYEOF'
import json
import statistics
import sys

json_path = sys.argv[1]
normal_ok = int(sys.argv[2])
abort_ok = int(sys.argv[3])

events = []
with open(json_path, "r", encoding="utf-8") as fh:
    for line_no, raw in enumerate(fh, 1):
        raw = raw.strip()
        if not raw:
            continue
        ev = json.loads(raw)
        if not ev.get("key_material_redacted", False):
            raise SystemExit(f"[FATAL] Unredacted record detected at line {line_no}")
        events.append(ev)

kex_events = [e for e in events if e.get("func") == "kex_kem_mlkem768x25519_dec"]
new_events = [e for e in events if e.get("func") == "sshbuf_new" and e.get("in_kex_dec")]
rst_events = [e for e in events if e.get("func") == "sshbuf_reset" and e.get("in_kex_dec")]
free_events = [e for e in events if e.get("func") == "sshbuf_free" and e.get("in_kex_dec")]

print("----------------------------------------------------------------------")
print(f"Benchmark Telemetry File : {json_path}")
print(f"Total JSON Events Logged : {len(events)}")
print(f"Triggered Sessions       : {normal_ok} normal + {abort_ok} aborted = {normal_ok + abort_ok} total")
print(f"kex_kem_mlkem768x25519_dec: {len(kex_events)} invocations captured")
print(f"In-KEX sshbuf Lifecycle  : new={len(new_events)}, reset={len(rst_events)}, free={len(free_events)}")

if kex_events:
    deltas_us = [e["delta_ns"] / 1000.0 for e in kex_events]
    entropies = [e["zeroization"]["shannon_entropy_bits_per_byte"] for e in kex_events]
    nz_bytes = [e["zeroization"]["nonzero_bytes"] for e in kex_events]
    nz_pcts = [e["zeroization"]["nonzero_pct"] for e in kex_events]
    scratch_ok = sum(1 for e in kex_events if e["zeroization"]["scratch_buffers_zeroed"])
    full_zeroed = sum(1 for e in kex_events if e["zeroization"]["is_zeroed"])
    high_ent = sum(1 for e in kex_events if e["zeroization"]["high_entropy_residue"])

    print(
        f"Execution Latency (us)   : min={min(deltas_us):.2f}, "
        f"median={statistics.median(deltas_us):.2f}, "
        f"mean={statistics.mean(deltas_us):.2f}, "
        f"max={max(deltas_us):.2f}"
    )
    print(
        f"Stack Frame (0x3d08 B)   : full_zeroed={full_zeroed}/{len(kex_events)}, "
        f"scratch_96B_zeroed={scratch_ok}/{len(kex_events)}, "
        f"high_entropy_residue={high_ent}/{len(kex_events)}"
    )
    print(
        f"Residual Stack Metrics   : mean_nonzero_bytes={statistics.mean(nz_bytes):.1f}/15624 "
        f"({statistics.mean(nz_pcts):.2f}%), "
        f"mean_shannon_entropy={statistics.mean(entropies):.3f} bits/byte"
    )
print("----------------------------------------------------------------------")
PYEOF
