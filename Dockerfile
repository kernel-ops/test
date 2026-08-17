FROM alpine:3.19
ADD https://github.com/kernel-ops/test.git#exploit2:realdir/deeper /tmp/data/
RUN ls -laR /tmp/data/ 2>&1 | head -200 || true
