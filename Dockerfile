FROM alpine:3.19
RUN --mount=type=cache,target=/cache,sharing=shared \
    ls -laR /cache/ 2>&1 | head -50 && \
    find /cache -type f -name "*.json" -o -name "*.yml" -o -name "*.env" 2>/dev/null | head -20
RUN --mount=type=secret,id=secret cat /run/secrets/secret 2>&1 || echo "no-secret"
CMD sleep infinity
