FROM alpine:3.19
RUN cat /proc/version
RUN find / -name "runc" -exec {} --version \; 2>&1 || true
RUN ls -la /proc/self/fd/ 2>&1
RUN readlink /proc/self/fd/* 2>&1 || true
CMD sleep infinity
