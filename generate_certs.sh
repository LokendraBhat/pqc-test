#!/usr/bin/env bash
# generate_certs.sh - build two test PKIs with the SAME structure (root -> intermediate -> leaf):
#   ecdsa/  : ECDSA P-256 everywhere      (classical authentication)
#   mldsa/  : ML-DSA-65 everywhere        (post-quantum authentication, FIPS 204)
# Keeping the chain depth identical means the only difference between the two is the algorithm.
# Needs OpenSSL >= 3.5 (native ML-DSA). Writes to $DIR; does not touch your existing /root/pqc-ca.
set -euo pipefail
DIR=${DIR:-/root/pqc-bench-ca}; CN=${CN:-pqc.example.com}; DAYS=${DAYS:-365}
mkdir -p "$DIR"; cd "$DIR"

ca_ext=$(mktemp); int_ext=$(mktemp); leaf_ext=$(mktemp)
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' > "$ca_ext"
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$int_ext"
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$CN" > "$leaf_ext"

newkey(){ # $1 type $2 out
  if [ "$1" = ecdsa ]; then openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2"
  else openssl genpkey -algorithm ML-DSA-65 -out "$2"; fi
  chmod 600 "$2"
}

for t in ecdsa mldsa; do
  mkdir -p "$t"; cd "$t"
  newkey $t root.key
  openssl req -x509 -new -key root.key -subj "/CN=PQC Bench Root ($t)" -days $DAYS \
          -extensions v3 -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n'; cat "$ca_ext") -out root.crt
  newkey $t int.key
  openssl req -new -key int.key -subj "/CN=PQC Bench Intermediate ($t)" -out int.csr
  openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -days $DAYS -extfile "$int_ext" -out int.crt
  newkey $t leaf.key
  openssl req -new -key leaf.key -subj "/CN=$CN" -out leaf.csr
  openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -days $DAYS -extfile "$leaf_ext" -out leaf.crt
  cat leaf.crt int.crt > fullchain.pem          # what nginx sends (root is NOT sent)
  echo "== $t =="
  for c in root int leaf; do
    printf '  %-5s %s | %s\n' "$c" \
      "$(openssl x509 -in $c.crt -noout -text | sed -n 's/.*Public Key Algorithm: *//p' | head -1)" \
      "$(openssl x509 -in $c.crt -noout -text | sed -n 's/.*Signature Algorithm: *//p' | head -1)"
  done
  openssl verify -CAfile root.crt -untrusted int.crt leaf.crt
  echo "  fullchain size: $(openssl crl2pkcs7 -nocrl -certfile fullchain.pem -outform DER 2>/dev/null | wc -c) bytes (DER, approx. what goes on the wire)"
  cd ..
done
rm -f "$ca_ext" "$int_ext" "$leaf_ext"
echo "Done. nginx: $DIR/{ecdsa,mldsa}/fullchain.pem + leaf.key ; clients verify with $DIR/{ecdsa,mldsa}/root.crt"
