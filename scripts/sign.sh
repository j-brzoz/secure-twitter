#!/bin/sh
##
##  sign.sh -- Sign a SSL Certificate Request (CSR)
##  Copyright (c) 1998 Ralf S. Engelschall, All Rights Reserved. 
##

#   argument line handling
CSR=$1
if [ $# -ne 1 ]; then
    echo "Usage: sign.sign <whatever>.csr"; exit 1
fi
if [ ! -f $CSR ]; then
    echo "CSR not found: $CSR"; exit 1
fi
case $CSR in
   *.csr ) CERT="`echo $CSR | sed -e 's/\.csr/.crt/'`" ;;
       * ) CERT="$CSR.crt" ;;
esac

#   make sure environment exists
if [ ! -d ca.db.certs ]; then
    mkdir /etc/nginx/ssl/ca.db.certs
fi
if [ ! -f ca.db.serial ]; then
    echo '01' >/etc/nginx/ssl/ca.db.serial
fi
if [ ! -f ca.db.index ]; then
    cp /dev/null /etc/nginx/ssl/ca.db.index
fi

#   create an own SSLeay config
cat >/etc/nginx/ssl/ca.config <<EOT
[ ca ]
default_ca              = CA_own
[ CA_own ]
dir                     = /etc/nginx/ssl
certs                   = \$dir
new_certs_dir           = \$dir/ca.db.certs
database                = \$dir/ca.db.index
serial                  = \$dir/ca.db.serial
RANDFILE                = \$dir/ca.db.rand
certificate             = \$dir/ca.crt
private_key             = \$dir/ca.key
default_days            = 365
default_crl_days        = 30
default_md              = sha256
preserve                = no
policy                  = policy_anything
[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
EOT

#  sign the certificate
echo "CA signing: $CSR -> $CERT:"
#ssleay ca -config ca.config -out $CERT -infiles $CSR 
# above commented out by kcl and substituted below
openssl ca -config /etc/nginx/ssl/ca.config -batch -out $CERT -infiles $CSR
echo "CA verifying: $CERT <-> CA cert"
#ssleay verify -CAfile ca.crt $CERT
openssl verify -CAfile /etc/nginx/ssl/ca.crt $CERT

#  cleanup after SSLeay 
rm -f /etc/nginx/ssl/ca.config
rm -f /etc/nginx/ssl/ca.db.serial.old
rm -f /etc/nginx/ssl/ca.db.index.old

#  die gracefully
exit 0

