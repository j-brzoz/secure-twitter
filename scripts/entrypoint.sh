#!/bin/bash

chmod 755 /app/env.sh
source env.sh
rm env.sh

chmod 644 /app/config.py
chmod 644 /app/safespace.conf
chmod 600 /app/secrets
chown www-data:www-data /app/secrets
chmod 644 /app/uwsgi.ini
chmod 644 /app/wsgi.py

mkdir -p /var/run/clamav
chown clamav:clamav /var/run/clamav
chmod 755 /var/run/clamav
freshclam --daemon
clamd &

cp /app/safespace.conf /etc/nginx/sites-available/safespace.conf
ln -s /etc/nginx/sites-available/safespace.conf /etc/nginx/sites-enabled/safespace.conf
rm /etc/nginx/sites-available/default
rm /etc/nginx/sites-enabled/default

mkdir /etc/nginx/ssl
chmod 700 /etc/nginx/ssl

SAFESPACE="/C=PL/ST=Mazowieckie/L=Warszawa/O=Safespace/CN=safespace.com"
AGENCY="/C=PL/ST=Mazowieckie/L=Warszawa/O=ImportantAgency/CN=important-agency.com"
mv ./sign.sh /etc/nginx/ssl/sign.sh
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/ca.key -out /etc/nginx/ssl/ca.crt -subj "$AGENCY"
openssl req -newkey rsa:2048 -nodes -keyout /etc/nginx/ssl/safespace.key -out /etc/nginx/ssl/safespace.csr -subj "$SAFESPACE"
/etc/nginx/ssl/sign.sh /etc/nginx/ssl/safespace.csr
service nginx restart

flask db init
flask db migrate
flask db upgrade

chown www-data: /app/instance
chown www-data: /app/instance/db.sqlite
chmod 700 /app/instance
chown www-data: /app/src/static/uploads
chmod 700 /app/src/static/uploads

uwsgi --ini /app/uwsgi.ini --thunder-lock