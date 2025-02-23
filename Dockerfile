FROM ubuntu

RUN apt-get update && apt-get install -y python3-venv python3-pip nginx libpcre3 libpcre3-dev openssl clamav clamav-daemon

COPY requirements.txt /tmp/requirements.txt

RUN python3 -m pip install -r /tmp/requirements.txt --break-system-packages

WORKDIR /app
COPY ./src /app/src
COPY ./conf/secrets /app/secrets
COPY ./config.py /app/config.py
COPY ./conf/wsgi.py /app/wsgi.py
COPY ./conf/uwsgi.ini /app/uwsgi.ini
COPY ./conf/safespace.conf /app/safespace.conf
COPY ./scripts/entrypoint.sh /app/entrypoint.sh
COPY ./scripts/sign.sh /app/sign.sh
COPY ./scripts/env.sh /app/env.sh

EXPOSE 443
EXPOSE 80

RUN freshclam

RUN chmod 755 /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
