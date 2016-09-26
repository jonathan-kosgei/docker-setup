FROM debian:jessie
 
MAINTAINER Jonathan Kosgei "jonathan@saharacluster.com"

ADD build.sh  /opt/nginx/

RUN chmod +x /opt/nginx/build.sh

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y aptitude;\
    mkdir -p /opt/nginx/sources \
    /var/lib/nginx/body \
    /usr/share/nginx/html \
    /etc/nginx/ssl \
    /etc/nginx/sites-available \
    /etc/nginx/sites-enabled;\
    aptitude install -y \
    build-essential \
    wget \
    git \
    unzip \
    openssl \
    libpcre3 \
    libpcre3-dev \
    zlib1g \
    zlib1g-dbg \
    zlib1g-dev \
    libgeoip-dev ;\
    ./opt/nginx/build.sh ;\
    aptitude -fy remove \
    build-essential\
    wget\
    git

COPY nginx.crt /etc/nginx/ssl/nginx.crt

COPY nginx.key /etc/nginx/ssl/nginx.key

COPY index.html /usr/share/nginx/html

COPY nginx.conf /etc/nginx/nginx.conf

COPY py /etc/nginx/sites-available/py

RUN ln -s /etc/nginx/sites-available/py /etc/nginx/sites-enabled/py

CMD nginx -g 'daemon off;'