FROM debian:jessie
 
MAINTAINER Jonathan Kosgei "jonathan@saharacluster.com"

ADD build.sh  /opt/python/

RUN chmod +x /opt/python/build.sh

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
    git \
    uwsgi \
    aptitude \
    uwsgi-plugin-python \
    wget \
    libpq-dev \
    python-dev \
    python-pip \
    libssl-dev \
    libyaml-dev \
    zlib1g-dev \
    libbz2-dev \
    libsqlite3-dev \
    build-essential ;\
    mkdir -p /opt/python/sources ;\
    ./opt/python/build.sh &&\
    aptitude -fy remove \
    build-essential\
    wget\
    git

COPY python /app

#RUN git clone https://github.com/sstephenson/rbenv.git /usr/local/rbenv

#ADD SETUP/rbenv.sh /etc/profile.d/rbenv.sh

#RUN mkdir /usr/local/rbenv/plugins && git clone https://github.com/sstephenson/ruby-build.git /usr/local/rbenv/plugins/ruby-build

#ENV RBENV_ROOT /usr/local/rbenv
#ENV PATH $RBENV_ROOT/bin:$RBENV_ROOT/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

#RUN rbenv install 2.3.0 && rbenv global 2.3.0 && rbenv rehash && gem install bundle --no-ri --no-rdoc && gem update --system --no-ri --no-rdoc 

WORKDIR /app

RUN pip install -r /app/requirements.txt

ENTRYPOINT uwsgi --chdir /app --ini /app /app/app.ini --plugins python --limit-as 512