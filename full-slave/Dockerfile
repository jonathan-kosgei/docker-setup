# DOCKER-VERSION 0.4.8

# am facing issue
# https://github.com/dotcloud/docker/issues/1123

FROM debian:jessie
 
MAINTAINER Sandeep Srinivasa "sss@lambdacurry.com"

#ADD SETUP/sources.list /etc/apt/sources.list


ENV DEBIAN_FRONTEND noninteractive

# this forces dpkg not to call sync() after package extraction and speeds up install
RUN echo "force-unsafe-io" > /etc/dpkg/dpkg.cfg.d/02apt-speedup
# we don't need and apt cache in a container
RUN echo "Acquire::http {No-Cache=True;};" > /etc/apt/apt.conf.d/no-cache

RUN apt-get -y update  && apt-get -y  install zsh curl htop wget git nginx openssh-server python-dev bzip2 libbz2-dev rsyslog cron postfix locales screen tmux aptitude python-software-properties build-essential libreadline-dev libssl-dev zlib1g-dev libxml2-dev libxslt-dev git libpq-dev libmysqlclient-dev libpq-dev libcurl4-openssl-dev libffi-dev imagemagick libjpeg-progs pngcrush python-software-properties software-properties-common daemontools lzop pv sudo vim
# install essentials
#RUN  apt-get -y -q install zsh build-essential curl wget git nginx openssh-server python-dev bzip2 libbz2-dev rsyslog cron postfix locales screen tmux 
RUN curl -sL https://deb.nodesource.com/setup | bash -
RUN apt-get -y  install nodejs



# prevent apt from starting postgres right after the installation
RUN echo "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d


#RUN aptitude -q -y update && aptitude -q -y upgrade &&  aptitude -q -y reinstall language-pack-en
RUN localedef --no-archive  -i en_US -f UTF-8 en_US.utf8 
ADD SETUP/locale.gen /etc/locale.gen
RUN dpkg-reconfigure -f noninteractive locales && echo "Asia/Kolkata" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata

#for postgres LC_CTYPE=en_US.UTF-8 
# and LC_COLLATE = C 

RUN update-locale LANGUAGE=en_US.UTF-8 LC_CTYPE="en_US.UTF-8" LC_NUMERIC="en_US.UTF-8" LC_TIME="en_US.UTF-8" LC_COLLATE="C" LC_MONETARY="en_US.UTF-8" LC_MESSAGES="en_US.UTF-8" LC_PAPER="en_US.UTF-8" LC_NAME="en_US.UTF-8" LC_ADDRESS="en_US.UTF-8" LC_TELEPHONE="en_US.UTF-8" LC_MEASUREMENT="en_US.UTF-8" LC_IDENTIFICATION="en_US.UTF-8" LC_ALL=en_US.UTF-8






#openresty
RUN mkdir -p /opt/deployer/custom/openresty/sources && aptitude install -y zip checkinstall libpcre3 libpcre3-dev zlib1g zlib1g-dbg zlib1g-dev libgeoip-dev build-essential libpcre3-dev libssl-dev libpq-dev
ADD SETUP/nginx_17_build.sh  /opt/deployer/custom/openresty/
RUN chmod +x /opt/deployer/custom/openresty/nginx_17_build.sh 
RUN zsh -c /opt/deployer/custom/openresty/nginx_17_build.sh

#golang
RUN mkdir -p /opt/deployer/custom/golang/sources && aptitude install -y zip checkinstall libpcre3 libpcre3-dev zlib1g zlib1g-dbg zlib1g-dev libgeoip-dev build-essential libpcre3-dev libssl-dev libpq-dev
ADD SETUP/install_golang.sh /opt/deployer/custom/golang/
RUN chmod +x /opt/deployer/custom/golang/install_golang.sh
RUN zsh -c /opt/deployer/custom/golang/install_golang.sh


#redis
RUN mkdir -p /opt/deployer/custom/redis/sources
ADD SETUP/redis_build.sh /opt/deployer/custom/redis/redis_build.sh
RUN chmod +x /opt/deployer/custom/redis/redis_build.sh
RUN zsh -c /opt/deployer/custom/redis/redis_build.sh

#memcached
RUN  groupadd memcache && useradd -r -g memcache -s /sbin/nologin -M -d /var/run/memcache memcache && aptitude install memcached


RUN mkdir -p /var/run/sshd &&  mkdir -p /var/run/supervisor && mkdir -p /var/log/supervisor && mkdir -p /var/run/app && mkdir -p /var/run/supervisor && mkdir -p /var/run/pgbouncer && mkdir -p /var/log/nginx && mkdir -p /var/log/rsyslog


############################################### POSTGRESQL########################### 

# Add the PostgreSQL PGP key to verify their Debian packages.
# It should be the same key as https://www.postgresql.org/media/keys/ACCC4CF8.asc

# Add PostgreSQL's repository. It contains the most recent stable release
#     of PostgreSQL, ``9.3``.
# Update the Ubuntu and PostgreSQL repository indexes

# Install ``python-software-properties``, ``software-properties-common`` and PostgreSQL 9.3
#  There are some warnings (in red) that show up during the build. You can hide
#  them by prefixing each apt-get statement with DEBIAN_FRONTEND=noninteractive

RUN wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add - && echo "deb http://apt.postgresql.org/pub/repos/apt/ wheezy-pgdg main" > /etc/apt/sources.list.d/pgdg.list && apt-get update && apt-get -y -q install postgresql-9.3 postgresql-client-9.3 postgresql-contrib-9.3 pgbouncer stunnel4

# Run the rest of the commands as the ``postgres`` user created by the ``postgres-9.3`` package when it was ``apt-get installed``
USER postgres

# Create a PostgreSQL role named ``docker`` with ``docker`` as the password and
# then create a database `docker` owned by the ``docker`` role.
# Note: here we use ``&&\`` to run commands one after the other - the ``\``
#       allows the RUN command to span multiple lines.
#RUN    /etc/init.d/postgresql start &&\
#    psql --command "CREATE USER docker WITH SUPERUSER PASSWORD 'docker';" &&\
#    createdb -O docker docker

# Adjust PostgreSQL configuration so that remote connections to the
# database are possible. 
RUN echo "host all  all    0.0.0.0/0  md5" >> /etc/postgresql/9.3/main/pg_hba.conf


# Expose the PostgreSQL port
#EXPOSE 5432

#####VOLUME  [ "/data", "/var/log/postgresql", "/var/lib/postgresql"]
#RUN mkdir -p /var/lib/postgresql/9.3/main
#RUN chown postgres:postgres /var/lib/postgresql

##############################################################################################



USER root 
RUN useradd -d /home/deployer -m -s /bin/zsh deployer && echo deployer:12345678 | chpasswd && mkdir -p /opt/deployer && chown deployer:deployer /opt/deployer

ADD SETUP/sudoers /etc/sudoers
ADD SETUP/zshenv /etc/zsh/zshenv


########### SSH ##################
USER root 
RUN mkdir -p /home/deployer/.ssh
#I just dont want to mess about with the GIT_SSH nonsense
ADD SETUP/deploy_rsa /home/deployer/.ssh/id_rsa
RUN chown  deployer:deployer -R /home/deployer/.ssh/




USER deployer
ENV HOME /home/deployer
WORKDIR /home/deployer
RUN cd /home/deployer && chmod 700 $HOME/.ssh/id_rsa && chmod 700 $HOME/.ssh  && touch $HOME/.ssh/known_hosts && ssh-keyscan bitbucket.org > $HOME/.ssh/known_hosts && ssh-keyscan github.com >> $HOME/.ssh/known_hosts

###################### RUBY #############3

USER root 
# Install rbenv
RUN git clone https://github.com/sstephenson/rbenv.git /usr/local/rbenv
ADD SETUP/rbenv.sh /etc/profile.d/rbenv.sh
#RUN chmod +x /etc/profile.d/rbenv.sh

# install ruby-build
RUN mkdir /usr/local/rbenv/plugins && git clone https://github.com/sstephenson/ruby-build.git /usr/local/rbenv/plugins/ruby-build

ENV RBENV_ROOT /usr/local/rbenv
ENV PATH $RBENV_ROOT/bin:$RBENV_ROOT/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
#ENV RUBY_CONFIGURE_OPTS --with-readline-dir="/usr/lib/x86_64-linux-gnu/libreadline.so"

# install ruby2
RUN rbenv install 2.3.0 && rbenv global 2.3.0 && rbenv rehash && gem install bundle --no-ri --no-rdoc && gem update --system --no-ri --no-rdoc 



##################  PYTHON ##################
#python
RUN mkdir -p /opt/deployer/custom/python/sources
ADD SETUP/python_build.sh /opt/deployer/custom/python/python_build.sh
RUN chmod +x /opt/deployer/custom/python/python_build.sh 
RUN zsh -c /opt/deployer/custom/python/python_build.sh

USER root
ENV HOME /

RUN  /opt/Python/bin/virtualenv --system-site-packages --always-copy /opt/wal-e && /opt/wal-e/bin/pip install git+https://github.com/wal-e/wal-e && mkdir -p /etc/wal-e.d/env && chown -R postgres:postgres /etc/wal-e.d 

RUN  /opt/Python/bin/pip install supervisor awscli


############################# JAVA + ELASTICSEARCH ##################
#RUN echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu precise main" | tee -a /etc/apt/sources.list && echo "deb-src http://ppa.launchpad.net/webupd8team/java/ubuntu precise main" | tee -a /etc/apt/sources.list && apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys EEA14886 && aptitude update && echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections &&  aptitude install -y oracle-java8-installer

RUN mkdir -p /opt/deployer/custom/java/sources
ADD SETUP/java_install.sh /opt/deployer/custom/java/java_install.sh
RUN chmod +x /opt/deployer/custom/java/java_install.sh
RUN zsh -c /opt/deployer/custom/java/java_install.sh 



ENV ES_PKG_NAME elasticsearch-1.4.2

# Install ElasticSearch.
RUN \
  mkdir -p /opt/ElasticSearch && \
  cd /opt/ElasticSearch && \
  wget https://download.elasticsearch.org/elasticsearch/elasticsearch/$ES_PKG_NAME.tar.gz && \
  tar xvzf $ES_PKG_NAME.tar.gz && \
  #rm -f $ES_PKG_NAME.tar.gz && \
  mv /opt/ElasticSearch/$ES_PKG_NAME /opt/ElasticSearch/elasticsearch && \
  /opt/ElasticSearch/elasticsearch/bin/plugin -i elasticsearch/marvel/latest 



######################################## neo4j #########################################
RUN mkdir -p /opt/deployer/neo4j/sources && mkdir -p /opt/deployer/neo4j/neo4j  && wget http://neo4j.com/artifact.php?name=neo4j-community-3.0.0-unix.tar.gz  -O /opt/deployer/neo4j/sources/neo4j.tar.gz && tar xvof /opt/deployer/neo4j/sources/neo4j.tar.gz -C /opt/deployer/neo4j/neo4j --strip-components 1 

############################### SOURCE ##############################
USER deployer
ENV HOME /home/deployer
WORKDIR /home/deployer
###unset rbenv_root
RUN echo 'export RBENV_ROOT=' >> ~/.zshenv && git clone https://github.com/sstephenson/rbenv.git  $HOME/.rbenv && git clone https://github.com/sstephenson/ruby-build.git $HOME/.rbenv/plugins/ruby-build
RUN rm -rf $HOME/.rbenv/versions && ln -s /usr/local/rbenv/versions $HOME/.rbenv
RUN zsh -c 'echo $PATH | tr  : "\n"' && zsh -c 'echo $RBENV_ROOT | tr : "\n"' && zsh -c 'which rbenv' && zsh -c "rbenv global 2.3.0" && zsh -c "rbenv  rehash" 

USER deployer


RUN cd /opt/deployer && mkdir -p /opt/deployer/run  && git clone git@bitbucket.org:redcarpetup/redcarpet-web-new.git cherry_web && git clone git@bitbucket.org:redcarpetup/redcarpet-web-new.git plum_web && git clone git@bitbucket.org:redcarpetup/redcarpet-web-new.git production_web  && git clone -b master git@bitbucket.org:redcarpetup/desktop-ux.git cherry_api && git clone -b master git@bitbucket.org:redcarpetup/desktop-ux.git production_api && git clone -b master git@bitbucket.org:redcarpetup/oms prod_oms && git clone -b master git@bitbucket.org:redcarpetup/oms cherry_oms 


RUN /opt/Python/bin/virtualenv --system-site-packages --always-copy /opt/deployer/cherry_api/desktop-flask/flask-distro && /opt/Python/bin/virtualenv --system-site-packages --always-copy /opt/deployer/production_api/desktop-flask/flask-distro && /opt/Python/bin/virtualenv --system-site-packages --always-copy /opt/deployer/cherry_api/api/flask-distro && /opt/Python/bin/virtualenv --system-site-packages --always-copy /opt/deployer/production_api/api/flask-distro

RUN /opt/deployer/cherry_api/desktop-flask/flask-distro/bin/pip install -r /opt/deployer/cherry_api/desktop-flask/requirements.txt &&  /opt/deployer/production_api/desktop-flask/flask-distro/bin/pip install -r /opt/deployer/production_api/desktop-flask/requirements.txt && /opt/deployer/cherry_api/api/flask-distro/bin/pip install -r /opt/deployer/cherry_api/api/requirements.txt && /opt/deployer/production_api/api/flask-distro/bin/pip install -r /opt/deployer/production_api/api/requirements.txt

RUN zsh -c "gem install  bundle && bundle install --gemfile /opt/deployer/cherry_web/Gemfile --path /opt/deployer/GEMS && bundle install --gemfile /opt/deployer/plum_web/Gemfile --path /opt/deployer/GEMS &&  bundle install --gemfile /opt/deployer/production_web/Gemfile --path /opt/deployer/GEMS" 

RUN  cd /opt/deployer && git clone https://github.com/letsencrypt/letsencrypt  && cd /opt/deployer/letsencrypt 

################## SYSTEM CONFIGS #####################
USER root
ENV HOME /
#RUN mkdir -p /etc/nginx/ssl/letsencrypt/ && /opt/deployer/letsencrypt/letsencrypt-auto  -t -vvv --debug --help 

#certonly --keep --debug --webroot -w /etc/nginx/ssl/letsencrypt/ --cert-path /etc/nginx/ssl/letsencrypt/ --agree-tos  --email sss@lambdacurry.com -d payclan.com 

RUN mkdir /var/log/app 
RUN chown deployer:deployer -R /var/log/app 
RUN chown deployer:deployer -R /var/run/app
RUN chown -R stunnel4:stunnel4 /var/run/stunnel4 && touch /var/run/rsyslogd.pid  &&  rm /var/run/rsyslogd.pid
VOLUME /var/log
VOLUME /var/log/app
VOLUME /var/run

RUN echo 'export PATH="/opt/Python/bin:$PATH"' > /etc/profile.d/supervisor.sh
RUN cat /etc/profile.d/supervisor.sh >> /etc/environment
RUN mkdir -p /var/cache/nginx/cached
ADD  SETUP/zshrc /etc/zsh/zlogin
ADD  SETUP/zprofile /etc/zsh/zprofile
ADD SETUP/s3cfg /etc/s3cfg
RUN echo "AKINGQ"> /etc/wal-e.d/env/AWS_ACCESS_KEY_ID && echo "Rz0aQa6i"> /etc/wal-e.d/env/AWS_SECRET_ACCESS_KEY && echo 's3://pgpcom/sofer-tto'> /etc/wal-e.d/env/WALE_S3_PREFIX &&  echo "access_key = AKIKSD" >> /etc/s3cfg && echo "secret_key = Rz0aQJi" >> /etc/s3cfg  && echo "bucket_location = ap-southeast-1" >> /etc/s3cfg

#s3cmd  --config /etc/s3cfg ls s3://pgbucketredcarpetupcom/s3cmd 

ADD SETUP/nginx /etc/nginx/
ADD SETUP/sshd_config /etc/ssh/sshd_config
ADD SETUP/ssh_config /etc/ssh/ssh_config
ADD SETUP/nginx_default /etc/nginx/sites-available/default



ADD SETUP/supervisord.conf /etc/supervisord.conf
ADD SETUP/supervisord.d /etc/supervisord.d
ADD SETUP/rsyslog.conf /etc/rsyslog.d/50-default.conf
ADD SETUP/logrotate.conf /etc/logrotate.d/rsyslog
ADD SETUP/redis/redis.conf /etc/redis.conf
ADD SETUP/sysctl_local.conf /etc/sysctl.d/local.conf
ADD SETUP/redis_backup.sh /etc/redis_backup.sh
ADD SETUP/crontab /etc/crontab
ADD postgres_config /etc/postgresql/9.3/main
ADD SETUP/elasticsearch.yml /etc/elasticsearch.yml
ADD SETUP/.gitconfig /home/deployer/.gitconfig
ADD SETUP/stunnel.conf /etc/stunnel/stunnel-pgbouncer.conf
ADD SETUP/rds-combined-ca-bundle.pem /etc/stunnel/rds-combined-ca-bundle.pem
ADD SETUP/pgbouncer-users.txt /etc/pgbouncer/users.txt
ADD SETUP/pgbouncer.ini /etc/pgbouncer/pgbouncer.ini
ADD SETUP/pgbouncer-cherry.ini /etc/pgbouncer/pgbouncer-cherry.ini
ADD SETUP/limits.conf /etc/security/limits.conf
ADD SETUP/go-wrapper /usr/local/bin/
# Define commonly used JAVA_HOME variable
ENV JAVA_HOME /usr/lib/jvm/jdk1.8.0_66/ 

CMD ["/opt/Python/bin/supervisord", "-c", "/etc/supervisord.conf"]
#CMD ["/usr/bin/zsh"]


#sudo chown -R stunnel4:stunnel4 /var/run/stunnel4/
