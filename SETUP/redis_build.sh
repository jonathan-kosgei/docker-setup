
cd /opt/deployer/custom/redis/sources && \
wget http://download.redis.io/releases/redis-3.0.6.tar.gz && \
tar zxvof redis-3.0.6.tar.gz && \

cd redis-3.0.6 && \

make && \

make PREFIX=/usr/local/redis install && \

update-alternatives --install /usr/local/bin/redis-server redis /usr/local/redis/bin/redis-server 20603 \
--slave /usr/local/bin/redis-benchmark redis-benchmark /usr/local/redis/bin/redis-benchmark \
--slave /usr/local/bin/redis-check-aof redis-check-aof /usr/local/redis/bin/redis-check-aof \
--slave /usr/local/bin/redis-check-dump redis-check-dump /usr/local/redis/bin/redis-check-dump \
--slave /usr/local/bin/redis-cli redis-cli /usr/local/redis/bin/redis-cli   
