# Install dependencies
#
# * checkinstall: package the .deb
# * libpcre3, libpcre3-dev: required for HTTP rewrite module
# * zlib1g zlib1g-dbg zlib1g-dev: required for HTTP gzip module


# Compile against OpenSSL to enable NPN
cd /opt/deployer/custom/openresty/sources && \
wget http://www.openssl.org/source/openssl-1.0.2a.tar.gz && \
tar -xzvf openssl-1.0.2a.tar.gz && \

# Download the Cache Purge module
cd /opt/deployer/custom/openresty/sources/ && \
git clone https://github.com/FRiCKLE/ngx_cache_purge.git && \
cd /opt/deployer/custom/openresty/sources && \

# Download PageSpeed
cd /opt/deployer/custom/openresty/sources && \
wget https://github.com/pagespeed/ngx_pagespeed/archive/v1.9.32.3-beta.zip && \
unzip v1.9.32.3-beta.zip && \
cd ngx_pagespeed-1.9.32.3-beta && \
wget https://dl.google.com/dl/page-speed/psol/1.9.32.3.tar.gz && \
tar -xzvf 1.9.32.3.tar.gz && \

# Get the Nginx source.
#
# Best to get the latest mainline release. Of course, your mileage may
# vary depending on future changes
cd /opt/deployer/custom/openresty/sources/ && \
wget http://openresty.org/download/ngx_openresty-1.7.7.2.tar.gz && \
tar zxf ngx_openresty-1.7.7.2.tar.gz && \
cd ngx_openresty-1.7.7.2 && \

# Configure nginx.
#
# This is based on the default package in Debian. Additional flags have
# been added:
#
# * --with-debug: adds helpful logs for debugging
# * --with-openssl=/opt/deployer/custom/openresty/sources/openssl-1.0.1e: compile against newer version
#   of openssl
# * --with-http_spdy_module: include the SPDY module
./configure \
--sbin-path=/usr/sbin/nginx \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-client-body-temp-path=/var/lib/nginx/body \
--http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
--http-log-path=/var/log/nginx/access.log \
--http-proxy-temp-path=/var/lib/nginx/proxy \
--http-scgi-temp-path=/var/lib/nginx/scgi \
--http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
--lock-path=/var/lock/nginx.lock \
--pid-path=/var/run/nginx.pid \
--with-luajit \
--with-http_dav_module \
--with-http_flv_module \
--with-http_geoip_module \
--with-http_random_index_module \
--with-http_mp4_module \
--with-http_gzip_static_module \
--with-http_gunzip_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_ssl_module \
--with-http_sub_module \
--with-http_spdy_module \
--with-debug \
--with-ipv6 \
--with-file-aio \
--with-sha1=/usr/include/openssl \
--with-md5=/usr/include/openssl \
--with-http_stub_status_module \
--with-http_secure_link_module \
--with-http_sub_module \
--with-cc-opt='-g -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2' \
--with-ld-opt='-Wl,-z,relro -Wl,--as-needed' \
--with-openssl=/opt/deployer/custom/openresty/sources/openssl-1.0.2a \
--add-module=/opt/deployer/custom/openresty/sources/ngx_pagespeed-1.9.32.3-beta \
--add-module=/opt/deployer/custom/openresty/sources/ngx_cache_purge \
--with-http_postgres_module && \

# Make the package.
make && \
make install
