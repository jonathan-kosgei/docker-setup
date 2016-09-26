JDK_ALT_LINK_JAVA=/usr/bin/java
URL_TO_DOWNLOAD='http://download.oracle.com/otn-pub/java/jdk/8u66-b17/jdk-8u66-linux-x64.tar.gz'

JDK8_ARCHIVE=$(basename $URL_TO_DOWNLOAD)

 wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie"  "${URL_TO_DOWNLOAD}" && \
tar zxvf "${JDK8_ARCHIVE}" && \
mkdir -p /usr/lib/jvm && \
mv jdk1.8.0_66/ /usr/lib/jvm/ && \
update-alternatives --install /usr/bin/java java /usr/lib/jvm/jdk1.8.0_66/bin/java 1008000060
