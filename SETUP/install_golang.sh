GOLANG_VERSION=1.4.3 && \
GOLANG_DOWNLOAD_URL=https://golang.org/dl/go$GOLANG_VERSION.src.tar.gz && \
GOLANG_DOWNLOAD_SHA1=486db10dc571a55c8d795365070f66d343458c48 && \
GOPATH=/opt/Golang && \
mkdir -p /opt/Golang && \
cd $GOPATH && \
mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH" && \
curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
        && echo "$GOLANG_DOWNLOAD_SHA1  golang.tar.gz" | sha1sum -c - \
        && tar -C /usr/src -xzf golang.tar.gz \
        && rm golang.tar.gz \
        && cd /usr/src/go/src && ./make.bash --no-clean 2>&1

