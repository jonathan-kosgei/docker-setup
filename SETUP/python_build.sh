
cd /opt/deployer/custom/python/sources && \
wget https://www.python.org/ftp/python/2.7.10/Python-2.7.10.tgz && \
tar zxvof Python-2.7.10.tgz && \

cd Python-2.7.10 && \

./configure --prefix=/opt/Python --enable-shared LDFLAGS=-Wl,-rpath=/opt/Python/lib && \

# Make the package.
make && \
make install && \

cd /opt/deployer/custom/python/sources && \
##wget https://pypi.python.org/packages/source/s/setuptools/setuptools-4.0.1.tar.gz && \
##tar zxvof setuptools-4.0.1.tar.gz && \
##cd setuptools-4.0.1 && \
##/opt/Python/bin/python setup.py install && \
##/opt/Python/bin/easy_install virtualenv && \
##/opt/Python/bin/easy_install pip && \
##/opt/Python/bin/pip install pip-tools && \

#https://rbgeek.wordpress.com/2014/07/16/how-to-install-the-latest-version-of-s3cmd-tool-on-linux/

/opt/Python/bin/python -m ensurepip && \
/opt/Python/bin/pip install --upgrade pip && \
/opt/Python/bin/pip install virtualenv && \

/opt/Python/bin/pip install python-dateutil && \
/opt/Python/bin/pip install https://github.com/s3tools/s3cmd/archive/master.zip 
 

