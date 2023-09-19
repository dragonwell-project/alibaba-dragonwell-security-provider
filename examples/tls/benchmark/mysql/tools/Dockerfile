FROM openanolis/anolisos:8.8 as builder

RUN yum update -y && yum install -y wget zip perl make gcc

WORKDIR /
RUN wget https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/8.3.3.zip && unzip 8.3.3.zip && rm -rf 8.3.3.zip
RUN pushd Tongsuo-8.3.3 && mkdir -p build && \
    ./config --libdir=lib --prefix=/Tongsuo-8.3.3/build enable-weak-ssl-ciphers && \
    make -j8 && make install && tar -zcvf build.tar.gz build && popd

FROM openanolis/anolisos:8.8

RUN yum update -y && yum install -y https://dev.mysql.com/get/mysql80-community-release-el8-4.noarch.rpm && \
    yum module disable mysql -y && dnf install mysql-server -y

WORKDIR /MySQL-SMx

COPY --from=builder /Tongsuo-8.3.3/build.tar.gz .
RUN tar -zxvf build.tar.gz && rm -rf build.tar.gz

WORKDIR /MySQL-SMx/entrypoint
COPY mysqld_entrypoint.sh .

COPY picture/Java_Logo.png /var/lib/mysql-files

WORKDIR /MySQL-SMx/ca
COPY ca .

RUN echo 'LD_LIBRARY_PATH=/MySQL-SMx/build/lib:$LD_LIBRARY_PATH' >> /root/.bashrc && \
    echo 'PATH=/MySQL-SMx/build/bin:$PATH' >> /root/.bashrc

RUN echo 'require_secure_transport=ON' >> /etc/my.cnf && \
    echo 'tls_ciphersuites=TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3' >> /etc/my.cnf && \
    echo 'tls_version=TLSv1.3' >> /etc/my.cnf && \
    echo 'ssl_ca=/MySQL-SMx/ca/ca.pem' >> /etc/my.cnf && \
    echo 'ssl_cert=/MySQL-SMx/ca/server-cert.pem' >> /etc/my.cnf && \
    echo 'ssl_key=/MySQL-SMx/ca/server-key.pem' >> /etc/my.cnf && \
    echo 'Environment=LD_LIBRARY_PATH=/MySQL-SMx/build/lib' >> /etc/systemd/system/multi-user.target.wants/mysqld.service

ENV PATH=/MySQL-SMx/build/bin:$PATH
ENV LD_LIBRARY_PATH=/MySQL-SMx/build/lib:$LD_LIBRARY_PATH

RUN chmod 755 /MySQL-SMx/entrypoint/mysqld_entrypoint.sh
