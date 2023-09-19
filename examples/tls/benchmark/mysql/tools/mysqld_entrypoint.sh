#!/bin/bash

systemctl daemon-reload
systemctl restart mysqld

PASSWORD_TXT=`cat /var/log/mysqld.log|grep temp`
PASSWORD_TMP=$(echo "$PASSWORD_TXT" | sed 's/.* //')

mysql --connect-expired-password -u root -p"$PASSWORD_TMP" << EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY 'Wsj.123456';
FLUSH PRIVILEGES;
EOF

HOSTNAME="127.0.0.1"
PORT="3306"
USERNAME="root"
PASSWORD="Wsj.123456"
DBNAME="IMAGES"
TABLENAME="images_table"

create_db_sql="create database IF NOT EXISTS ${DBNAME}"
mysql -h${HOSTNAME}  -P${PORT}  -u${USERNAME} -p${PASSWORD} -e "${create_db_sql}"

create_table_sql="create table IF NOT EXISTS ${TABLENAME} (id INT AUTO_INCREMENT PRIMARY KEY, image_name VARCHAR(255) NOT NULL, image_data LONGBLOB NOT NULL)"
mysql -h${HOSTNAME}  -P${PORT}  -u${USERNAME} -p${PASSWORD}  -D ${DBNAME} -e "${create_table_sql=}"

insert_sql="insert into ${TABLENAME}(image_name, image_data) values('java_logo', LOAD_FILE('/var/lib/mysql-files/Java_Logo.png'))"
mysql -h${HOSTNAME}  -P${PORT}  -u${USERNAME} -p${PASSWORD} -D ${DBNAME} -e "${insert_sql}"
