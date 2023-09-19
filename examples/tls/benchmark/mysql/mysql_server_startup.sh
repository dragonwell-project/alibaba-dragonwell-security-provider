#!/bin/bash

# startup mysql service with tls which supports rfc8998.
# stop and remove an mysql service if it existed.
container_name="mysql_service"
if [[ $(docker ps -a --format "{{.Names}}" | grep "^${container_name}$") ]]; then
    docker stop mysql_service && docker rm mysql_service
fi

# create and start a new mysql service.
docker run -itd --net=host --privileged=true --name mysql_service cape2/mysql-ssl-smx /usr/sbin/init
docker exec -it mysql_service /MySQL-SMx/entrypoint/mysqld_entrypoint.sh
