#!/bin/bash

./mysql_server_startup.sh

docker run -it --network=host --rm -v `pwd`:`pwd` -w `pwd` ubuntu:22.04 ./mysql_client_entrypoint.sh