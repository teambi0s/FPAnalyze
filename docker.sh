#!/bin/bash

docker build -t container .
docker run -dit --privileged container
id=$(docker ps | awk 'FNR == 2 {print $1}')
docker exec -it $id /bin/bash

