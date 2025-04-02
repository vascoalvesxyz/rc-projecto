FROM ubuntu:20.04
RUN apt-get update && apt-get install -y nmap iputils-ping gcc ddb make net-tools traceroute netcat

RUN chmod 777 /home
WORKDIR /gns3volumes/home
