FROM ubuntu

MAINTAINER Agustin Chiappe Berrini

ARG zookeeper
ARG subnet_dns
ARG port=2288

ENV ZOO $zookeeper

VOLUME /etc/haproxy

WORKDIR /opt/pegboard
ADD . /opt/pegboard

RUN apt-get update
RUN apt-get install -y python-pip python-dev build-essential 
RUN pip install --upgrade pip 
RUN pip install --upgrade virtualenv 
RUN pip install kazoo
RUN python pegboard.py install --zookeeper $zookeeper --port $port --config-frontend haproxy_frontend.cfg.tpl --config-backend haproxy_backend.cfg.tpl --config-tcp haproxy_tcp.cfg.tpl --config-general haproxy_general.cfg.tpl --subnet-dns $subnet_dns --no-force-restart

CMD python pegboard.py start --zookeeper $ZOO --no-force-restart && /bin/bash
