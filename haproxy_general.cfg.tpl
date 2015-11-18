# General section with all the global values.
global
daemon
nbproc 2
pidfile /var/run/haproxy-private.pid
log 127.0.0.1 local0
log 127.0.0.1 local1 notice
maxconn 2048
tune.ssl.default-dh-param 2048

defaults
log            global
retries             30000
maxconn          150000
timeout connect  150000
timeout client  150000
timeout server  150000
option httplog
option dontlognull
option forwardfor
option http-server-close

listen stats
bind 10.10.0.126:9090
balance
mode http
stats enable
stats auth admin:admin
stats uri /haproxy?stats

