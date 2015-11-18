# Configuration for all the apps that are accessible using acl and custom DNS names

frontend https-in
bind 0.0.0.0:443 ssl crt /opt/haproxy/haproxy.pem
mode http
reqadd X-Forwarded-Proto:\ https
option tcplog
$acls
$use_backends

$internals


