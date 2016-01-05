# Configuration for all the apps that are accessible using acl and custom DNS names

frontend http-in
bind 0.0.0.0:80
mode http
reqadd X-Forwarded-Proto:\ http
option tcplog
$acls
$use_backends

$internals

