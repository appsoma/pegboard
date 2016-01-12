# Configuration for the app $app_name
# Using port $service_port
listen $app_name-$service_port
bind 0.0.0.0:$service_port
mode tcp
option tcplog
balance leastconn
