# Backend of the app $app_name
backend srvs_$app_name
redirect scheme https if !{ ssl_fc }
mode http
balance leastconn
$servers

