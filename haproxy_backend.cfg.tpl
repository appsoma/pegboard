# Backend of the app $app_name
backend srvs_$app_name
mode http
balance leastconn
$servers

