# Pegboard

A pegboard is the place where you put all your tools so they are easy to find.  And so this service discovery tool for 
Mesos clusters is called "pegboard".  It provides a service to bridge between Marathon and HAProxy using Zookeeper or 
etcd as a key-value store of service configuration information and provides dynamically updated HAProxy configs.

### Prerequisites

* HAProxy installed
* Zookeeper or etcd configured and working.

### Installation

Check out the code in the location of your choice, change to that directory and customize the templates to suit your needs.

Once you're satisfied with the HAProxy configuration that will be used, install Pegboard: 

    sudo python pegboard.py install --config-frontend haproxy_frontend.cfg --config-backend haproxy_backend.cfg \
         --config-tcp haproxy_tcp.cfg --config-general haproxy_general.cfg 
         --subnet-dns [subnet dns] --zookeeper <zk_host1>:2181,<zk_host2>:2181 --marathon master.mesos:8080

This process can be repeated as needed (the pegboard.py script is re-installed and the haproxy config template are overwritten
in the key-value store).  Don't forget to include the comma-separated zookeeper host list if using Zookeeper.  `subnet-dns` 
is a wildcard domain to be used for services (like Marathon jobs). This will create a cron job which runs every minute 
in `/etc/cron.d/pegboard`. A log of the cron runs will be saved in `/var/log/pegboard.log`.

### Running the service

* To start the service:

	`sudo python /usr/local/bin/pegboard.py [--zookeeper {{ zookeeper_host_list }}] start`

* To stop the service:

    `sudo python /usr/local/bin/pegboard.py [--zookeeper {{ zookeeper_host_list }}] stop`

### Configure wildcard services

Create a wildcard DNS entry like `*.mycluster.mydomain.com` in your DNS pointing to the HAProxy host, and then create entries for Gandalf to identify your services

You can either:

* Submit the service data to Gandalf by sending a JSON block in a POST command:


    curl -X POST http://localhost:2288/apps -H "Content-Type: application/json" 
        \-d '{ "url": "marathon.mycluster.mydomain.com", "service_port": "3000", "app_name": "marathon", "servers": [ "leader.mesos:8080" ] }


### How to use the service

* From inside a cluster (private IP access), go to the master IP, port `2288`, select internal or external, and the name of the APP to look up.

    `curl {{ pegboard_host }}:2288/internals/marathon # Gets the internal address of marathon from local`
    `curl {{ pegboard_host }}:2288/externals/marathon # Gets the external address of marathon from local`

* From outside a proxied cluster (i.e. from the user's browser), change the url to use the `service-discovery` DNS endpoint.

	`curl http://service-discovery.mycluster.mydomain.com/internals/marathon # Gets the internal address of marathon from outside`
	`curl http://service-discovery.mycluster.mydomain.com/externals/marathon # Gets the external address of marathon from outside`

### Configuration management
An [Ansible role which installs HAProxy and uses Pegboard with zookeeper](https://github.com/appsoma/ansible-appsoma-mesos/tree/master/roles/ansible-haProxy) is available.

### Use docker to run

```
sudo docker build -t agustincb/pegboard --no-cache --build-arg zookeeper=zookeeper.host:2181 --build-arg subnet_dns=$SUBNET_DNS .
sudo docker run -dt -v /etc/haproxy/:/etc/haproxy/ -p  2288:2288 agustincb/pegboard
```
