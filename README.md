# Gandalf

A service to bridge between Marathon and HAProxy using Zookeeper or etcd to store service configuration information and dynamically update HAProxy.

### Prerequisites

* Install HAProxy and an `/etc/haproxy/haproxy.cfg` file exists.
* Zookeeper or etcd configured and working.
* Before running, create paths (in Zookeeper or etcd):
    * `/internals`
    * `/externals`
    * `/gandalf`
    * `/gandalf/services`

### Installation

Check out the code in the location of your choice, change to that directory then run: 

`sudo python gandalf.py [--zookeeper <zk_host0_ip>:<zk_port>,<zk_host1_ip>:<zk_port>] install`

Don't forget to include the comma-separated zookeeper host list if using Zookeeper.   

This will create a cron job which runs every minute in `/etc/cron.d/gandalf`.  A log of the cron runs will be saved in `/var/log/gandalf.log`.

### Running the service

* To start the service:

	`sudo python /usr/local/bin/gandalf.py [--zookeeper {{ zookeeper_host_list }}] start [--with-webservice] [--log-file {{ gandalf_log_dir }}/gandalf.log]`

* To stop the service:

    `sudo python /usr/local/bin/gandalf.py [--zookeeper {{ zookeeper_host_list }}] stop [--with-webservice]`

### Configure wildcard services

Create a wildcard DNS entry like `*.mycluster.mydomain.com` in your DNS pointing to the HAProxy host, and then create entries for Gandalf to identify your services

You can either:

* Submit the service data to Gandalf with a POST command:

	`curl -X POST 127.0.0.1:2288/apps -d url=marathon.mycluster.mydomain.com -d app_name=marathon -d service_port=80 -d servers=master:8080`

* OR Create an entry by hand in Zookeeper at, for instance, `/gandalf/services/<app_name>` with a JSON block like this:

    ```
    {
      "url": "marathon.mycluster.mydomain.com", 
      "service_port": "3000",
      "app_name": "marathon",
      "servers": [ "master:8080" ]
    }
    ```

### How to use the service

* From inside a cluster (private IP access), go to the master IP, port `2288`, select internal or external, and the name of the APP to look up.

    `curl {{ gandalf_master }}:2288/internals/marathon # Gets the internal address of marathon from local`
    `curl {{ gandalf_master }}:2288/externals/marathon # Gets the external address of marathon from local`

* From outside a proxied cluster (i.e. from the user's browser), change the url to use the `service-discovery` DNS endpoint.

	`curl http://service-discovery.mycluster.mydomain.com/internals/marathon # Gets the internal address of marathon from outside`
	`curl http://service-discovery.mycluster.mydomain.com/externals/marathon # Gets the external address of marathon from outside`

### Configuration manangement
An [Ansible role which installs HAProxy and uses Gandalf with zookeeper](https://github.com/appsoma/ansible-appsoma-mesos/tree/master/roles/ansible-haProxy) is available.
