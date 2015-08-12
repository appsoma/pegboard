# Gandalf

A bridge between Marathon and HAProxy using Zookeeper or etcd to store service configuration information.  

### Prerequisites

* Install HAProxy and an `/etc/haproxy/haproxy.cfg` file exists.
* Zookeeper or etcd configured and working.
* Before running, create paths (in Zookeeper or etcd):
    * `/internals`
    * `/externals`
    * `/gandalf`
    * `/gandalf/services`

### Installation

Check out the code in the location of your choice, cd to that directory then run: 

`sudo python gandalf.py [--zookeeper <zk_host0_ip>:<zk_port>,<zk_host1_ip>:<zk_port>] install`

Don't forget to include the comma-separated zookeeper host list if using Zookeeper.   

This will create a cron job which runs every minute in `/etc/cron.d/gandalf`.  A log of the cron runs will be saved in `/var/log/gandalf.log`.

### Configure wildcard services

* Create a wildcard DNS entry like `*.mycluster.mydomain.com` in your DNS pointing to the HAProxy host.
* Create an entry with a meaningful name in `/gandalf/services/{{service_name}}` with a JSON block like this:


    ```
    {
      "url": "{{service_name}}.mycluster.mydomain.com", 
      "service_port": "3000",
      "app_name": "{{service_name}}",
      "servers": [ "{{internal_host_ip}}:{{internal_port}}" ]
    }
    ```

### Configuration manangement
An [Ansible role which installs HAProxy and uses Gandalf with zookeeper](https://github.com/appsoma/ansible-appsoma-mesos/tree/master/roles/ansible-haProxy) is available.
