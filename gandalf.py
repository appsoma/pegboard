#!/usr/bin/python
import sys
import stat
import os
import shutil
import subprocess
import urllib
import urllib2
import json
import socket
import random
import argparse
from abc import ABCMeta,abstractmethod
from kazoo.client import KazooClient

script = sys.argv[0].split("/")[-1]
name = ".".join(script.split(".")[:-1])

"""
Port Management
"""

class PortManagement:
	def __init__(self):
		self.ports = []
	def check_port(self,port):
		return port in self.ports
	def new_port(self):
		available_ports = [ i for i in range(1024, 49151) if i not in self.ports and PortManagement.available(i) ]

		if len(available_ports) == 0: return False

		choosen = random.choice(available_ports)
		self.ports.append(choosen)
		return choosen
	def available(i):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		result = sock.connect_ex(('127.0.0.1',i))
		return result == 0

"""
Key/value management
"""

class KeyManager:
	__metaclass__ = ABCMeta
	config_template = name+"/haproxy.cfg"
	config_port_template = name+"/haproxy_port.cfg"
	config_frontends_template = name+"/haproxy_frontends.cfg"
	config_backend_template = name+"/haproxy_backend.cfg"
	extra_services_directory = name+"/services"
	subnet_dns = name+"/subnet_dns"
	path_prefix = name+"/path_prefix"
	cronjob_conf_file = name+"/marathons"
	backends_directory = "internals"
	externals_directory = "externals"

	@abstractmethod
	def get(self,key): pass
	@abstractmethod
	def set(self,key,data): pass

class Etcd(KeyManager):
	def __init__(self):
		self.api_url = "http://127.0.0.1:2379/v2"
	def get(self,key):
		value = self._request(os.path.join("/keys",key))["node"]
		return value["value"] if "value" in value else value["nodes"]
	def set(self,key,data):
		return self._request(os.path.join("/keys",key),urllib.urlencode({ "value": data }))
	def _request(self,url,data=None):
		req = urllib2.Request(self.api_url+url, data)
		if data:
			req.get_method = lambda: "PUT"
		response = urllib2.urlopen(req)
		return json.load(response)

class Zookeeper(KeyManager):
	def __init__(self,hosts): 
		self._hosts = hosts
		self.zk = KazooClient(hosts=hosts)
	def get(self,key):
		return self.zk.get(key)[0] 
	def set(self,key,data):
		self.zk.set(key, data)

"""
HAPROXY management
"""

class Haproxy:
	config_file = "/etc/haproxy/haproxy.cfg"
	pid_file = "/var/run/haproxy-private.pid"
	@classmethod
	def restart(cls):
		pids = False
		try:
			with open(cls.pid_file,"r") as f:
				pids = f.read().replace("\n"," ")
		except IOError as e:
			# ACB: File may not exist
			if(e.errno != 2): raise e

		pids_string = (" -sf "+pids) if pids else ""

		return subprocess.Popen("/bin/bash -c '/usr/sbin/haproxy -f "+cls.config_file+" -p "+cls.pid_file+pids_string+"'", shell=True, stdout=subprocess.PIPE)
	@classmethod
	def writeConfig(cls,content):
		try:
			with open(cls.config_file,"w") as f:
				f.write(content)
		except:
			raise EnvironmentError("Can't write config file, please check haproxy installation.")
	@classmethod
	def readConfig(cls):
		content = ""
		try:
			with open(cls.config_file,"r") as f:
				content = f.read()
		except:
			raise EnvironmentError("Can't write config file, please check haproxy installation.")
		return content

"""
CRON management
"""

class Cron:
	cronjob_dir = "/etc/cron.d/"

	@classmethod
	def createCronJob(cls,cron_file,content):
		try:
			os.mkdir(Cron.cronjob_dir)
		except OSError as e: 
			if(e.errno!=17): raise e

		with open(Cron.cronjob_dir+cron_file,"w") as f:
			f.write(content)

"""
Bridge management
"""

class Bridge:
	def __init__(self,keymanager):
		self._kv = keymanager
		self.portManager = PortManagement()

	def generateConfigContent(self):
		masters = self._kv.get(KeyManager.cronjob_conf_file).split("\n")

		apps = {}
		apps_data = self._kv.get(KeyManager.extra_services_directory)
		try:
			prefix = self._kv.get(path_prefix)
		except:
			prefix = ""
		for i in apps_data:
			s = json.loads(i["value"])
			apps[s["app_name"]] = s

		http_apps = apps
		tcp_apps = {}
		content = self.getConfigHeader().split("\n")
		for master in masters:
			req = urllib2.Request("http://"+master+"/v2/apps?embed=apps.tasks")
			response = urllib2.urlopen(req)
			marathon_apps = json.loads(response.read())["apps"]
			for app in marathon_apps:
				app_name = app["id"] if app_name[0] != "/" else app["id"][1:]

				http_ports = []
				if "HAPROXY_HTTP" in app["env"]:
					http_ports = map(int,app["env"]["HAPROXY_HTTP"].split(","))
		
				for i in range(len(app["ports"])):
					service_port = app["ports"][i]
					servers = [ t["host"]+":"+str(t["ports"][i]) for t in app["tasks"] ]
	
					if i in http_ports and app_name not in http_apps: 
						http_apps[app_name] = {
							"strip_path": False,
							"url": app_name+self._kv.get(subnet_dns)["node"]["value"],
							"app_name": app_name
						}

					if app_name in http_apps:
						http_apps[app_name] = { "url": apps[app_name]["url"], "app_name": app_name+"-"+str(service_port), "service_port": str(service_port), "servers": servers, "strip_path": apps[app_name]["strip_path"] if "strip_path" in apps[app_name] else True }
					else:
						if self.portManager.check_port(service_port):
							service_port = self.portManager.new_port()
							if not service_port:
								raise EnvironmentError("No open port available")
							self.portManager.ports.append(service_port)
						tcp_apps[app_name] = { "app_name": app_name+"-"+str(service_port), "service_port": str(service_port), "servers": servers }
		
		content += self._tcpApps(tcp_apps) + self._httpApps(http_apps)
		return "\n".join(content)

	def getConfigHeader(self):
		return self._kv.get(KeyManager.config_template)
	
	def _tcpApps(self,apps):
		content = []
		
		for app_name,app in apps.items():
			server_config = self_kv.get(config_port_template).replace("$app_name",app["app_name"]).replace("$service_port",app["service_port"]).split("\n")
			for i in range(len(servers)):
				server = servers[i]
				if server.strip() == "": continue
				server_config.append("  server "+app_name+"-"+str(i)+" "+server+" check")
			
			backend = socket.gethostbyname(socket.gethostname())+":"+app["service_port"]
			external = urllib2.urlopen('http://whatismyip.org').read()+":"+app["service_port"]
			self._saveEndpoints(app_name,backend,external)
			content += server_config

		return content

	def _httpApps(self,apps):
		frontends = self._kv.get(KeyManager.config_frontends_template)
		backend_template = self._kv.get(KeyManager.config_backend_template)
		acls = []
		use_backends = []
		backends = []

		for app_name,app in apps.items():
			if "servers" not in app: continue
			frontend = ""
			if(app["url"][0] == "/"): frontend = "   acl "+app_name+" path_end -i "+app["url"]
			else: frontend = "   acl "+app_name+" hdr(host) -i "+app["url"]

			acls.append(frontend)
			use_backends.append("use_backend srvs_"+app_name+"    if "+app_name)
			servers = []
			for s in range(len(app["servers"])):
				server = app["servers"][s]
				if server.strip() == "": continue
				servers.append("   server "+app_name+"-host"+str(s)+" "+server)
			tmp_backend = backend_template.replace("$app_name",app_name).replace("$servers","\n".join(servers))
	                if (app["url"][0] == "/") and app["strip_path"]:
				tmp_backend = tmp_backend.replace("$replace_req", "reqrep ^([^\ ]*\ /)"+app["url"][1:]+'[/]?(.*)     \\1\\2')
                	else:
        	                tmp_backend = tmp_backend.replace("$replace_req", "")
	                backends += tmp_backend.split("\n")
			self._saveEndpoints(app_name,app["url"],app["url"])
	
		apps = frontends.replace("$acls","\n".join(acls)).replace("$use_backends","\n".join(use_backends)).split("\n") + backends
		return apps

	def _saveEndpoints(self,app_name,backend,external):
		self._kv.set(os.path.join(KeyManager.backends_directory,app_name),backend)
		self._kv.set(os.path.join(KeyManager.externals_directory,app_name),external)

"""
Command manager
"""

class CommandManager:
	@classmethod
	def doCommand(cls,command,*args):
		method = getattr(cls,command)
		if not method:
			raise ValueError("Command "+command+" doesn't exists")

		method(*args)

	@classmethod
	def install(cls,kv,script_dir,script):
		script_path = script_dir + script
		try:
			os.makedirs(script_dir)
		except OSError as e: 
			if(e.errno!=17): raise e
		shutil.copyfile(script,script_path)
		os.chmod(script_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

		Cron.createCronJob(script,cls._cronContent(script_path))

	@classmethod
	def update(cls,kv,script_dir,script):
		bridge = Bridge(kv)

		new_content = bridge.generateConfigContent()
		old_content = Haproxy.readConfig()

		if new_content == old_content: return

		Haproxy.writeConfig(new_content)
		Haproxy.restart()

	@classmethod
	def _cronContent(cls,script_path):
		return "* * * * * root python "+script_path+" update >>/tmp/haproxycron.log 2>&1\n"

if __name__ == "__main__":
	script_dir = "/usr/local/bin/"+name+"-dir/"

	parser = argparse.ArgumentParser(description='Bridge between marathon and haproxy')
	parser.add_argument("--zookeeper", help="Use zookeeper instead of etcd, should pass a list of hosts")
	parser.add_argument("--installation-folder", help="Choose another installation folder, default "+script_dir)
	parser.add_argument('action', choices=['update','install'])
	args = parser.parse_args()

	if args.installation_folder:
		script_dir = args.installation_folder

	if args.zookeeper:
		kv = Zookeeper(args.zookeeper)
	else:
		kv = Etcd()

	CommandManager.doCommand(args.action,kv,script_dir,script)
