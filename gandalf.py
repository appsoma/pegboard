#!/usr/bin/python
import sys
import stat
import os
import re
import cgi
import shutil
import subprocess
import urlparse
import urllib
import urllib2
import json
import socket
import random
import argparse
import signal
import time
import atexit
from abc import ABCMeta,abstractmethod
from kazoo.client import KazooClient
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

script = sys.argv[0].split("/")[-1]
name = ".".join(script.split(".")[:-1])

"""
Linux Daemon, based on https://github.com/serverdensity/python-daemon/blob/master/daemon.py
"""

class Daemon(object):
	"""
	A generic daemon class.
	Usage: subclass the Daemon class and override the run() method
	"""
	def __init__(self, pidfile, stdin=os.devnull,
				 stdout=os.devnull, stderr=os.devnull,
				 home_dir='.', umask=022, verbose=1):
		self.stdin = stdin
		self.stdout = stdout
		self.stderr = stderr
		self.pidfile = pidfile
		self.home_dir = home_dir
		self.verbose = verbose
		self.umask = umask
		self.daemon_alive = True

	def daemonize(self, *args, **kwargs):
		"""
		Do the UNIX double-fork magic, see Stevens' "Advanced
		Programming in the UNIX Environment" for details (ISBN 0201563177)
		http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
		"""
		try:
			pid = os.fork()
			if pid > 0:
				# Exit first parent
				return
		except OSError, e:
			sys.stderr.write(
				"fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
			sys.exit(1)

		# Decouple from parent environment
		os.chdir(self.home_dir)
		os.setsid()
		os.umask(self.umask)

		# Do second fork
		try:
			pid = os.fork()
			if pid > 0:
				# Exit from second parent
				sys.exit(0)
		except OSError, e:
			sys.stderr.write(
				"fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
			sys.exit(1)

		if sys.platform != 'darwin':  # This block breaks on OS X
			# Redirect standard file descriptors
			sys.stdout.flush()
			sys.stderr.flush()
			si = file(self.stdin, 'r')
			so = file(self.stdout, 'a+')
			if self.stderr:
				se = file(self.stderr, 'a+', 0)
			else:
				se = so
			os.dup2(si.fileno(), sys.stdin.fileno())
			os.dup2(so.fileno(), sys.stdout.fileno())
			os.dup2(se.fileno(), sys.stderr.fileno())

		def sigtermhandler(signum, frame):
			self.daemon_alive = False
			sys.exit()

		signal.signal(signal.SIGTERM, sigtermhandler)
		signal.signal(signal.SIGINT, sigtermhandler)

		if self.verbose >= 1:
			print "Started"

		# Write pidfile
		atexit.register(
			self.delpid)  # Make sure pid file is removed if we quit
		pid = str(os.getpid())
		file(self.pidfile, 'w+').write("%s\n" % pid)
		self.run(*args, **kwargs)

	def delpid(self):
		os.remove(self.pidfile)

	def start(self, *args, **kwargs):
		"""
		Start the daemon
		"""

		if self.verbose >= 1:
			print "Starting..."

		# Check for a pidfile to see if the daemon already runs
		try:
			pf = file(self.pidfile, 'r')
			pid = int(pf.read().strip())
			pf.close()
		except IOError:
			pid = None
		except SystemExit:
			pid = None

		if pid:
			message = "pidfile %s already exists. Is it already running?\n"
			sys.stderr.write(message % self.pidfile)
			sys.exit(1)

		# Start the daemon
		self.daemonize(*args, **kwargs)

	def stop(self):
		"""
		Stop the daemon
		"""

		if self.verbose >= 1:
			print "Stopping..."

		# Get the pid from the pidfile
		pid = self.get_pid()

		if not pid:
			message = "pidfile %s does not exist. Not running?\n"
			sys.stderr.write(message % self.pidfile)

			# Just to be sure. A ValueError might occur if the PID file is
			# empty but does actually exist
			if os.path.exists(self.pidfile):
				os.remove(self.pidfile)

			return  # Not an error in a restart

		# Try killing the daemon process
		try:
			i = 0
			while 1:
				os.kill(pid, signal.SIGTERM)
				time.sleep(0.1)
				i = i + 1
				if i % 10 == 0:
					os.kill(pid, signal.SIGHUP)
		except OSError, err:
			err = str(err)
			if err.find("No such process") > 0:
				if os.path.exists(self.pidfile):
					os.remove(self.pidfile)
			else:
				print str(err)
				sys.exit(1)

		if self.verbose >= 1:
			print "Stopped"

	def restart(self):
		"""
		Restart the daemon
		"""
		self.stop()
		self.start()

	def get_pid(self):
		try:
			pf = file(self.pidfile, 'r')
			pid = int(pf.read().strip())
			pf.close()
		except IOError:
			pid = None
		except SystemExit:
			pid = None
		return pid

	def is_running(self):
		pid = self.get_pid()

		if pid is None:
			print 'Process is stopped'
		elif os.path.exists('/proc/%d' % pid):
			print 'Process (pid %d) is running...' % pid
		else:
			print 'Process (pid %d) is killed' % pid

		return pid and os.path.exists('/proc/%d' % pid)

	def run(self):
		"""
		You should override this method when you subclass Daemon.
		It will be called after the process has been
		daemonized by start() or restart().
		"""
		raise NotImplementedError

"""
Port Management
"""

class PortManagement:
	def __init__(self):
		self.ports = []
		self.available_ports = [ i for i in range(1024, 49151) if i not in self.ports and self.available(i) ]
	def check_port(self,port):
		return port in self.ports
	def new_port(self):
		if len(self.available_ports) == 0: return False

		choosen = random.choice(self.available_ports)
		self.ports.append(choosen)
		return choosen
	def choose_port(self,port):
		self.ports.append(port)
		self.available_ports.remove(port)
	def available(self,i):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			result = sock.bind(('127.0.0.1',i))
		except:
			return False
		sock.close()
		return True

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
	def close(self): pass

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
		self.zk.start()
	def get(self,key):
		result = self.zk.get(key)[0]
		if result == "":
			result = []
			children = self.zk.get_children(key)
			for i in children:
				result.append({'name': i, 'value': self.zk.get(os.path.join(key, i))[0]} )
			return result
		else:
			return self.zk.get(key)[0]
	def set(self,key,data):
		try:
			self.zk.set(key, data.encode('utf-8'))
		except Exception as e:
			self.zk.create(key, data.encode('utf-8'))

	def close(self):
		self.zk.stop()
		self.zk.close()

	@property
	def hosts(self):
		return self._hosts

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

	@property
	def kv(self):
		return self._kv

	def addStandaloneApp(self,app_name,url,service_port,servers):
		if not url:
			url = app_name+self._kv.get(KeyManager.subnet_dns)
		app_path = KeyManager.extra_services_directory + "/" + app_name
		self._kv.set(app_path, json.dumps({
			"app_name": app_name,
			"url": url,
			"service_port": service_port,
			"servers": servers
		}))

	def getApp(self,app_name):
		app = self._kv.get(os.path.join(KeyManager.extra_services_directory,app_name))
		
		if not app:
			masters = self._kv.get(KeyManager.cronjob_conf_file).split("\n")
			for master in masters:
				req = urllib2.Request("http://"+master+"/v2/apps/"+app_name+"?embed=apps.tasks")
				response = json.loads(urllib2.urlopen(req).read())["app"]
				if "app" in response:
					return response["app"]
		if app:
			app = json.loads(app)

		return app

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
			if "app_name" in s:
				apps[s["app_name"]] = s
			else:
				print "ERROR. Entry", i, "in", KeyManager.extra_services_directory, "lacks app_name", i["value"]

		http_apps = apps
		tcp_apps = {}
		content = self.getConfigHeader().split("\n")
		for master in masters:
			req = urllib2.Request("http://"+master+"/v2/apps?embed=apps.tasks")
			response = urllib2.urlopen(req)
			marathon_apps = json.loads(response.read())["apps"]
			for app in marathon_apps:
				app_name = app["id"] if app["id"][0] != "/" else app["id"][1:]

				http_ports = []
				if "HAPROXY_HTTP" in app["env"]:
					http_ports = map(int,app["env"]["HAPROXY_HTTP"].split(","))
		
				for i in range(len(app["ports"])):
					service_port = app["ports"][i]
					service_name = app_name+"-"+str(service_port)
					servers = [ t["host"]+":"+str(t["ports"][i]) for t in app["tasks"] ]
	
					if i in http_ports and service_name not in http_apps: 
						http_apps[service_name] = {
							"strip_path": False,
							"url": app_name+self._kv.get(KeyManager.subnet_dns),
							"app_name": service_name
						}

					if service_name in http_apps:
						http_apps[service_name] = { "url": apps[service_name]["url"], "app_name": service_name, "service_port": str(service_port), "servers": servers, "strip_path": apps[service_name]["strip_path"] if "strip_path" in apps[service_name] else True, "internal_port": apps[service_name]["internal_port"] if "internal_port" in apps[service_name] else False }
					else:
						if self.portManager.check_port(service_port):
							service_port = self.portManager.new_port()
							if not service_port:
								raise EnvironmentError("No open port available")
							self.portManager.choose_port(service_port)
						tcp_apps[app_name] = { "app_name": app_name+"-"+str(service_port), "service_port": str(service_port), "servers": servers }
		
		content += self._tcpApps(tcp_apps) + self._httpApps(http_apps)
		return "\n".join(content)

	def getConfigHeader(self):
		return self._kv.get(KeyManager.config_template)
	
	def _tcpApps(self,apps):
		content = []
		
		for app_name,app in apps.items():
			server_config = self._kv.get(KeyManager.config_port_template).replace("$app_name",app["app_name"]).replace("$service_port",app["service_port"]).split("\n")
			for i in range(len(app["servers"])):
				server = app["servers"][i]
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
		internals = []
		backends = []

		for app_name,app in apps.items():
			if "servers" not in app: continue
			frontend = ""
			if(app["url"][0] == "/"): frontend = "   acl "+app_name+" path_end -i "+app["url"]
			else: frontend = "   acl "+app_name+" hdr(host) -i "+app["url"]

			acls.append(frontend)
			use_backends.append("use_backend srvs_"+app_name+"	if "+app_name)

			servers = []
			for s in range(len(app["servers"])):
				server = app["servers"][s]
				if server.strip() == "": continue
				servers.append("   server "+app_name+"-host"+str(s)+" "+server)

			tmp_backend = backend_template.replace("$app_name",app_name).replace("$servers","\n".join(servers))
			if app["url"][0] == "/" and app["strip_path"]:
				tmp_backend = tmp_backend.replace("$replace_req", "reqrep ^([^\ ]*\ /)"+app["url"][1:]+'[/]?(.*)	 \\1\\2')
			else:
				tmp_backend = tmp_backend.replace("$replace_req", "")
			backends += tmp_backend.split("\n")

			if "internal_port" not in app or not app["internal_port"]:
				service_port = self.portManager.new_port()
				if not service_port:
					raise EnvironmentError("No open port available")
				self.portManager.choose_port(service_port)
				app["internal_port"] = service_port
				app_path = KeyManager.extra_services_directory + "/" + app_name
				self._kv.set(app_path, json.dumps(app))
			else:
				service_port = app["internal_port"]
			
			internals += [
				"frontend internal-"+app_name,
				"bind 0.0.0.0:"+str(service_port),
				"mode http",
				"default_backend srvs_"+app_name
			]

			self._saveEndpoints(app_name,socket.gethostbyname(socket.gethostname())+":"+str(service_port),app["url"])
	
		apps = frontends.replace("$acls","\n".join(acls)).replace("$use_backends","\n".join(use_backends)).replace("$internals","\n".join(internals)).split("\n") + backends
		return apps

	def getExternal(self,app_name):
		return self._kv.get(os.path.join(KeyManager.externals_directory,app_name))

	def getInternal(self,app_name):
		return self._kv.get(os.path.join(KeyManager.backends_directory,app_name))

	def _saveEndpoints(self,app_name,backend,external):
		self._kv.set(os.path.join(KeyManager.backends_directory,app_name),backend)
		self._kv.set(os.path.join(KeyManager.externals_directory,app_name),external)

"""
HTTP server deamon
"""

class HttpRouter:
	# ACB: Ugly as hell, but can't think a better way
	@property
	def bridge(self):
		return self._bridge

	@bridge.setter
	def bridge(self,bridge):
		self._bridge = bridge

	# GET /internals/:app
	def get_internal(self,path,headers,rfile):
		app_name = path.path.split("/")[2]
		try:
			res = {"value": self.bridge.getInternal(app_name)}
		except:
			res = { "error": app_name+" doesn't exist" }
		return res
	
	# GET /exteransl/:app
	def get_external(self,path,headers,rfile):
		app_name = path.path.split("/")[2]
		try:
			res = {"value": self.bridge.getExternal(app_name)}
		except:
			res = { "error": app_name+" doesn't exist" }
		return res
	
	# GET /apps/:app
	def get_app(self,path,headers,rfile):
		app_name = path.path.split("/")[2]
		try:
			app = self.bridge.getApp(app_name)
		except:
			app = { "error": app_name+" doesn't exist" }
		return app

	# POST /apps/:app
	def post_app(self,path,headers,rfile):
		if "Content-Length" not in headers:
			return { "Error": "Empty request" }
		length = int(headers["Content-Length"])
		data = rfile.read(length)
		form = {}
		for k,v in urlparse.parse_qsl( data ):
			form[k] = v

		if "app_name" not in form or "url" not in form or "service_port" not in form or	"servers" not in form:
			return { "Error": "You should post app_name, url, service_port and servers values" }

		self.bridge.addStandaloneApp(form["app_name"],form["url"],form["service_port"],form["servers"].split(","))
		return { "success": True }
	

class HttpHandler(BaseHTTPRequestHandler):
	routes = {
		'GET /internals/[^\/]+$': 'get_internal',
		'GET /externals/[^\/]+$': 'get_external',

		# apps api
		'GET /apps/[^\/]+$': 'get_app',
		'POST /apps$': 'post_app'
	}
	router = HttpRouter()

	def doCommand(self, requestType):
		def search(dictionary, path):
			result = []
			for key in dictionary:
				if re.search(key,path):
					return key
			return False
		try:
			path = urllib.unquote(self.path)
			parsed_path = urlparse.urlparse(self.path)
			route_name = search(HttpHandler.routes,requestType + " " + path)
			if route_name:
				reply = getattr(HttpHandler.router,HttpHandler.routes[route_name])(parsed_path,self.headers,self.rfile)
				self.send_response(200)
				replyStr = json.dumps(reply)
				self.send_header("Content-type", "application/json")
				self.send_header("Content-length", str(len(replyStr)))
				self.send_header("Access-Control-Allow-Origin", "*")
				self.end_headers()
				self.wfile.write(replyStr)
			else:
				self.send_error(404, "Command not found")
		except Exception as e:
			self.send_error(403, "Failed to process command") 

	def do_HEAD(self):
		self.doCommand("HEAD")

	def do_GET(self):
		self.doCommand("GET")

	def do_DELETE(self):
		self.doCommand("DELETE")

	def do_POST(self):
		self.doCommand("POST")

	def do_PUT(self):
		self.doCommand("PUT")

	def do_OPTIONS(self):
		self.send_response(200)
		self.send_header('Allow', 'GET, DELETE, POST, PUT, HEAD, OPTIONS')
		self.send_header('Access-Control-Allow-Methods', 'GET, DELETE, POST, PUT, HEAD, OPTIONS')
		self.send_header('Access-Control-Allow-Origin', '*')
		self.send_header('Access-Control-Allow-Headers', 'X-Request, X-Requested-With')
		self.send_header('Content-Length', '0')
		self.end_headers()

	def log_message(self,format,*args):
		# trace here to see all the http
		return

class HTTPServerDaemon(Daemon):
	def run(self,zookeeper,port):
		# ACB: For some reason, I can't the bridge created on the other thread
		if zookeeper:
			kv = Zookeeper(zookeeper)
		else:
			kv = Etcd()

		self._kv = kv

		# TODO: Find a nicer way to do that, Agustin, PLEASE
		def sigtermhandler(signum, frame):
			self.daemon_alive = False
			self._kv.close()
			sys.exit()

		signal.signal(signal.SIGTERM, sigtermhandler)
		signal.signal(signal.SIGINT, sigtermhandler)

		HttpHandler.router.bridge = Bridge(kv)
		self._server = HTTPServer(('localhost', port), HttpHandler)
		self._server.serve_forever()

"""
Bridge Daemon
"""

class BridgeDaemon(Daemon):
	def run(self,args):
		if args.zookeeper:
			kv = Zookeeper(args.zookeeper)
		else:
			kv = Etcd()
		self._kv = kv

		def sigtermhandler(signum, frame):
			self.daemon_alive = False
			self._kv.close()
			sys.exit()

		signal.signal(signal.SIGTERM, sigtermhandler)
		signal.signal(signal.SIGINT, sigtermhandler)

		commandManager = CommandManager(Bridge(kv),args)
		while True:
			commandManager.update()
			time.sleep(5)

"""
Command manager
"""

class CommandManager:
	def __init__(self,bridge,args):
		self._bridge = bridge
		self._args = args

	@property
	def args(self):
		return self._args

	def doCommand(self,command,*args):
		method = getattr(self,command)
		if not method:
			raise ValueError("Command "+command+" doesn't exists")

		return method(*args)

	def start(self):
		daemon = BridgeDaemon(self._args.pid_file,
			stdout = self._args.log_file,
			stderr = self._args.log_file
		)
		daemon.start(self._args)

		if self._args.with_webservice:
			self._bridge.addStandaloneApp("service-discovery",False,"80",["127.0.0.1:"+str(args.port)])
			http_server = HTTPServerDaemon(self._args.http_pid_file)
			http_server.start(self._args.zookeeper,self._args.port)

	def stop(self):
		daemon = BridgeDaemon(self._args.pid_file)
		daemon.stop()

		if self._args.with_webservice:
			http_server = HTTPServerDaemon(self._args.http_pid_file)
			http_server.stop()

	def restart(self):
		daemon = BridgeDaemon(self._args.pid_file)
		daemon.restart()

		if self._args.with_webservice:
			http_server = HTTPServerDaemon(self._args.http_pid_file)
			http_server.restart()

	def install(self):
		script_path = self._args.installation_folder + script
		try:
			os.makedirs(self._args.installation_folder)
		except OSError as e: 
			if(e.errno!=17): raise e
		shutil.copyfile(script,script_path)
		os.chmod(script_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

		Cron.createCronJob("gandalf",self._cronContent(script_path))

	def update(self):
		new_content = self._bridge.generateConfigContent()
		old_content = Haproxy.readConfig()

		if new_content == old_content: return

		Haproxy.writeConfig(new_content)
		Haproxy.restart()

	def internal(self):
		if not self._args.app_name:
			raise ValueError("You need to specify app name: --app-name name")
		print self._bridge.getInternal(self._args.app_name)

	def external(self):
		if not self._args.app_name:
			raise ValueError("You need to specify app name: --app-name name")
		print self._bridge.getExternal(self._args.app_name)

	def _cronContent(self,script_path):
		zookeeper = ""
		if type(self._bridge.kv) == Zookeeper:
			zookeeper = " --zookeeper "+self._bridge.kv.hosts
		return "* * * * * root python "+script_path+zookeeper+" update >>/var/log/gandalf-cron.log 2>&1\n"

if __name__ == "__main__":
	script_dir = "/usr/local/bin/"

	parser = argparse.ArgumentParser(description='Bridge between marathon and haproxy')
	parser.add_argument("--zookeeper", help="Use zookeeper instead of etcd, should pass a list of hosts")
	parser.add_argument("--pid-file", help="Pid file of the updater daemon")
	parser.add_argument("--http-pid-file", help="Pid file of the http daemon")
	parser.add_argument("--installation-folder", help="Choose another installation folder, default "+script_dir)
	parser.add_argument("--app-name", help="App name in which perform the action")
	parser.add_argument("--log-file", help="Log file location")
	parser.add_argument("--port", help="Port of the web service",type=int)
	parser.add_argument("--with-webservice", help="Use http service", action='store_true')
	parser.add_argument('action', choices=['update','install','start','stop','restart','internal','external'])
	args = parser.parse_args()

	if not args.installation_folder:
		args.installation_folder = script_dir

	if args.zookeeper:
		kv = Zookeeper(args.zookeeper)
	else:
		kv = Etcd()

	if not args.log_file:
		args.log_file = "/var/log/gandalf.log"

	if not args.pid_file:
		args.pid_file = "/var/run/gandalf.pid"

	if not args.http_pid_file:
		args.http_pid_file = "/var/run/gandalf_server.pid"

	if not args.port:
		args.port = 2288

	commandManager = CommandManager(Bridge(kv),args)

	commandManager.doCommand(args.action)

	kv.close()
