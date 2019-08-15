__author__ = 'Jason Ray Norris'
import paramiko
import time
import sys
import datetime
import socket

class Collector(object):
    '''requirements? firewall name,firewall serial,access lists,
    access group data,object data, object group data,timestamp'''
    def __init__(self,host,user_pass_dict,enable_password_list):
        self.data = []
        self.host = host
        self.user_pass_dict = user_pass_dict
        self.enable_password_list = enable_password_list
        self.clear_vars()
        self.message = ''

    def start(self):
        '''Run functions'''
        self.status = 'RUNNING'
        if self.connect():
            '''get enable, evaluate context'''
            try:
                context, hostname = self.get_enable()
                if context:
                    self.status = 'FAILED'
                    self.message = 'Firewall is contexted. Try connecting directly to child'
                    return self
                else:
                    self.set_pager()
                    self.get_serial_model()
                    self.get_accessgroup()
                    self.get_objectgroup()
                    self.get_objects()
                    self.get_acls()
                    self.store_data()
                    self.log('Work completed')
                    self.status = 'COMPLETED'
                    self.disconnect()
                    return self
            except:
                self.log('Work did not completed')
                self.disconnect()
        else:
            Exception('Could not connect to host')

    def check_server_listen(self,address, port):
        s = socket.socket()
        self.log("Attempting to connect to %s on port %s" % (address, port))
        try:
            s.connect((address, port))
            self.log("Connected to %s on port %s" % (address, port))
            return True
        except Exception as ex:
            print(ex)
            self.log("Connection to %s on port %s failed" % (address, port))
            return False

    def clear_vars(self):
        self.interface_applied_acl = []
        self.context = False
        self.hostname = None
        self.serialnum = ''
        self.model = ''
        self.accessgroup_write_buffer = ''
        self.objectgroup_write_buffer = ''
        self.acl_log_write_buffer = ''

    def connect(self):
        for k,v in self.user_pass_dict.items():
            self.log('Connecting ssh with username ['+str(k)+']')
            connected = False
            try:
                self.remote_conn_pre = paramiko.SSHClient()
                self.remote_conn_pre.set_missing_host_key_policy(
                    paramiko.AutoAddPolicy())
                self.remote_conn_pre.connect(self.host, username=k, password=v,
                look_for_keys=False, allow_agent=False)
                connected = True
            except:
                self.log('Connecting ssh with username [' + str(k)+ '] failed')
                self.remote_conn_pre.close()
            if connected:
                if self.remote_conn_pre.get_transport().is_active():
                    self.remote_conn = self.remote_conn_pre.invoke_shell()
                    self.log('Connected and authenticated with username ['+ str(k)+']')
                    return True
        return False

    def disconnect(self):
        self.remote_conn_pre.close()
        self.log('Disconnected')

    def get_enable(self):
        self.send_command('en', timer=10)
        found_enable_pass = False
        context = False
        while not found_enable_pass:
            for each in self.enable_password_list:
                self.log('Trying enable password ['+str(self.enable_password_list.index(each))+']')
                self.send_command(each, timer=4)
                output = self.remote_conn.recv(10000).decode("utf-8")
                lines = output.splitlines()
                self.hostname = lines[-1].rstrip(' ')
                if '/' in self.hostname:
                    context = True
                    self.log ('Current context is [admin] context')
                    if self.hostname[-1] == '#':
                        self.log ('Enable password found [' + str(self.enable_password_list.index(each)) + ']')
                        return context, self.hostname.rstrip('#').split('/')[0]
                if self.hostname[-1] == '#':
                    self.log('Enable password found ['+str(self.enable_password_list.index(each))+']')
                    found_enable_pass = True
                    return context, self.hostname.rstrip('#').split('/')[0]
            if not found_enable_pass:
                self.log('Enable password not found')
                self.hostname = 'None'
                Exception('Enable password not found')
                #return False, context, self.hostname.rstrip('#')
        if context:
            self.hostname = self.hostname.split('/')[0]
        if self.hostname == None:
            self.hostname = 'None'
        return context, self.hostname.rstrip('#')

    def countdown(self,t):
        while t:
            mins, secs = divmod(t, 60)
            timeformat = '{:02d}:{:02d}'.format(mins, secs)
            sys.stdout.write('\rCountdown:'+str(timeformat))
            time.sleep(1)
            t -= 1
        sys.stdout.write('\r')

    def send_command(self,command,timer=2):
        self.remote_conn.send(command+"\n")
        self.countdown(t=timer)

    def send_privileged_command(self,command,iterations=10,timer=10,message='None'):
        output = ''
        for n in range(iterations):
            if n == 0:
                self.log('%s [%s] iteration/s' % (message,str(n+1)))
                self.send_command(command,timer=timer)
                output = self.remote_conn.recv(10000000).decode("utf-8")
            if n > 0:
                self.log ('%s [%s] iteration/s' % (message, str (n + 1)))
                self.countdown (t=timer)
                output += self.remote_conn.recv(10000000).decode("utf-8")
            lines = output.splitlines()
            checkhostname = lines[-1].rstrip(' ')
            try:
                if checkhostname[-1] == '#':
                    return output
                if n == iterations - 1:
                    Exception('Maximum iterations reached')
            except:
                pass

    def get_serial_model(self):
        output = self.send_privileged_command('show inventory',timer=3,iterations=3,message="Attempting to get serial number")
        chassis_found = False
        lines = output.splitlines()
        looking = True
        for line in lines:
            if not looking:
                break
            if not chassis_found:
                if 'Chassis' in line:
                    chassis_found = True
            elif chassis_found:
                words = line.split(',')
                for word in words:
                    if 'SN:' in word:
                        self.serialnum = word.strip('SN: ')
                        self.log('Serial Number successfully retrieved')
                        self.model = words[0].strip('PID: ')
                        looking = False
                        break

    def changeto_system_context(self):
        output = self.send_privileged_command ('changeto system', timer=3, iterations=3,
                                      message="Attempting to change context to system")
        lines = output.splitlines()
        self.hostname = lines[-1].rstrip(' ')
        try:
            if self.hostname[-1] == '#':
                self.send_command('show context count', timer=5)
                output = self.remote_conn.recv(10000).decode("utf-8")
                if 'Total active Security Contexts:' in output:
                    self.log ('Change to [system] context successful')
                    self.context = True
                    return True
        except:
            return False

    def changeto_context(self,context):
        output = self.send_privileged_command ('changeto context '+str(context), timer=3, iterations=3,
                                      message="Attempting to change context to "+str(context))
        lines = output.splitlines()
        self.hostname = lines[-1].rstrip(' ')

        try:
            if '/'+str(context)+'#' in self.hostname:
                self.log ('Changed to context ['+str(context)+']')
                self.context = True
                return True
        except:
            return False

    def get_context_list(self):
        self.log('Attempting to get contexts')
        output = self.send_privileged_command ('show context', timer=3, iterations=3,
                                      message="Attempting to get contexts")
        lines = output.splitlines()
        listofcontexts = []
        try:
            if self.hostname[-1] == '#':
                for line in lines:
                    if '*admin' not in line:
                        if 'Total active Security Contexts:' not in line:
                            words = line.split()
                            if len(words) == 5:
                                listofcontexts.append(words[0])
                if len(listofcontexts) > 0:
                    self.log ('Returned list of contexts successful')
                    return True, listofcontexts
                else:
                    self.log ('Failed to returned list of contexts')
                    return False, listofcontexts
        except:
            return False

    def get_acls(self):
        output = self.send_privileged_command(command='show access-list',timer=10,iterations=150,message='Attempting to fetch access lists')
        self.acl_log_write_buffer = output

    def get_objectgroup(self):
        self.objectgroup_write_buffer = ''
        self.log('Attempting to get object groups.')
        iterations = 112
        wait_timer = 5
        output = ''
        for n in range(iterations):
            if n == 0:
                self.log('Attempting to fetch object groups [%s] iteration/s' % str(n + 1))
                self.send_command('show run object-group', timer=wait_timer)
                output = self.remote_conn.recv(1000000).decode("utf-8")
            if n > 0:
                self.log('Attempting to fetch object groups [%s] iteration/s' % str(n + 1))
                self.send_command('\r', timer=wait_timer)
                output += self.remote_conn.recv(100000).decode("utf-8")
            lines = output.splitlines()
            checkhostname = lines[-1].rstrip(' ')

            try:
                if checkhostname[-1] == '#':
                    break
                if n == iterations - 1:
                    Exception('Maximum iterations reached')
            except:
                pass
        for line in lines:
            self.objectgroup_write_buffer += str(line) + '\n'
        self.log('Object groups successfully retrieved')

    def get_objects(self):
        self.object_write_buffer = ''
        self.log('Attempting to get objects')
        iterations = 150
        wait_timer = 5
        output = ''
        for n in range(iterations):
            if n == 0:
                self.log('Trying to fetch objects [%s] iteration/s' % str(n + 1))
                self.send_command('show run object', timer=wait_timer)
                output = self.remote_conn.recv(1000000).decode("utf-8")
            if n > 0:
                self.log('Trying to fetch objects [%s] iteration/s' % str(n + 1))
                self.send_command('\r', timer=wait_timer)
                output += self.remote_conn.recv(100000).decode("utf-8")
            lines = output.splitlines()
            checkhostname = lines[-1].rstrip(' ')

            try:
                if checkhostname[-1] == '#':
                    break
                if n == iterations - 1:
                    Exception('Maximum iterations reached')
            except:
                pass
        for line in lines:
            self.object_write_buffer += str(line) + '\n'

        self.log('Objects successfully retrieved')

    def get_accessgroup(self):
        self.accessgroup_write_buffer = ''
        self.log('Attempting to get access groups')
        iterations = 200
        wait_timer = 5
        output = ''
        for n in range(iterations):
            if n == 0:
                self.log('Trying to fetch access groups [%s] iteration/s' % str (n + 1))
                self.send_command('show run access-group', timer=wait_timer)
                output = self.remote_conn.recv(1000000).decode("utf-8")
            if n > 0:
                self.log('Trying to fetch access groups [%s] iteration/s' % str (n + 1))
                self.send_command('\r', timer=wait_timer)

                output += self.remote_conn.recv(100000).decode("utf-8")
            lines = output.splitlines()
            checkhostname = lines[-1].rstrip(' ')
            try:
                if checkhostname[-1] == '#':
                    break
                if n == iterations - 1:
                    Exception('Maximum iterations reached')
            except:
                pass
        for line in lines:
            self.accessgroup_write_buffer += str(line) + '\n'
        self.log('Access groups successfully retrieved')

    def check_pager(self):
        self.send_command('show pager', timer=5)
        output = self.remote_conn.recv(1000).decode("utf-8")
        if 'no pager' in output:
            self.log('Check pager passed')
            return True
        else:
            self.log('Check pager failed')
            return False

    def set_pager(self):
        self.send_command('terminal pager 0', timer=5)
        output = self.remote_conn.recv(1000).decode("utf-8")
        success = self.check_pager()
        if success:
            self.log('Set pager passed')
            return True
        else:
            self.log('Set pager failed')
            return False

    def store_data(self):
        timestamp = datetime.datetime.now().strftime("%d.%b %Y %H:%M:%S")
        self.data.append({
            "name":str(self.hostname).replace('#','').split('/')[0],
            "serialnum":str(self.serialnum),
            "context": str (self.context),
            "target":str(self.host),
            "model":str(self.model),
            "timestamp": timestamp,
            "access-lists": self.acl_log_write_buffer,
            "access-groups": self.accessgroup_write_buffer,
            "object-groups": self.objectgroup_write_buffer,
            "objects": self.object_write_buffer,
        })
        self.log('Data stored')

    def log(self,message):
        print(message)
        #logmessage = "%s %s" % (str('['+self.host+']'),str(message))
        #logger.write_collector_log_file(logmessage)




