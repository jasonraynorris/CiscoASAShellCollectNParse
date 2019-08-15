__author__ = 'Jason Ray Norris'
import ipaddress
import json
import re

class Parser(object):

    def __init__(self,data):

        self.data_timestamp = data['timestamp']
        self.return_acl_data = []
        self.data = {}

        '''set vars for input data'''
        self.fw_name = data['name']
        self.fw_model = data['model']
        self.fw_context = data['context']
        self.target = data['target']
        self.fw_serial = data['serialnum']
        acllines = data['access-lists']
        accessgrouplines = data['access-groups']
        objectgrouplines = data['object-groups']
        objectlines = data['objects']

        self.remarkdata = {}

        '''used to translate port names to real'''
        self.port_alias_to_real = {
                                    'nameserver':42,
                                    'isakmp':500,
                                    'syslog':514,
                                    'bootp':67,
                                    'bootpc': 68,
                                    'bootps':69,
                                    'aol':5120,
                                    'ntp':123,
                                    'bgp':179,
                                    'chargen':19,
                                    'cifs':3020,
                                    'citrix-ica':1494,
                                    'cmd':514,
                                    'ctiqbe':2748,
                                    'daytime':13,
                                    'discard':9,
                                    'domain':53,
                                    'echo':7,
                                    'exec':512,
                                    'finger':79,
                                    'ftp':21,
                                    'ftp-data':20,
                                    'gopher':70,
                                    'h323':1720,
                                    'hostname':101,
                                    'http':80,
                                    'https':443,
                                    'ident':113,
                                    'imap4':143,
                                    'irc':194,
                                    'kerberos':88,
                                    'klogin':543,
                                    'kshell':544,
                                    'snmp':161,
                                    'snmptrap':162,
                                    'ldap':389,
                                    'ldaps':636,
                                    'login':513,
                                    'lotusnotes':1352,
                                    'lpd':515,
                                    'netbios-ssn':139,
                                    'netbios-dgm': 138,
                                    'netbios-ns': 137,
                                    'nfs':2049,
                                    'nntp':119,
                                    'pcanywhere-data':5631,
                                    'pim-auto-rp':496,
                                    'pop2':109,
                                    'pop3':110,
                                    'pptp':1723,
                                    'rsh':514,
                                    'rtsp':554,
                                    'sip':5060,
                                    'smtp':25,
                                    'sqlnet':1522,
                                    'ssh':22,
                                    'sunrpc':111,
                                    'tacacs':49,
                                    'talk':517,
                                    'telnet':23,
                                    'uucp':540,
                                    'whois':43,
                                    'www':80,
                                    'tftp':69,
                                        }

        '''used to translate icmp types to codes'''
        self.icmp_type_to_real = {
            'echo-reply':0,
            'unreachable':3,
            'source-quench':4,
            'redirect':5,
            'alternate-address':6,
            'echo':8,
            'router-advertisement':9,
            'router-solicitation':10,
            'time-exceeded':11,
            'parameter-problem':12,
            'timestamp-request':13,
            'timestamp-reply':14,
            'information-request':15,
            'information-reply':16,
            'mask-request':17,
            'mask-reply':18,
            'conversion-error':31,
            'mobile-redirect':32,
            'traceroute':33434,
        }

        '''build dict to reference access groups'''
        self.accessgroup_dict = self.build_access_group_dict(accessgrouplines)
        '''build dict to reference objects'''
        self.object_lvl1 = self.build_object_data(objectlines)
        '''build dict to reference object-groups'''
        self.objectgroup_lvl1 = self.build_objectgroup_data(objectgrouplines)
        self.acldata = self.get_acl_data(acllines)

    def build_access_group_dict(self,accessgrouplines):
        '''return empty dict if there are no lines'''
        try:
            accessgrouplines = accessgrouplines.splitlines()
        except:
            return {}

        accessgroup_dict = {}
        '''Build dict of (name of acl:name of interface)'''
        for line in accessgrouplines:
            if len(line) > 13:
                if line[0:12] == 'access-group':
                    words = line.split ()
                    accessgroup_dict[words[1]] = words[4]
        return accessgroup_dict

    def build_object_data(self,objectlines):
        try:
            objectlines = objectlines.splitlines()
        except:
            return {}
        '''build dict for recursive lookup of object data at self.object_lvl1'''
        object_lvl1 = {}
        object_lvl2 = {}
        object_lvl3 = []
        object_lvl4 = {}
        for line in objectlines:
            words = line.split()
            if len(words) > 0:
                if str(line[0]) != ' ':
                    if words[0] == 'object':
                        if len(object_lvl2) > 0:
                            object_lvl2['object_children'] = object_lvl3
                            object_lvl1[object_lvl2['object_name']] = object_lvl2
                        object_lvl2 = {}
                        object_lvl3 = []
                        object_lvl2['object_name'] = words[2]
                        object_lvl2['object_type'] = words[1]
                        object_lvl2['object_description'] = None
                        object_lvl2['object_children'] = None
                elif str(line[0]) == ' ':
                    object_lvl4 = {}
                    if 'description' in words[0]:
                        object_lvl2['object_description'] = line.lstrip(' '+words[0])
                    else:
                        if 'host' in words[0]:
                            object_lvl4['child_type'] = 'host'
                            object_lvl4['child'] = words[1] + '/32'
                        elif 'subnet' in words[0]:
                            object_lvl4['child_type'] = 'subnet'
                            object_lvl4['child'] = str(ipaddress.ip_network(words[1]+'/'+words[2]))
                        elif 'fqdn' in words[0]:
                            object_lvl4['child_type'] = 'fqdn'
                            object_lvl4['child'] = words[2]
                        elif 'range' in words[0]:
                            object_lvl4['child_type'] = 'range'

                            nets = ipaddress.summarize_address_range(ipaddress.ip_address(words[1]),ipaddress.ip_address(words[2]))
                            list = []
                            for each in nets:
                                list.append(str(each))
                            object_lvl4['child'] = list

                        elif 'service' in words[0]:
                            '''protocol,direction,portseq/range'''
                            object_lvl4['child_type'] = 'service'
                            if words[3] == 'eq':
                                object_lvl4['child'] = [words[1],words[2],words[4]]
                            else:
                                print(words)
                                input(json.dumps(object_lvl2, indent=4))
                                input('unknown service object')
                        else:
                            print(words)
                            input(json.dumps(object_lvl2, indent=4))
                            input('unknown object type')
                        object_lvl3.append(object_lvl4)
        try:
            object_lvl2['object_children'] = object_lvl3
            object_lvl1[object_lvl2['object_name']] = object_lvl2
        except:
            pass
        return object_lvl1

    def build_objectgroup_data(self,objectgrouplines):
        """ build object group dict """

        '''return empty dict if the lines can not be split'''
        try:
            objectgrouplines = objectgrouplines.splitlines()
        except:
            return {}
        '''return empty dict if there are no lines'''
        if len(objectgrouplines) <= 3:
            return {}
        '''build dict for recursive lookup of object data at objectgroup_lvl1'''
        objectgroup_lvl1 = {}
        objectgroup_lvl2 = {}
        objectgroup_lvl3 = []
        objectgroup_lvl4 = {}
        for line in objectgrouplines:
            words = line.split()
            if len(words) > 0:
                if str(line[0]) != ' ':
                    if words[0] == 'object-group':
                        if len(objectgroup_lvl2) > 0:
                            objectgroup_lvl2['objectgroup_children'] = objectgroup_lvl3
                            objectgroup_lvl1[objectgroup_lvl2['objectgroup_name']] = objectgroup_lvl2
                        objectgroup_lvl2 = {}
                        objectgroup_lvl3 = []
                        objectgroup_lvl2['objectgroup_name'] = words[2]
                        objectgroup_lvl2['objectgroup_type'] = words[1]
                        objectgroup_lvl2['objectgroup_sub_type'] = None
                        objectgroup_lvl2['objectgroup_description'] = None
                        objectgroup_lvl2['objectgroup_children'] = None
                        if words[1] == 'service':
                            try:
                                objectgroup_lvl2['objectgroup_sub_type'] = words[3]
                            except:
                                pass

                elif line[0] == ' ':
                    objectgroup_lvl4 = {}
                    objectgroup_lvl4['objectgroup_type'] = None
                    objectgroup_lvl4['childgroup_sub_type'] = None

                    objectgroup_lvl4['child_type'] = None
                    if 'description' in words[0]:
                        objectgroup_lvl2['objectgroup_description'] = line.lstrip(' '+words[0])
                        objectgroup_lvl1[objectgroup_lvl2['objectgroup_name']] = objectgroup_lvl2
                    elif '-object' in words[0]:
                        objectgroup_lvl4['child'] = None
                        objectgroup_lvl4['objectgroup_type'] = words[0]
                        if 'group-object' == words[0]:
                            for each in (objectgroup_lvl1[str(words[1])]['objectgroup_children']):
                                try:
                                    each['childgroup_sub_type'] = objectgroup_lvl1[str(words[1])]['objectgroup_sub_type']
                                except:
                                    pass
                                objectgroup_lvl3.append(each)
                                #print(each)
                            '''this is a nested object'''
                            pass
                        elif 'port-object' == words[0]:
                            try:
                                objectgroup_lvl4['child'] = self.port_alias_to_real[words[2]]
                            except:
                                objectgroup_lvl4['child'] = words[2]
                                pass
                            objectgroup_lvl4['child_type'] = objectgroup_lvl2['objectgroup_sub_type']

                        elif 'network-object' == words[0]:
                            if words[1] == 'host':
                                objectgroup_lvl4['child'] = words[2]+'/32'
                                objectgroup_lvl4['child_type'] = 'host'
                            elif words[1] == 'object':
                                objectgroup_lvl4['child'] = self.object_lvl1[words[2]]
                                objectgroup_lvl4['child_type'] = 'object'


                            elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", words[1]):
                                objectgroup_lvl4['child'] = words[1] + '/' + words[2]
                                objectgroup_lvl4['child_type'] = 'net'
                            else:
                                pass
                            pass
                        elif 'service-object' == words[0]:
                            objectgroup_lvl4['child_type'] = words[1]
                            try:
                                if words[3] == 'eq':
                                    try:
                                        port = self.port_alias_to_real[words[4]]
                                    except:
                                        port = words[4]
                                    objectgroup_lvl4['child'] = [words[1],words[2],port]
                            except:
                                pass
                            try:
                                if words[3] == 'range':
                                    objectgroup_lvl4['childgroup_sub_type'] = words[3]
                                    objectgroup_lvl4['child'] = words[4]+'-'+words[5]
                            except:
                                pass

                        elif 'icmp-object' == words[0]:
                            if words[1] == 'echo':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'echo-reply':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'unreachable':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'time-exceeded':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'source-quench':
                                objectgroup_lvl4['child'] = words[1]
                            elif words[1] == 'alternate-address':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'conversion-error':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'mask-reply':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'mask-request':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'mask-redirect':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'parameter-problem':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'redirect':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'router-advertisement':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'router-solicitation':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'timestamp-reply':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'timestamp-request':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'traceroute':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'mobile-redirect':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'icmp-object':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            elif words[1] == 'information-reply':
                                objectgroup_lvl4['child'] = words[1]
                                pass
                            else:
                                print(words)
                                input('unknown icmp type')
                        elif 'protocol-object' == words[0]:
                            if words[1] == 'tcp':
                                pass
                            elif words[1] == 'udp':
                                pass
                            elif words[1] == 'icmp':
                                pass
                            elif words[1] == 'icmp6':
                                pass
                            else:
                                print(words)
                                input('unknown protocol object type')
                        else:
                            print(words)
                            input('unknown nested type')
                        objectgroup_lvl3.append(objectgroup_lvl4)

        objectgroup_lvl2['objectgroup_children'] = objectgroup_lvl3
        objectgroup_lvl1[objectgroup_lvl2['objectgroup_name']] = objectgroup_lvl2
        return objectgroup_lvl1

    def object_lookup(self,object):
        '''return list of networks recursively from object group to object'''
        list_return = []
        try:
            for v in self.objectgroup_lvl1[object]['objectgroup_children']:
                if v['child']:
                    if isinstance(v['child'], list):
                        for each in v['child']:
                            list_return.append(each)
                    else:
                        list_return.append(v['child'])
        except Exception as ex:
            pass
        return list_return

    def build_json_object_data(self,objectgroup_lvl1,object_lvl1):
        for k,v in objectgroup_lvl1.items():
            childdata = []
            for each in (v['objectgroup_children']):
                '''IF the object is another object, go get the data'''
                if each['child_type'] == 'object':
                    try:
                        pre = object_lvl1[str(each['child']['object_name'])]
                        children = pre['object_children']
                        for child in children:
                            if len(child) > 0:
                                if child['child_type'] == 'fqdn':
                                    childdata.append(child)
                                elif child['child_type'] == 'host':
                                    childdata.append(child)
                                elif child['child_type'] == 'subnet':
                                    childdata.append(child)
                                elif child['child_type'] == 'range':
                                    childdata.append(child)
                                else:
                                    input('unknown child_type')
                    except Exception as ex:
                        pass

                if each['child_type'] != 'object':
                    childdata.append(each)
            v['objectgroup_children'] = childdata
        return (json.dumps(objectgroup_lvl1, indent=4))

    def get_acl_data(self,acllines):
        '''controls flow of line data to proper parsing methods'''
        acldata = []
        self.remarkdata = {}

        linecount = 0
        acllines = acllines.splitlines()
        for line in acllines:
            temp_line_data = {}
            linecount += 1
            linesplit = line.split()
            if 'remark' in line:
                '''send to parse_remark_acl'''
                if linesplit[4] == 'remark':
                    output = self.parse_remark_acl(line)
                    self.remarkdata[output['acl_name'] + ',' + output['acl_line']] = output
            elif 'extended' and '(hitcnt=' in line:
                '''send to parse_extended_acl'''
                if linesplit[4] == 'extended':
                    acl = self.parse_extended_acl(line)
                    if acl != None:
                        acldata.append(acl)
            # elif 'standard' and '(hitcnt=' in line:
            #     '''send to parse_extended_acl'''
            #     if linesplit[4] == 'standard':
            #         temp_line_data['acl_type'] = 'standard'
            #         acldata.append(self.parse_extended_acl(line))
        return acldata

    def parse_remark_acl(self,line):
        cc = None
        app = None
        cdt = None
        exp = None
        output = {}
        words = line.split()
        remark = ('%s' % (line.split('remark')[-1]))
        try:
            cc = remark.split('CC:')[1].split()[0].replace(' ','')
        except:
            pass
        try:
            app = remark.split('APP:')[1].split()[0].replace(' ','')
        except:
            pass
        try:
            cdt = remark.split('CDT:')[1].split()[0].replace(' ', '')
        except:
            pass
        try:
            exp = remark.split('EXP:')[1].split()[0].replace(' ', '')
        except:
            pass
        output['acl_name'] = str(words[1])
        output['acl_line'] = words[3]
        output['acl_type'] = 'remark'
        output['acl_change_control'] = cc
        output['acl_applier'] = app
        output['acl_applied_timestamp'] = cdt
        output['acl_expiration'] = exp
        output['line'] = line
        return output

    def parse_extended_acl(self,line):
        if line[0] == ' ' or 'object' not in line:
            if '0x' in line:
                temp_line_data = {}
                linesplit = line.split()
                temp_line_data['acl_line'] = line
                temp_line_data['acl_name'] = str(linesplit[1])
                temp_line_data['acl_function'] = None
                temp_line_data['acl_applied_to'] = None
                '''check to see if this acl is an interface acl'''
                try:
                    temp_line_data['acl_applied_to'] = self.accessgroup_dict[temp_line_data['acl_name']]
                    temp_line_data['acl_function'] = 'if_acl'
                except:
                    pass
                temp_line_data['acl_line_num'] = linesplit[3]
                temp_line_data['acl_action'] = linesplit[5]
                temp_line_data['acl_protocol'] = linesplit[6]
                temp_line_data['acl_icmp_type'] = None
                temp_line_data['acl_src_zone'] = None
                temp_line_data['acl_src_net'] = []
                temp_line_data['acl_src_dns'] = None
                temp_line_data['acl_src_port'] = None
                temp_line_data['acl_dst_zone'] = None
                temp_line_data['acl_dst_net'] = []
                temp_line_data['acl_dst_dns'] = None
                temp_line_data['acl_dst_port'] = None
                temp_line_data['acl_enabled'] = True
                temp_line_data['acl_user'] = None
                previous_line = int(temp_line_data['acl_line_num'])-1
                try:
                    temp_line_data['acl_change_control'] = self.remarkdata[
                        temp_line_data['acl_name'] + ',' + str(previous_line)]['acl_change_control']
                except:
                    temp_line_data['acl_change_control'] = None
                try:
                    temp_line_data['acl_applier'] = self.remarkdata[
                        temp_line_data['acl_name'] + ',' + str(previous_line)]['acl_applier']
                except:
                    temp_line_data['acl_applier'] = None
                try:
                    temp_line_data['acl_applied_timestamp'] = self.remarkdata[
                        temp_line_data['acl_name'] + ',' + str(previous_line)]['acl_applied_timestamp']
                except:
                    temp_line_data['acl_applied_timestamp'] = None
                try:
                    temp_line_data['acl_expiration'] = self.remarkdata[
                        temp_line_data['acl_name'] + ',' + str(previous_line)]['acl_expiration']
                except:
                    temp_line_data['acl_expiration'] = None
                try:
                    temp_line_data['acl_hitcnt'] = line.split('(hitcnt=')[1].split(')')[0]
                except Exception as ex:
                    print(ex)
                    print(line)
                    input()
                if '0x' in linesplit[-1]:
                    temp_line_data['acl_id'] = linesplit[-1]
                else:
                    print('no hex')
                    print(line)
                    input()
                if 'inactive' in line:
                    temp_line_data['acl_enabled'] = False
                    temp_line_data['acl_line'] = line
                if temp_line_data['acl_protocol'] == 'ip':
                    temp_line_data.update(self.parse_extended_ip_acl(line.split(' ip ')[1]))
                elif temp_line_data['acl_protocol'] == 'tcp':
                    temp_line_data.update (self.parse_extended_tcp_acl(line.split(' tcp ')[1]))
                elif temp_line_data['acl_protocol'] == 'udp':
                    temp_line_data.update (self.parse_extended_udp_acl(line.split(' udp ')[1]))
                elif temp_line_data['acl_protocol'] == 'icmp':
                    temp_line_data.update (self.parse_extended_icmp_acl(line.split(' icmp ')[1]))
                elif temp_line_data['acl_protocol'] == 'icmp6':
                    temp_line_data.update (self.parse_extended_icmp6_acl(line.split(' icmp6 ')[1]))
                    #self.parse_extended_icmp6_acl(output)
                elif temp_line_data['acl_protocol'] == 'url':
                    pass
                    #self.parse_extended_url_acl(output)
                elif temp_line_data['acl_protocol'] == 'object':
                    pass
                    #self.parse_extended_object_acl(output)
                elif temp_line_data['acl_protocol'] == 'esp':
                    pass
                    #self.parse_extended_esp_acl(output)
                else:
                    pass
                return temp_line_data

    def get_data(self):
        self.data["fw_name"] = self.fw_name
        self.data["fw_context"] = self.fw_context
        self.data["fw_serial"] = self.fw_serial
        self.data["fw_model"] = self.fw_model
        self.data["fw_target"] = self.target
        self.data["timestamp"] = self.data_timestamp
        self.data["access-lists"] = self.acldata
        return self.data

    def parse_user(self,line):
        temp_line_data = {}
        linesplit = line.split()
        if 'user' in linesplit[0]:
            if linesplit[1][0] == '"':
                temp_line_data['acl_user'] = line.split('"')[1]
                line = line.lstrip(' ' + linesplit[0]).lstrip('"'+temp_line_data['acl_user']+'"')
            else:
                temp_line_data['acl_user'] = linesplit[1]
                line = line.lstrip(' '+linesplit[0]).lstrip(linesplit[1])
        return line,temp_line_data

    def parse_source(self,line):
        temp_line_data = {}
        temp_line_data['acl_src_net'] = []
        temp_line_data['acl_src_port'] = None
        linesplit = line.split()
        if linesplit[0] == 'host':
            temp_line_data['acl_src_net'].append(linesplit[1].split('(')[0]+'/32')
            line = str(line).lstrip(' '+linesplit[0]).lstrip(linesplit[1])
        elif 'any' in linesplit[0]:
            temp_line_data['acl_src_net'].append('0.0.0.0/0')
            line = line.lstrip(' ').lstrip(linesplit[0])
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", linesplit[0]):
            if '(' in linesplit[1]:
                temp_line_data['acl_src_net'].append(str(ipaddress.ip_network(
                    linesplit[0] + '/' + linesplit[1].split('(')[0])))
            else:
                temp_line_data['acl_src_net'].append(str(ipaddress.ip_network(
                    linesplit[0] + '/' + linesplit[1])))
            line = line.lstrip(' ').lstrip(linesplit[0]).lstrip(' ').lstrip(linesplit[1])
        elif 'v4-object-group' in linesplit[0]:
            for each in self.object_lookup(object=linesplit[1].replace((linesplit[1][linesplit[1].rindex('('):]), '')):
                temp_line_data['acl_src_net'].append(each)
            line = line.lstrip(' ').lstrip(linesplit[0]).lstrip(' ').lstrip(linesplit[1])
        elif 'object' in linesplit[0]:
            for each in self.object_lookup(object=linesplit[1].replace((linesplit[1][linesplit[1].rindex('('):]), '')):
                temp_line_data['acl_src_net'].append(each)
            line = line.lstrip(' '+linesplit[0]).lstrip(linesplit[1])
        elif 'range' in linesplit[0]:
            rangelist = []
            for ipaddr in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(linesplit[1].split('(')[0]),
                ipaddress.IPv4Address(linesplit[2].split('(')[0])):
                for each in ipaddr:
                    rangelist.append(str(each))
            line = line.lstrip(' ')\
                .lstrip(linesplit[0]).\
                lstrip(' ').\
                lstrip(linesplit[1]).\
                lstrip(' ')\
                .lstrip(linesplit[2])
            temp_line_data['acl_src_net'] = rangelist
        else:
            print(line)
            input('unknown source')
        return line,temp_line_data

    def parse_src_dns_check(self,line):
        temp_line_data = {}
        linesplit = line.split()
        if re.match(r"^[(][a-zA-Z0-9\-\.]+\.(com|io|dev|org|net|mil|edu|COM|ORG|NET|MIL|EDU)[)]$", linesplit[0]):
            line = line.lstrip(' ').lstrip(str(linesplit[0]))
            temp_line_data['acl_src_dns'] = linesplit[0].lstrip('(').rstrip(')')
            print('src dns match')
        return line,temp_line_data

    def parse_src_port(self,line):
        temp_line_data = {}
        linesplit = line.split()
        if linesplit[0] == 'eq':
            try:
                int(linesplit[1])
                temp_line_data['acl_src_port'] = linesplit[1]
            except:
                temp_line_data['acl_src_port'] = self.port_alias_to_real[linesplit[1]]
            line = line.lstrip(' ' + linesplit[0]).lstrip(linesplit[1])

        elif linesplit[0] == 'range':
            try:
                a = int(linesplit[1])
            except:
                a = int(self.port_alias_to_real[linesplit[1]])
            try:
                b = int(linesplit[2])
            except:
                b = int(self.port_alias_to_real[linesplit[2]])
            temp_line_data['acl_src_port'] = range(a - b)
        else:
            pass
        return line,temp_line_data

    def parse_destination(self,line):
        temp_line_data = {}
        temp_line_data['acl_dst_net'] = []
        temp_line_data['acl_dst_port'] = None
        linesplit = line.split()
        if linesplit[0] == 'host':
            temp_line_data['acl_dst_net'].append(linesplit[1].split('(')[0]+'/32')
            line = line.lstrip(' ').lstrip(' '+linesplit[0]).lstrip(' ').lstrip(linesplit[1])
        elif 'any' in linesplit[0]:
            temp_line_data['acl_dst_net'].append('0.0.0.0/0')
            line = line.lstrip(' ').lstrip(linesplit[0])
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",linesplit[0]):
            if '(' in linesplit[1]:
                temp_line_data['acl_dst_net'].append(
                    str(ipaddress.ip_network(linesplit[0]+'/'+linesplit[1].split('(')[0])))
            else:
                temp_line_data['acl_dst_net'].append(
                    str(ipaddress.ip_network(linesplit[0] + '/' + linesplit[1])))
            line = line.lstrip(' '+linesplit[0]).lstrip(' ').lstrip(linesplit[1])
        elif 'v4-object-group' in linesplit[0]:
            '''get list of objects'''
            for each in self.object_lookup(object=linesplit[1].replace((linesplit[1][linesplit[1].rindex('('):]), '')):
                temp_line_data['acl_dst_net'].append(each)
            line = line.lstrip(' '+linesplit[0]).lstrip(linesplit[1])
        elif 'object' in linesplit[0]:
            for each in self.object_lookup(object=linesplit[1].replace((linesplit[1][linesplit[1].rindex('('):]), '')):
                temp_line_data['acl_dst_net'].append(each)
            line = line.lstrip(' '+linesplit[0]).lstrip(linesplit[1])
        elif 'range' in linesplit[0]:
            rangelist = []
            for ipaddr in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(linesplit[1].split('(')[0]),
                ipaddress.IPv4Address(linesplit[2].split('(')[0])):
                for each in ipaddr:
                    rangelist.append(str(each))
            line = line.lstrip(' ') \
                .lstrip(linesplit[0]). \
                lstrip(' '). \
                lstrip(linesplit[1]). \
                lstrip(' ') \
                .lstrip(linesplit[2])
            temp_line_data['acl_dst_net'] = rangelist
        else:
            print('\r')
            print(line)
            print(linesplit)
            print(temp_line_data)
            input('unknown destination')
        return line,temp_line_data

    def parse_dst_dns_check(self,line):
        temp_line_data = {}
        linesplit = line.split()
        if re.match(r"^[(][a-zA-Z0-9\-\.]+\.(com|org|io|dev|net|mil|edu|COM|ORG|NET|MIL|EDU)[)]$", linesplit[0]):
            line = line.lstrip(' ').lstrip(str(linesplit[0]))
            temp_line_data['acl_dst_dns'] = linesplit[0].lstrip('(').rstrip(')')
        return line,temp_line_data

    def parse_dst_port(self,line):
        temp_line_data = {}
        linesplit = line.split()
        if linesplit[0] == 'eq':
            try:
                int(linesplit[1])
                temp_line_data['acl_dst_port'] = linesplit[1]
            except:
                temp_line_data['acl_dst_port'] = self.port_alias_to_real[linesplit[1]]

        elif linesplit[0] == 'range':
            try:
                a = int(linesplit[1])
            except:
                a = int(self.port_alias_to_real[linesplit[1]])
            try:
                b = int(linesplit[2])
            except:
                b = int(self.port_alias_to_real[linesplit[2]])

            temp_line_data['acl_dst_port'] = '%s-%s' % (a,b)
        elif '(hitcnt=' in linesplit[0]:
            ''' in cases where no ports are defined'''
            pass
        elif linesplit[0] == 'log':
            ''' in cases where no ports are defined'''
            pass
        else:
            print('\r')
            print(line)
            print(linesplit[0])
            print(linesplit[1])
            input('unknown destination port')
        return line,temp_line_data

    def parse_icmp_dst_port(self,line):
        temp_line_data = {}
        linesplit = line.split()
        if linesplit[0] in self.icmp_type_to_real:
            temp_line_data['acl_icmp_type'] = self.icmp_type_to_real[linesplit[0]]
        elif 'log' in linesplit[0]:
            pass
        elif '(hitcnt=' in linesplit[0]:
            pass
        else:
            print('\r')
            print(line)
            print(linesplit[0])
            print(linesplit[1])
            input('unknown icmp destination type')
        return line,temp_line_data

    def parse_extended_ip_acl(self,line):
        temp_line_data = {}
        line,data = self.parse_user(line)
        temp_line_data.update(data)
        line,data = self.parse_source(line)
        temp_line_data.update (data)
        line,data = self.parse_src_dns_check(line)
        temp_line_data.update (data)
        #line = self.parse_src_port(line)
        line,data = self.parse_destination(line)
        temp_line_data.update (data)
        line,data = self.parse_dst_dns_check(line)
        temp_line_data.update (data)
        #line = self.parse_dst_port(line)
        return temp_line_data

    def parse_extended_tcp_acl(self,line):
        temp_line_data = {}
        line,data = self.parse_user(line)
        temp_line_data.update (data)
        line,data = self.parse_source(line)
        temp_line_data.update (data)
        line,data = self.parse_src_dns_check(line)
        temp_line_data.update (data)
        line,data = self.parse_src_port(line)
        temp_line_data.update (data)
        line,data = self.parse_destination(line)
        temp_line_data.update (data)
        line,data = self.parse_dst_dns_check(line)
        temp_line_data.update (data)
        line,data = self.parse_dst_port(line)
        temp_line_data.update (data)
        return temp_line_data

    def parse_extended_udp_acl(self,line):
        temp_line_data = {}
        line,data = self.parse_user(line)
        temp_line_data.update (data)
        line,data = self.parse_source(line)
        temp_line_data.update (data)
        line,data = self.parse_src_dns_check(line)
        temp_line_data.update (data)
        #line = self.parse_src_port(line)
        line,data = self.parse_destination(line)
        temp_line_data.update (data)
        line,data = self.parse_dst_dns_check(line)
        temp_line_data.update (data)
        line,data = self.parse_dst_port(line)
        temp_line_data.update (data)
        return temp_line_data

    def parse_extended_icmp_acl(self,line):
        temp_line_data = {}
        line,data = self.parse_user(line)
        temp_line_data.update (data)
        line,data = self.parse_source(line)
        temp_line_data.update (data)
        line,data = self.parse_src_dns_check(line)
        temp_line_data.update (data)
        line,data = self.parse_src_port(line)
        temp_line_data.update (data)
        line,data = self.parse_destination(line)
        temp_line_data.update (data)
        line,data = self.parse_dst_dns_check(line)
        temp_line_data.update (data)
        line,data = self.parse_icmp_dst_port(line)
        temp_line_data.update (data)
        return temp_line_data

    def parse_extended_icmp6_acl(self,line):
        temp_line_data = {}
        line,data = self.parse_user(line)
        temp_line_data.update (data)
        line,data = self.parse_source(line)
        temp_line_data.update (data)
        line,data = self.parse_src_dns_check(line)
        temp_line_data.update (data)
        #line = self.parse_src_port(line)
        line,data = self.parse_destination(line)
        temp_line_data.update (data)
        line,data = self.parse_dst_dns_check(line)
        temp_line_data.update (data)
        line,data = self.parse_icmp_dst_port(line)
        temp_line_data.update (data)
        return temp_line_data






