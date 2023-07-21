#:mode=python:
# Python Script used to filter out nf-monitor
# For filtering all the traffic will be redirect by ss-redir
# Filter Source IP address, according to dnsmasq.lease to locate
# source device from local network 
# it will require to mount share storage from main router
# and sync lease data from main router to here, and then monitoring
# all new create traffic to outside of localnetwork which marked as
# outbound
#
# require following other python script to analysis this match and date
# and store the result at main router side
# DoH based firewall access direct use sock5 tunnle bypassed the DNS query
# and its relevant audit, just left IP can be traced.
# DoH can provide considerable better security/privacy
#   it can be blocked, but hard to audit at wifi router
#
import os;
import subprocess;
import re;
import time;
import threading;
import sys;
import copy;

from threading import Lock;

from MySQLdb import _mysql;
import MySQLdb;

# Modify the mac address of the DMZ address   
global_device_mac_pair = {"?????" : "VM of DNS forwarder"}
global_device_ignore = {}

# Global forward list
global_fwd_list = []
# Global forward configured list
global_fwd_configured_target_ip_list = {}
# Lock for multi-threading
global_fwd_configured_target_ip_list_lock = Lock()


# Fixed configuration of DMZ host IP addr, this is the fixed IP address currently used with UmbrellaFirewall
global_dmz_ip_addr = "192.168.10.84"


# Global dmz target IP list
global_dmz_target_list = []
# buffered Configured DMZ list for timeout counting
global_dmz_configured_target_ip_list = {}
# Lock for multi-threading
global_dmz_configured_target_ip_list_lock = Lock()

# Timeout for allow list entries
global_default_timeout = 60 * 30

def split_addr_to_ip_port(addr):
    addr_parts = addr.split(':')
    ip = addr_parts[0]
    port = addr_parts[1]

    return (ip, port)    

def classify_traffic_types(db, arp_filter, tproto, src, dst, via = ""):
    global global_device_ignore

    src_ip, src_port = split_addr_to_ip_port(src)
    dst_ip, dst_port = split_addr_to_ip_port(dst)

    current_time = time.localtime()
    mac_addr = "00:00:00:00:00:00"

    arp_process = subprocess.Popen(['arp', '-an', src_ip],
                        stdout=subprocess.PIPE)
    arp_output = arp_process.stdout.readline()
    arp_match = arp_filter.match(arp_output.decode("utf-8"))
    if arp_match:
        if arp_match.group(3):
            mac_addr = arp_match.group(3)

    dev_comments = "Unknown"
    if mac_addr in global_device_mac_pair:
        dev_comments = global_device_mac_pair[mac_addr]

    if tproto == "udp":
        # UDP Processing
        return 
    elif tproto == "tcp":
        # Critical Monitoring of the TCP link, record 5901/22 port connection from where, who, last for how long time.        
        if dst_port == "443":
            # HTTPS traffic outbound, need further classify the source IP address
            # to form a allow list according to lease
            return
        elif dst_port == "53":
            # TCP based DNS lookup
            return
        elif dst_port == "8388" and dst_ip == "192.168.10.1":
            # Direct socket5 bypass
            return
        elif src_ip == "192.168.10.84":
            return
        elif dst_ip == "192.168.10.84":
            # Critical Retry Mandatory
            update_success = False
            retry_count = 0
            while update_success == False and retry_count < 5:
                try:
                    retry_count = retry_count + 1
                    if dst_port == "5901":
                        insert_vnc_str = "insert into controller_vnc_service values (0, \"{mac}\", \"{ip}\", \"{dev}\", current_timestamp);".format(mac=mac_addr, ip=src_ip, dev=dev_comments)
                        db.query(insert_vnc_str)
                    elif dst_port == "22":
                        insert_ssh_str = "insert into controller_ssh_service values (0, \"{mac}\", \"{ip}\", \"{dev}\", current_timestamp);".format(mac=mac_addr, ip=src_ip, dev=dev_comments)
                        db.query(insert_ssh_str)
                    elif dst_port == "514":
                        insert_syslog_str = "insert into controller_syslog_service values (0, \"{mac}\", \"{ip}\", \"{dev}\", current_timestamp);".format(mac=mac_addr, ip=src_ip, dev=dev_comments)
                        db.query(insert_syslog_str)
                    else:
                        print(time.asctime(current_time), ": Alert Critical Unknown Connection", tproto, " src ", src, "dst ", dst)
                    update_success = True
                except (MySQLdb.Error, MySQLdb.Warning) as e:
                    update_success = False
                    print("Access control database update failed  ", e, "Reconnecting")
                    db = _mysql.connect(host="localhost", user="auditor", password="?", database="RouterServiceMonitor")            
            if retry_count >=5:
                print("Abnormal Shit happend, Mysql Database down")
        else:
            # other TCP dst port all need to be logged
            if via == "":
                print(time.asctime(current_time), ": new ", tproto, " src ", src, " mac_addr ", mac_addr, " dst ", dst)
            else:
                print(time.asctime(current_time), ": new ", tproto, " src ", src, " mac_addr ", mac_addr, " dst ", dst, "via ", via)

def nf_connection_monitor():
    # Connectivity monitoring by Netfilter
    # All links outgoing through the forwarding will be monitored
    # it will not monitoring the link direct go with Main router which
    # based on FreeBSD, will use python script on main router to collect
    # monitoring with ipfw
    nf_process = subprocess.Popen(['nf-monitor', 'ct-new'],
                                    stdout=subprocess.PIPE)

    dnat_filter = re.compile("(^tcp|^udp) ([\w\W]+)", re.IGNORECASE)
    link_create_filter = re.compile("", re.IGNORECASE)
    ip_filter = re.compile("(\d+\.\d+\.\d+\.\d+\:\d+)", re.IGNORECASE)

    access_db = _mysql.connect(host="localhost", user="auditor", password="?", database="RouterServiceMonitor")
    arp_filter = re.compile("^\? \((\d+\.\d+\.\d+\.\d+)\) at ((\w+\:\w+\:\w+\:\w+\:\w+\:\w+) \[ether\]|(<\w+>)) on (\w+)", re.IGNORECASE)

    while True:
        output = nf_process.stdout.readline()
        dnat_match = dnat_filter.match(output.decode("utf-8"))
        if dnat_match:
            ips = ip_filter.findall(dnat_match.group(2))
            tproto = dnat_match.group(1)
            if len(ips) == 4:
                classify_traffic_types(access_db, arp_filter, tproto, ips[0], ips[1], ips[2])
            elif len(ips) == 2:
                classify_traffic_types(access_db, arp_filter, tproto, ips[0], ips[1])
            sys.stdout.flush()

def update_dns_ans_to_db(db, name, resolved_record_type, resolved_record):
    query_phase = "Start Update Ans"
    try:
        query_str = "select * from dns_records where name=\"{domain_name}\" and record_type=\"{record_type}\" and record_content=\"{record_content}\";".format(domain_name=name, record_type=resolved_record_type, record_content=resolved_record)
        query_phase = "sheck domain name with specific records existed " + name
        db.query(query_str)

        r = db.store_result()
        if not r.fetch_row():
            query_phase = "update domain name"
            insert_str = "insert into dns_records values (0, \"{domain_name}\", \"{record_type}\", \"{resolved_record}\");".format(domain_name=name, record_type=resolved_record_type, resolved_record=resolved_record)
            db.query(insert_str)
    except (MySQLdb.Error, MySQLdb.Warning) as e:
        print("wrong during query database ", query_phase, " error ", e, "reconnecting")
        db = _mysql.connect(host="localhost", user="auditor", password="?", database="DNSMonitor")


def update_dns_record_to_db(db, name, src_ip, mac_addr, comments="not registered"):
    query_phase = "Start"
    try:
        query_str = "select * from domain_names where name=\"{lookup_name}\";".format(lookup_name=name)
        query_phase = "check domain existed" + name
        db.query(query_str)

        r = db.store_result()
        if r.fetch_row():
            update_str = "update domain_names set last_lookup=current_timestamp where name=\"{domain_name}\";".format(domain_name=name)
            query_phase = "update domain_names table for " + name
            db.query(update_str)
        else:
            insert_str = "insert into domain_names values (\"{domain_name}\", current_timestamp, 0);".format(domain_name=name)
            query_phase = "insert domain_names table for " + name
            db.query(insert_str)

        query_phase = "Get ID for ACL table for name " + name
        id_str = "select ID from domain_names where name=\"{domain_name}\";".format(domain_name=name)
        db.query(id_str)

        id_r = db.store_result()
        id = id_r.fetch_row()
        if id:
            index = int(id[0][0])
            query_phase = "check acl table existed for access_records table"

            select_access_record_str = "select * from access_records where domain_name_idx={domain_id} and ip=\"{ip}\" and mac_address=\"{addr}\";".format(domain_id=index, ip=src_ip, addr=mac_addr)
            db.query(select_access_record_str)
            tbl_r = db.store_result()
            if tbl_r.fetch_row():
                query_phase = "update acl table existed entry for " + name + "mac  " + mac_addr
                update_acl_str = "update access_records set counts = counts + 1, last_lookup=current_timestamp where domain_name_idx={domain_id} and ip=\"{ip}\" and mac_address=\"{addr}\";".format(domain_id=index, ip=src_ip, addr=mac_addr)
                db.query(update_acl_str)
            else:
                query_phase = "insert acl table entry for " + name + "table " + "mac  " + mac_addr
                insert_acl_str = "insert into access_records values (\"{addr}\", \"{device}\", 1, current_timestamp, {domain_id}, \"{ip}\");".format(addr=mac_addr, device=comments, domain_id=index, ip=src_ip)
                db.query(insert_acl_str)
        else:
            print("Not able to find index for lookuped domain name ", name)
    except (MySQLdb.Error, MySQLdb.Warning) as e:
        print("wrong during query database ", query_phase, " error ", e, "reconnecting")
        db = _mysql.connect(host="localhost", user="auditor", password="?", database="DNSMonitor")


def dmz_lookup_monitor():
    """
    DMZ Direct access DNS lookup monitoring for name based bypass
    """
    # DMZ original DNS lookup traffic comes with 127.0.0.1:53
    dns_dump_process = subprocess.Popen(['tcpdump', '-vnnttl', '-i', 'lo', '--immediate-mode', 'udp and host 127.0.0.1 and port 53'],
                                          stdout=subprocess.PIPE)
    dns_ans_filter = re.compile("([\d\.]+) > ([\d\.]+): ([\d]+) ([\d]+)\/([\d]+)\/([\d]+) ([\w\.\,\s\-]+) (\([\d]+\))", re.IGNORECASE)

    dns_ans_record_filter = re.compile("([\w\d\.\-]+\s[\w]+\s[\w\d\.\-]+)", re.IGNORECASE)
    dns_ans_record_split = re.compile("([\w\d\-\.]+)\s([\w]+)\s([\w\.\-]+)", re.IGNORECASE)

    while True:
        output = dns_dump_process.stdout.readline()
        decoded_output = output.decode('utf-8').strip()
        dns_ans_match = dns_ans_filter.match(decoded_output)
        if dns_ans_match:
            src_ip = dns_ans_match.group(1)
            dst_ip = dns_ans_match.group(2)
            if dns_ans_match.group(4):
                ans_count = int(dns_ans_match.group(4))
                if ans_count > 0:
                    answers = dns_ans_match.group(7)
                    if answers:
                        updated_ans_count = 0
                        single_ans_with_can_name = False
                        for record in re.finditer(dns_ans_record_filter, answers):
                            record_match = dns_ans_record_split.match(record.group(1))
                            name = record_match.group(1)
                            record_type = record_match.group(2)
                            record_content = record_match.group(3)
                            update_dynamic_firewall_dmz_access_control(name, single_ans_with_can_name, record_type, record_content)
                            updated_ans_count = updated_ans_count + 1
                        if ans_count != updated_ans_count:
                            print("Error when insert answers to database expect ", ans_count, "but have ", updated_ans_count)


def dns_lookup_monitor():
    dns_db = _mysql.connect(host="localhost", user="auditor", password="?", database="DNSMonitor")
    global global_device_mac_pair

    # Monitoring all outgoring DNS lookup and record all name resolution 
    # with filtered by TCPDUMP from local network, for dnsmasq on main router
    # DNS be forwarded to Linux VM, so all lookup will be recorded here
    dns_dump_process = subprocess.Popen(['tcpdump', '-vnnttl', '--immediate-mode', 'udp and host 192.168.10.84 and port 53 and not host 192.168.1.1'],
                                          stdout=subprocess.PIPE)
    dns_ans_filter = re.compile("([\d\.]+) > ([\d\.]+): ([\d]+) ([\d]+)\/([\d]+)\/([\d]+) ([\w\.\,\s\-]+) (\([\d]+\))", re.IGNORECASE)

    dns_ans_record_filter = re.compile("([\w\d\.\-]+\s[\w]+\s[\w\d\.\-]+)", re.IGNORECASE)
    dns_ans_record_split = re.compile("([\w\d\-\.]+)\s([\w]+)\s([\w\.\-]+)", re.IGNORECASE)

    dns_query_filter = re.compile("([\d\.]+) > ([\d\.]+): ([\d]+)\+ ([\w]+)\?\s([\w\.\-]+) (\([\d]+\))", re.IGNORECASE)

    ip_spliter = re.compile("(\d+\.\d+\.\d+\.\d+).(\d+)", re.IGNORECASE)

    arp_filter = re.compile("^\? \((\d+\.\d+\.\d+\.\d+)\) at ((\w+\:\w+\:\w+\:\w+\:\w+\:\w+) \[ether\]|(<\w+>)) on (\w+)", re.IGNORECASE)

    while True:
        output = dns_dump_process.stdout.readline()
        decoded_output = output.decode("utf-8").strip()
        dns_query_match = dns_query_filter.match(decoded_output)
        if dns_query_match:
            src = dns_query_match.group(2)
            src_match = ip_spliter.match(src)
            if src_match:
                src_ip = src_match.group(1)

                dns_lookup_type = dns_query_match.group(4)
                domain_name = dns_query_match.group(5)

                mac_addr = "00:00:00:00:00:00"

                arp_process = subprocess.Popen(['arp', '-an', src_ip],
                                    stdout=subprocess.PIPE)
                arp_output = arp_process.stdout.readline()
                arp_match = arp_filter.match(arp_output.decode("utf-8"))
                if arp_match:
                    if arp_match.group(3):
                        mac_addr = arp_match.group(3)

                if mac_addr in global_device_ignore:
                    continue
                else:
                    if mac_addr in global_device_mac_pair:
                        update_dns_record_to_db(dns_db, domain_name, src_ip, mac_addr, global_device_mac_pair[mac_addr])                     
                    else:
                        update_dns_record_to_db(dns_db, domain_name, src_ip, mac_addr)                     
        else:
            dns_ans_match = dns_ans_filter.match(decoded_output)
            if dns_ans_match:
                if dns_ans_match.group(4):
                    ans_count = int(dns_ans_match.group(4))
                    if ans_count > 0:
                        answers = dns_ans_match.group(7)
                        if answers:
                            updated_ans_count = 0
                            single_ans_with_can_name = False
                            for record in re.finditer(dns_ans_record_filter, answers):
                                record_match = dns_ans_record_split.match(record.group(1))
                                name = record_match.group(1)
                                record_type = record_match.group(2)
                                record_content = record_match.group(3)
                                update_dns_ans_to_db(dns_db, name, record_type, record_content)
                                find_if_name_in_forward_name_list(name, single_ans_with_can_name, record_type, record_content)
                                updated_ans_count = updated_ans_count + 1
                            if ans_count != updated_ans_count:
                                print("Error when insert answers to database expect ", ans_count, "but have ", updated_ans_count)

def timeout_process():
    """
    Timeout Process for all timeout firewall entries
    """
    global global_dmz_configured_target_ip_list
    global global_dmz_configured_target_ip_list_lock

    global global_fwd_configured_target_ip_list
    global global_fwd_configured_target_ip_list_lock

    flush_cnt = 0
    while True:
        time.sleep(10)
        global_dmz_configured_target_ip_list_lock.acquire()
        for ip in global_dmz_configured_target_ip_list:
            if ip in global_dmz_configured_target_ip_list:
                if time.time() - global_dmz_configured_target_ip_list[ip] > global_default_timeout:
                    async_del_dmz_allow_target("async_del_dmz_allow_target", ip)
                    del global_dmz_configured_target_ip_list[ip]
        global_dmz_configured_target_ip_list_lock.release()

        global_fwd_configured_target_ip_list_lock.acquire()
        for ip in global_fwd_configured_target_ip_list:
            if ip in global_fwd_configured_target_ip_list:
                if time.time() - global_fwd_configured_target_ip_list[ip] > global_default_timeout:
                    async_del_fwd_allow_target("async_del_fwd_allow_target", ip)
                    del global_fwd_configured_target_ip_list[ip]
        global_fwd_configured_target_ip_list_lock.release()        

        flush_cnt = flush_cnt + 1
        if flush_cnt >= 1800:
            # Every 5 hours flush the fwdlist table
            global_fwd_configured_target_ip_list_lock.acquire()
            global_fwd_configured_target_ip_list.clear()
            async_flush_fwd_allow_table("fwdlist")
            global_fwd_configured_target_ip_list_lock.release()
            flush_cnt = 0


# automatic configure direct forward IP address to ipfw firewall
def async_add_fwd_allow_target(name, fwd_ip):
    """
    Async configure Dynamic firewall on FreeBSD ipfw fwd_list table Make sure you have 192.168.10.1 as the UmbrellaFirewall
    """
    cmdline = "curl -k -X POST https://192.168.10.1:6466/add_fwd_target_ip?ip_addr={ip}".format(ip=fwd_ip)
    status = os.system(cmdline)

def async_del_fwd_allow_target(name, fwd_ip):
    """
    Async configure Dynamic firewall on FreeBSD ipfw fwd_list table
    """
    cmdline = "curl -k -X POST https://192.168.10.1:6466/del_fwd_target_ip?ip_addr={ip}".format(ip=fwd_ip)
    status = os.system(cmdline)

def async_flush_fwd_allow_table(name):
    """
    Async flush Dynamic firewall on FreeBSD ipfw fwd_list table
    """
    cmdline = "curl -k -X POST https://192.168.10.1:6466/del_fwd_target_ip?table=fwdlist"
    status = os.system(cmdline)

# Async add dmz firewall
def async_add_dmz_allow_target(name, fwd_ip):
    """
    Async configure Dynamic firewall on FreeBSD ipfw fwd_list table
    """
    cmdline = "curl -k -X POST https://192.168.10.1:6466/add_dmz_target_ip?ip_addr={ip}".format(ip=fwd_ip)
    status = os.system(cmdline)

# Async del dmz firewall
def async_del_dmz_allow_target(name, fwd_ip):
    """
    Async configure Dynamic firewall on FreeBSD ipfw fwd_list table
    """
    cmdline = "curl -k -X POST https://192.168.10.1:6466/del_dmz_target_ip?ip_addr={ip}".format(ip=fwd_ip)
    status = os.system(cmdline)

def find_if_name_in_forward_name_list(name, same_record, record_type, record_content):
    global global_fwd_list
    # Only activate on A record for IPv4 only network 
    if record_type == "CNAME":
        for name_pattern in global_fwd_list:
            name_match = name_pattern.match(name.strip())
            if name_match:
                same_record = True
    if record_type == "A":
        global_fwd_configured_target_ip_list_lock.acquire()
        if same_record:
            # CNAME used for load balance traffic may have different resolved name
            # then with IP
            if record_content in global_fwd_configured_target_ip_list:
                global_fwd_configured_target_ip_list[record_content] = time.time()
            else:
                async_add_fwd_allow_target(name, record_content)
                global_fwd_configured_target_ip_list[record_content] = time.time()
        else:
            for name_pattern in global_fwd_list:
                name_match = name_pattern.match(name.strip())
                if name_match:
                    if record_content in global_fwd_configured_target_ip_list:
                        global_fwd_configured_target_ip_list[record_content] = time.time()
                    else:
                        async_add_fwd_allow_target(name, record_content)
                        global_fwd_configured_target_ip_list[record_content] = time.time()
        global_fwd_configured_target_ip_list_lock.release()

def update_dynamic_firewall_dmz_access_control(name, same_record, record_type, record_content):
    global global_dmz_target_list
    global global_dmz_configured_target_ip_list
    global global_dmz_configured_target_ip_list_lock
    if record_type == "CNAME":
        for name_pattern in global_dmz_target_list:
            name_match = name_pattern.match(name.strip())
            if name_match:
                same_record = True
    if record_type == "A":
        global_dmz_configured_target_ip_list_lock.acquire()
        if same_record:
            if record_content in global_dmz_configured_target_ip_list:
                global_dmz_configured_target_ip_list[record_content] = time.time()
            else:
                async_add_dmz_allow_target(name, record_content)
                global_dmz_configured_target_ip_list[record_content] = time.time()
        else:
            for name_pattern in global_dmz_target_list:
                name_match = name_pattern.match(name.strip())
                if name_match:
                    if record_content in global_dmz_configured_target_ip_list:
                        global_dmz_configured_target_ip_list[record_content] = time.time()
                    else:
                        async_add_dmz_allow_target(name, record_content)
                        global_dmz_configured_target_ip_list[record_content] = time.time()
        global_dmz_configured_target_ip_list_lock.release()

def load_device_list(device_list):
    global global_device_mac_pair
    global global_device_ignore
    device_list_filter = re.compile("([\w\:]+)[ \t]+\"([\w\W]+)\"\s*(\w+)*", re.IGNORECASE)
    if device_list != "":
        f = open(device_list, "r")
        lines = f.readlines()
        for line in lines:
            device_match = device_list_filter.match(line)
            if device_match:
                if device_match.group(1) and device_match.group(2):
                    mac_addr = device_match.group(1)
                    device_name = device_match.group(2)
                    global_device_mac_pair[mac_addr] = device_name
                    if device_match.group(3):
                        if device_match.group(3) == "ignore":
                            global_device_ignore[mac_addr] = True 

def load_forward_name_list(fwd_list):
    global global_fwd_list
    if fwd_list != "":
        f = open(fwd_list, "r")
        lines = f.readlines()
        for line in lines:
            if line.startswith('#') == False:
                name_filter = re.compile(line.strip(), re.IGNORECASE)
                global_fwd_list.append(name_filter)

# Below function writteing by Copilot
# it can be further optimize to find global variable name
# match in previous defined list, (it is dangerous to define
# global variable by Copilot, if similiar name of variable existed
# it will make debug very hard) 
def load_dmz_allow_name_list(dmz_list):
    global global_dmz_target_list
    if dmz_list != "":
        f = open(dmz_list, "r")
        lines = f.readlines()
        for line in lines:
            if line.startswith('#') == False:
                name_filter = re.compile(line.strip(), re.IGNORECASE)
                global_dmz_target_list.append(name_filter)

if __name__ == '__main__':
    known_device_list = ""
    forward_name_list = ""

    if sys.argv[1]:
        known_device_list = sys.argv[1]

    if sys.argv[2]:
        forward_name_list = sys.argv[2]
    
    if sys.argv[3]:
        dmz_name_list = sys.argv[3]

    if known_device_list != "":
        load_device_list(known_device_list)

    if forward_name_list != "":
        load_forward_name_list(forward_name_list)

    if dmz_name_list != "":
        load_dmz_allow_name_list(dmz_name_list)

    dns_mon_th = threading.Thread(name="dns mon", target=dns_lookup_monitor)
    dns_mon_th.start()

    nf_con_mon_th = threading.Thread(name='nf con_mon', target=nf_connection_monitor)
    nf_con_mon_th.start()

    dmz_mon_th = threading.Thread(name='dmz mon', target=dmz_lookup_monitor)
    dmz_mon_th.start()

    timeout_process_th = threading.Thread(name='timeout process', target=timeout_process)
    timeout_process_th.start()

    while True:
        time.sleep(10)
