#!/usr/bin/python
# LICENSE: Apache 2.0
# Copyright 2021-2023 Zhao Zhe, Alex Zhao
#
# Umbrella Agent of Dynamic Firewall Configuration
#
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
# Required DBs for auditing:
#
#  DNS Monitoring Database
#
#     Table  dns_records
#            +----------------+--------------+------+-----+---------+----------------+
#            | Field          | Type         | Null | Key | Default | Extra          |
#            +----------------+--------------+------+-----+---------+----------------+
#            | ID             | int(11)      | NO   | PRI | NULL    | auto_increment |
#            | name           | varchar(255) | YES  |     | NULL    |                |
#            | record_type    | varchar(16)  | YES  |     | NULL    |                |
#            | record_content | varchar(255) | YES  |     | NULL    |                |
#            +----------------+--------------+------+-----+---------+----------------+
#     
#     Table  domain_names
#            +-------------+----------+------+-----+---------+----------------+
#            | Field       | Type     | Null | Key | Default | Extra          |
#            +-------------+----------+------+-----+---------+----------------+
#            | name        | text     | YES  |     | NULL    |                |
#            | last_lookup | datetime | YES  |     | NULL    |                |
#            | ID          | int(11)  | NO   | PRI | NULL    | auto_increment |
#            +-------------+----------+------+-----+---------+----------------+
#
#     Table  access_records
#            +-----------------+--------------+------+-----+---------+-------+
#            | Field           | Type         | Null | Key | Default | Extra |
#            +-----------------+--------------+------+-----+---------+-------+
#            | mac_address     | char(255)    | YES  |     | NULL    |       |
#            | comments        | text         | YES  |     | NULL    |       |
#            | counts          | int(11)      | YES  |     | NULL    |       |
#            | last_lookup     | datetime     | YES  |     | NULL    |       |
#            | domain_name_idx | int(11)      | NO   |     | NULL    |       |
#            | ip              | varchar(128) | YES  |     | NULL    |       |
#            +-----------------+--------------+------+-----+---------+-------+
#
#  Router Basic Service Database
#
#     Table  controller_vnc_service
#            +-------------+------------------+------+-----+---------+----------------+
#            | Field       | Type             | Null | Key | Default | Extra          |
#            +-------------+------------------+------+-----+---------+----------------+
#            | ID          | int(10) unsigned | NO   | PRI | NULL    | auto_increment |
#            | mac_address | char(255)        | YES  |     | NULL    |                |
#            | ip_address  | char(255)        | YES  |     | NULL    |                |
#            | comments    | tinytext         | YES  |     | NULL    |                |
#            | last_access | datetime         | YES  |     | NULL    |                |
#            +-------------+------------------+------+-----+---------+----------------+
#
#     Table  controller_ssh_service
#            +-------------+------------------+------+-----+---------+----------------+
#            | Field       | Type             | Null | Key | Default | Extra          |
#            +-------------+------------------+------+-----+---------+----------------+
#            | ID          | int(10) unsigned | NO   | PRI | NULL    | auto_increment |
#            | mac_address | char(255)        | YES  |     | NULL    |                |
#            | ip_address  | char(255)        | YES  |     | NULL    |                |
#            | comments    | tinytext         | YES  |     | NULL    |                |
#            | last_access | datetime         | YES  |     | NULL    |                |
#            +-------------+------------------+------+-----+---------+----------------+
#
#     Table  controller_syslog_service
#            +-------------+------------------+------+-----+---------+----------------+
#            | Field       | Type             | Null | Key | Default | Extra          |
#            +-------------+------------------+------+-----+---------+----------------+
#            | ID          | int(10) unsigned | NO   | PRI | NULL    | auto_increment |
#            | mac_address | char(255)        | YES  |     | NULL    |                |
#            | ip_address  | char(255)        | YES  |     | NULL    |                |
#            | comments    | tinytext         | YES  |     | NULL    |                |
#            | last_access | datetime         | YES  |     | NULL    |                |
#            +-------------+------------------+------+-----+---------+----------------+
#
import os;
import subprocess;
import re;
import time;
import threading;
import sys;
import json;

from threading import Lock;

from MySQLdb import _mysql;
import MySQLdb;

# Modify the mac address of the DMZ address   
global_device_mac_pair = {}
global_device_ignore = {}

# Global forward list
global_fwd_list = []
# Global forward configured list
global_fwd_configured_target_ip_list = {}
# Lock for multi-threading
global_fwd_configured_target_ip_list_lock = Lock()

# Global dmz target IP list
global_dmz_target_list = []
# buffered Configured DMZ list for timeout counting
global_dmz_configured_target_ip_list = {}
# Lock for multi-threading
global_dmz_configured_target_ip_list_lock = Lock()

# Timeout for allow list entries 30 minutes
global_default_timeout = 60 * 30

def split_addr_to_ip_port(addr):
    addr_parts = addr.split(':')
    ip = addr_parts[0]
    port = addr_parts[1]

    return (ip, port)    

def classify_traffic_types(db, agent_ip, arp_filter, tproto, src, dst, via = ""):
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
        elif dst_port == "8388":
            # Direct socket5 bypass
            return
        elif src_ip == agent_ip:
            return
        elif dst_ip == agent_ip:
            # Critical Retry Mandatory
            try:
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
            except (MySQLdb.Error, MySQLdb.Warning) as e:
                print("Access control database update failed  ", e, "Reconnecting")
                raise e
        else:
            # other TCP dst port all need to be logged
            if via == "":
                print(time.asctime(current_time), ": new ", tproto, " src ", src, " mac_addr ", mac_addr, " dst ", dst)
            else:
                print(time.asctime(current_time), ": new ", tproto, " src ", src, " mac_addr ", mac_addr, " dst ", dst, "via ", via)

def nf_connection_monitor(db_host, db_user, db_password, db_database, firewall_ip, firewall_port, agent_ip):
    # Connectivity monitoring by Netfilter
    # All links outgoing through the forwarding will be monitored
    # it will not monitoring the link direct go with Main router which
    # based on FreeBSD, will use python script on main router to collect
    # monitoring with ipfw
    try:
        access_db = _mysql.connect(host=db_host, user=db_user, password=db_password, database=db_database)
    except BaseException as e:
        print("Host monitoring Connecting Database Failed ", e)
        sys.exit()

    try:
        nf_process = subprocess.Popen(['nf-monitor', 'ct-new'],
                                        stdout=subprocess.PIPE)
    except BaseException as e:
        print("Not able to initiate nf-monitor to check linux host connection ", e)
        sys.exit()

    dnat_filter = re.compile("(^tcp|^udp) ([\w\W]+)", re.IGNORECASE)
    link_create_filter = re.compile("", re.IGNORECASE)
    ip_filter = re.compile("(\d+\.\d+\.\d+\.\d+\:\d+)", re.IGNORECASE)

    arp_filter = re.compile("^\? \((\d+\.\d+\.\d+\.\d+)\) at ((\w+\:\w+\:\w+\:\w+\:\w+\:\w+) \[ether\]|(<\w+>)) on (\w+)", re.IGNORECASE)

    while True:
        output = nf_process.stdout.readline()
        dnat_match = dnat_filter.match(output.decode("utf-8"))
        if dnat_match:
            ips = ip_filter.findall(dnat_match.group(2))
            tproto = dnat_match.group(1)
            try:
                if len(ips) == 4:
                    classify_traffic_types(access_db, agent_ip, arp_filter, tproto, ips[0], ips[1], ips[2])
                elif len(ips) == 2:
                    classify_traffic_types(access_db, agent_ip, arp_filter, tproto, ips[0], ips[1])
            except (MySQLdb.Error, MySQLdb.Warning) as e:
                access_db = _mysql.connect(host=db_host, user=db_user, password=db_password, database=db_database)
            
            sys.stdout.flush()

def update_dns_ans_to_db(db, name, resolved_record_type, resolved_record):
    query_phase = "Start Update DNS Answer"
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
        raise e

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
        raise e

def dmz_lookup_monitor(firewall_ip, firewall_port):
    """
    DMZ Direct access DNS lookup monitoring for name based bypass
    """
    umbrella_firewall_uri = "https://{ip}:{port}".format(ip=firewall_ip, port=firewall_port)

    # DMZ original DNS lookup traffic comes with 127.0.0.1:53
    # This is Linux optimization with system-resolved
    try:
        dns_dump_process = subprocess.Popen(['tcpdump', '-vnnttl', '-i', 'lo', '--immediate-mode', 'udp and host 127.0.0.1 and port 53'],
                                              stdout=subprocess.PIPE)
    except BaseException as e:
        print("Not able to initiate tcpdump ", e)
        sys.exit()

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
                            update_dynamic_firewall_dmz_access_control(name, umbrella_firewall_uri, single_ans_with_can_name, record_type, record_content)
                            updated_ans_count = updated_ans_count + 1
                        if ans_count != updated_ans_count:
                            print("Error when insert answers to database expect ", ans_count, "but have ", updated_ans_count)


def nw_dns_monitor(nw_dns_log, db_host, db_user, db_password, db_database, firewall_ip, firewall_port, agent_ip):
    """
    Parse Umbrella NW filtered packets log
    """
    global global_device_mac_pair
    umbrella_firewall_uri = "https://{ip}:{port}".format(ip=firewall_ip, port=firewall_port)

    try:
        dns_db = _mysql.connect(host=db_host, user=db_user, password=db_password, database=db_database)
    except BaseException as e:
        print("DNS Monitor Connecting Database Failed ", e)
        sys.exit()

    try:
        log_file = nw_dns_log["file"]
        dns_pkt_process = subprocess.Popen(['tail', '-f', log_file], stdout=subprocess.PIPE)
    except BaseException as e:
        print("NW DNS Monitoring log not found  ", e)
        sys.exit()

    try:
        endpoints = dict({})
        for dns in nw_dns_log["dns_endpoints"]:
            endpoints[dns] = True
        
        upstreams = dict({})
        for upstream, fwd in nw_dns_log["dns_upstreams"].items():
            if fwd == "fwd":
                upstreams[upstream] = True
            else:
                upstreams[upstream] = False
    except BaseException as e:
        print("NW DNS Monitoring log not have correct DNS configuration  ", e)
        sys.exit()

    # Flush the fwd list
    async_flush_fwd_allow_table("fwdlist", umbrella_firewall_uri)

    while True:
        output = dns_pkt_process.stdout.readline().decode("utf-8").strip()
        try:
            dns_pkt = json.loads(output)
            if dns_pkt["pkt_type"] == "dns_request":
                # DNS Request 
                dst_ip = dns_pkt["ip_header"]["dst"]
                if dst_ip not in endpoints:
                    continue
                src_mac = dns_pkt["mac_header"]["src"]
                src_ip = dns_pkt["ip_header"]["src"]
                for q in dns_pkt["questions"]:
                    try:
                        domain_name = q.split()[0]

                        if src_mac in global_device_ignore:
                            continue
                        else:
                            try:
                                if src_mac in global_device_mac_pair:
                                    update_dns_record_to_db(dns_db, domain_name, src_ip, src_mac, global_device_mac_pair[src_mac])                     
                                else:
                                    update_dns_record_to_db(dns_db, domain_name, src_ip, src_mac)                     
                            except (MySQLdb.Error, MySQLdb.Warning) as e:
                                dns_db = _mysql.connect(host=db_host, user=db_user, password=db_password, database=db_database)                
                    except BaseException as e:
                        """
                        No need to process exception
                        """

            elif dns_pkt["pkt_type"] == "dns_response":
                # DNS Response
                src_ip = dns_pkt["ip_header"]["src"]
                dst_ip = dns_pkt["ip_header"]["dst"]
		single_ans_with_can_name = False
                for record in dns_pkt["rrs"]:
                    recs = record.split()
                    name = recs[0]
                    record_type = recs[3]
                    record_content = recs[4]

                    # DMZ Access Control based on needs
                    # DMZ's outgoing traffic is under configured allow list of domain names
                    if src_ip == dst_ip and src_ip == "127.0.0.1":
                        update_dynamic_firewall_dmz_access_control(name, umbrella_firewall_uri, single_ans_with_can_name, record_type, record_content)
                        continue

                    try:
                         update_dns_ans_to_db(dns_db, name, record_type, record_content)
                    except (MySQLdb.Error, MySQLdb.Warning) as e:
                        dns_db = _mysql.connect(host=db_host, user=db_user, password=db_password, database=db_database)

                    try:
                        if src_ip in upstreams and upstreams[src_ip]:
                            find_if_name_in_forward_name_list(name, umbrella_firewall_uri, single_ans_with_can_name, record_type, record_content)
                    except BaseException as e:
                        """
                        No handling of this exception
                        """
        except BaseException as e:
            print("Not able to process the monitored DNS packet  ", output, e)

def dns_lookup_monitor(db_host, db_user, db_password, db_database, firewall_ip, firewall_port, agent_ip):
    """
    Parse DNS packet direct with tcpdump
    """
    global global_device_mac_pair
    umbrella_firewall_uri = "https://{ip}:{port}".format(ip=firewall_ip, port=firewall_port)

    try:
        dns_db = _mysql.connect(host=db_host, user=db_user, password=db_password, database=db_database)
    except BaseException as e:
        print("DNS Monitor Connecting Database Failed ", e)
        sys.exit()
    
    # Monitoring all outgoring DNS lookup and record all name resolution 
    # with filtered by TCPDUMP from local network, for dnsmasq on main router
    # DNS be forwarded to Linux VM, so all lookup will be recorded here
    try:
        parameter_str = "udp and host {agent_ip} and port 53 and not host 192.168.1.1".format(agent_ip=agent_ip)
        dns_dump_process = subprocess.Popen(['tcpdump', '-vnnttl', '--immediate-mode', parameter_str],
                                              stdout=subprocess.PIPE)
    except BaseException as e:
        print("Not able to tcpdump DNS traffic ", e)
        sys.exit()

    # Flush the fwd list
    async_flush_fwd_allow_table("fwdlist", umbrella_firewall_uri)

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
                    try:
                        if mac_addr in global_device_mac_pair:
                            update_dns_record_to_db(dns_db, domain_name, src_ip, mac_addr, global_device_mac_pair[mac_addr])                     
                        else:
                            update_dns_record_to_db(dns_db, domain_name, src_ip, mac_addr)                     
                    except (MySQLdb.Error, MySQLdb.Warning) as e:
                        dns_db = _mysql.connect(host=db_host, user=db_user, password=db_password, database=db_database)
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
                                
                                try:
                                    update_dns_ans_to_db(dns_db, name, record_type, record_content)
                                except (MySQLdb.Error, MySQLdb.Warning) as e:
                                    dns_db = _mysql.connect(host=db_host, user=db_user, password=db_password, database=db_database)

                                find_if_name_in_forward_name_list(name, umbrella_firewall_uri, single_ans_with_can_name, record_type, record_content)
                                updated_ans_count = updated_ans_count + 1
                            if ans_count != updated_ans_count:
                                print("Error when insert answers to database expect ", ans_count, "but have ", updated_ans_count)

def timeout_process(firewall_ip, firewall_port, firewall_timeout):
    """
    Timeout Process for all timeout firewall entries
    """
    umbrella_firewall_uri = "https://{ip}:{port}".format(ip=firewall_ip, port=firewall_port)
    global global_dmz_configured_target_ip_list
    global global_dmz_configured_target_ip_list_lock

    global global_fwd_configured_target_ip_list
    global global_fwd_configured_target_ip_list_lock

    flush_cnt = 0
    while True:
        time.sleep(60) # per minute check timeout
        dmz_clean_ip = []
        global_dmz_configured_target_ip_list_lock.acquire()
        for ip in global_dmz_configured_target_ip_list:
            if ip in global_dmz_configured_target_ip_list:
                if time.time() - global_dmz_configured_target_ip_list[ip] > firewall_timeout:
                    dmz_clean_ip.append(ip)
                    del global_dmz_configured_target_ip_list[ip]
        global_dmz_configured_target_ip_list_lock.release()

        for ip in dmz_clean_ip:
            async_del_dmz_allow_target("async_del_dmz_allow_target", umbrella_firewall_uri, ip)

        flush_cnt = flush_cnt + 1
        if flush_cnt >= 60 * 24:  #Every Day flush fwdlist table
            global_fwd_configured_target_ip_list_lock.acquire()
            global_fwd_configured_target_ip_list.clear()
            global_fwd_configured_target_ip_list_lock.release()
            async_flush_fwd_allow_table("fwdlist", umbrella_firewall_uri)
            flush_cnt = 0
        else:
            fwd_clean_ip = []
            global_fwd_configured_target_ip_list_lock.acquire()
            for ip in global_fwd_configured_target_ip_list:
                if ip in global_fwd_configured_target_ip_list:
                    if time.time() - global_fwd_configured_target_ip_list[ip] > firewall_timeout:
                        fwd_clean_ip.append(ip)
                        del global_fwd_configured_target_ip_list[ip]
            global_fwd_configured_target_ip_list_lock.release()        

            for ip in fwd_clean_ip:
                async_del_fwd_allow_target("async_del_fwd_allow_target", umbrella_firewall_uri, ip)


# automatic configure direct forward IP address to ipfw firewall
def async_add_fwd_allow_target(name, uri, fwd_ip):
    """
    Async configure Dynamic firewall on FreeBSD ipfw fwd_list table Make sure you have 192.168.10.1 as the UmbrellaFirewall
    """
    try:
        cmdline = "curl -k -X POST {uri}/add_fwd_target_ip?ip_addr={ip}".format(uri=uri, ip=fwd_ip)
        status = os.system(cmdline)
    except BaseException as e:
        print(e)

def async_del_fwd_allow_target(name, uri, fwd_ip):
    """
    Async configure Dynamic firewall on FreeBSD ipfw fwd_list table
    """
    try:
        cmdline = "curl -k -X POST {uri}/del_fwd_target_ip?ip_addr={ip}".format(uri=uri, ip=fwd_ip)
        status = os.system(cmdline)
    except BaseException as e:
        print(e)

def async_flush_fwd_allow_table(name, uri):
    """
    Async flush Dynamic firewall on FreeBSD ipfw fwd_list table
    """
    try:
        cmdline = "curl -k -X POST {uri}/clr_fwd_target_ip?table=fwdlist".format(uri=uri)
        status = os.system(cmdline)
    except BaseException as e:
        print(e)

# Async add dmz firewall
def async_add_dmz_allow_target(name, uri, fwd_ip):
    """
    Async configure Dynamic firewall on FreeBSD ipfw fwd_list table
    """
    try:
        cmdline = "curl -k -X POST {uri}/add_dmz_target_ip?ip_addr={ip}".format(uri=uri, ip=fwd_ip)
        status = os.system(cmdline)
    except BaseException as e:
        print(e)

# Async del dmz firewall
def async_del_dmz_allow_target(name, uri, fwd_ip):
    """
    Async configure Dynamic firewall on FreeBSD ipfw fwd_list table
    """
    try:
        cmdline = "curl -k -X POST {uri}/del_dmz_target_ip?ip_addr={ip}".format(uri=uri, ip=fwd_ip)
        status = os.system(cmdline)
    except BaseException as e:
        print(e)

def find_if_name_in_forward_name_list(name, uri, same_record, record_type, record_content):
    global global_fwd_list
    # Only activate on A record for IPv4 only network 
    if record_type == "CNAME":
        for name_pattern in global_fwd_list:
            name_match = name_pattern.match(name.strip())
            if name_match:
                same_record = True
    if record_type == "A":
        if same_record:
            # CNAME used for load balance traffic may have different resolved name
            # then with IP
            update_fwd_list = False
            global_fwd_configured_target_ip_list_lock.acquire()
            if record_content not in global_fwd_configured_target_ip_list:
                update_fwd_list = True
            global_fwd_configured_target_ip_list[record_content] = time.time()
            global_fwd_configured_target_ip_list_lock.release()

            if update_fwd_list:
                async_add_fwd_allow_target(name, uri, record_content)
        else:
            for name_pattern in global_fwd_list:
                name_match = name_pattern.match(name.strip())
                if name_match:
                    update_fwd_list = False
                    global_fwd_configured_target_ip_list_lock.acquire()
                    if record_content not in global_fwd_configured_target_ip_list:
                        update_fwd_list = True
                    global_fwd_configured_target_ip_list[record_content] = time.time()
                    global_fwd_configured_target_ip_list_lock.release()

                    if update_fwd_list:
                        async_add_fwd_allow_target(name, uri, record_content)

def update_dynamic_firewall_dmz_access_control(name, uri, same_record, record_type, record_content):
    global global_dmz_target_list
    global global_dmz_configured_target_ip_list
    global global_dmz_configured_target_ip_list_lock
    if record_type == "CNAME":
        for name_pattern in global_dmz_target_list:
            name_match = name_pattern.match(name.strip())
            if name_match:
                same_record = True
    if record_type == "A":
        if same_record:
            update_dmz_list = False
            global_dmz_configured_target_ip_list_lock.acquire()
            if record_content not in global_dmz_configured_target_ip_list:
                update_dmz_list = True
            global_dmz_configured_target_ip_list[record_content] = time.time()
            global_dmz_configured_target_ip_list_lock.release()
            
            if update_dmz_list:
                async_add_dmz_allow_target(name, uri, record_content)
        else:
            for name_pattern in global_dmz_target_list:
                name_match = name_pattern.match(name.strip())
                if name_match:
                    update_dmz_list = False
                    global_dmz_configured_target_ip_list_lock.acquire()
                    if record_content not in global_dmz_configured_target_ip_list:
                        update_dmz_list = True
                    global_dmz_configured_target_ip_list[record_content] = time.time()
                    global_dmz_configured_target_ip_list_lock.release()

                    if update_dmz_list:
                        async_add_dmz_allow_target(name, uri, record_content)

def load_device_list(device_list):
    global global_device_mac_pair
    global global_device_ignore
    device_list_filter = re.compile("([\w\:]+)[ \t]+\"([\w\W]+)\"\s*(\w+)*", re.IGNORECASE)
    if device_list != "":
        try:
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
        except BaseException as e:
            print("Load Device List failed  ", device_list)
            sys.exit()

def load_forward_name_list(fwd_list):
    global global_fwd_list
    if fwd_list != "":
        try:
            f = open(fwd_list, "r")
            lines = f.readlines()
            for line in lines:
                if line.startswith('#') == False:
                    name_filter = re.compile(line.strip(), re.IGNORECASE)
                    global_fwd_list.append(name_filter)
        except BaseException as e:
            print("Load forward list failed  ", fwd_list)
            sys.exit()

# Below function writteing by Copilot
# it can be further optimize to find global variable name
# match in previous defined list, (it is dangerous to define
# global variable by Copilot, if similiar name of variable existed
# it will make debug very hard) 
def load_dmz_allow_name_list(dmz_list):
    global global_dmz_target_list
    if dmz_list != "":
        try:
            f = open(dmz_list, "r")
            lines = f.readlines()
            for line in lines:
                if line.startswith('#') == False:
                    name_filter = re.compile(line.strip(), re.IGNORECASE)
                    global_dmz_target_list.append(name_filter)
        except BaseException as e:
            print("Load DMZ allowed access list failed  ", dmz_list)
            sys.exit()


def build_config(config, db):
    thread_config = {}
    try:
        if db in config["databases"]:
            thread_config["db_host"] = config["databases"][db]["host"]
            thread_config["db_user"] = config["databases"][db]["user"]
            thread_config["db_password"] = config["databases"][db]["password"]
            thread_config["db_database"] = config["databases"][db]["database"]
            thread_config["firewall_ip"] = config["umbrella_firewall_endpoint"]["ip"]
            thread_config["firewall_port"] = config["umbrella_firewall_endpoint"]["port"]
            thread_config["agent_ip"] = config["umbrella_agent_ip"]
    except BaseException as e:
        return None

    return thread_config

if __name__ == '__main__':
    """
    Dynamic Firewall Agent
    """
    known_device_list = ""
    forward_name_list = ""
    dmz_name_list = ""

    config_file = "/etc/umbrella/agent/um_agent.json"

    if sys.argv[1]:
        config_file = sys.argv[1]

    try:
        file = open(config_file, 'r')
        config = json.load(file)
    except BaseException as e:
        print("Not able to load Configuration file ", config_file)
        sys.exit()

    if "known_devices_list" in config:
        known_device_list = config["known_devices_list"]

    if known_device_list != "":
        load_device_list(known_device_list)

    if "dmz_allow_access_list" in config:
        dmz_name_list = config["dmz_allow_access_list"]

    if dmz_name_list != "":
        load_dmz_allow_name_list(dmz_name_list)

    if "gfw_bypass_list" in config:
        forward_name_list = config["gfw_bypass_list"]

    if forward_name_list != "":
        load_forward_name_list(forward_name_list)

    if "nw_dns_log" in config:
        nw_dns_th_config = build_config(config, "dns_mon")
        if nw_dns_th_config:
            nw_dns_th_config["nw_dns_log"] = config["nw_dns_log"]
            nw_dns_mon_th = threading.Thread(name="nw dns mon", target=nw_dns_monitor, kwargs=nw_dns_th_config)
            nw_dns_mon_th.start()
        else:
            print("Internal network DNS monitor not with correct configuration")
            sys.exit()
    else:
        dns_thread_config = build_config(config, "dns_mon")
        if dns_thread_config:
            dns_mon_th = threading.Thread(name="dns mon", target=dns_lookup_monitor, kwargs=dns_thread_config)
            dns_mon_th.start()
        else:
            print("Internal network DNS monitor not with correct configuration")
            sys.exit()

        dmz_agent_config = {}
        if "umbrella_firewall_endpoint" in config:
            dmz_agent_config["firewall_ip"] = config["umbrella_firewall_endpoint"]["ip"]
            dmz_agent_config["firewall_port"] = config["umbrella_firewall_endpoint"]["port"]
        else:
            dmz_agent_config = None

        if dmz_agent_config:
            dmz_mon_th = threading.Thread(name='dmz mon', target=dmz_lookup_monitor, kwargs=dmz_agent_config)
            dmz_mon_th.start()
        else:
            print("Not firewall on main router configuration existed")
            sys.exit()

    nf_thread_config = build_config(config, "router_mon")
    if nf_thread_config:
        nf_con_mon_th = threading.Thread(name='nf con_mon', target=nf_connection_monitor, kwargs=nf_thread_config)
        nf_con_mon_th.start()
    else:
        print("Internal network router monitor not with correct configuration")
        sys.exit()

    timeout_config = {}
    timeout_config["firewall_timeout"] = global_default_timeout
    if "firewall_timeout" in config and "umbrella_firewall_endpoint" in config:
        timeout_config["firewall_ip"] = config["umbrella_firewall_endpoint"]["ip"]
        timeout_config["firewall_port"] = config["umbrella_firewall_endpoint"]["port"]
        if config["firewall_timeout"] >= 5 * 60:
            timeout_config["firewall_timeout"] = config["firewall_timeout"]

    timeout_process_th = threading.Thread(name='timeout process', target=timeout_process, kwargs=timeout_config)
    timeout_process_th.start()

    while True:
        time.sleep(60)
