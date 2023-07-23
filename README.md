# UmbrellaAgent

This works with UmbrellaFirewall    
From Agent to filter the domain name by tcpdump to send the IP to open the access on FreeBSD Router   
tcpdump is a bad idea for this usage, ebpf based DNS filter take sometime    


# SQLSchema    
Mysql Database Schema used for recording the domain name accessed through the Umbrella Controlled internal network   


## Communicate with UmbrellaFirewall to update out access allow list (Firewall Open)  



## Update SQL database to record all DNS lookup initiated from Internal network (Audit)   

record of the DNS name with CNAME and its associated IP   
```
dns_records:
| ? | ?.taobao.com.                                    | CNAME       | ?.queniuak.com.                                                                                 |
| ? | ?.queniuak.com.                                  | A           | ?                                                                                               |
...
| ? | ?.googlevideo.com.                               | CNAME       | ?.googlevideo.com.                                                                              |

```

record of the access initiated from 
```
domain_names:
| ?.queniuak.com.                                                                                                     | ?-?-? ?:?:? | 42859 |
| ?.googlevideo.com.                                                                                                  | ?-?-? ?:?:? | 42860 |
| ?.googlevideo.com.                                                                                                  | ?-?-? ?:?:? | 42861 |


access_recods:
| ? | ? |      1 | 2023-?-? ?:?:? |           42859 | 192.168.10.? |

From domain_names it has all the domain names lookup by internal controlled network devices
and with its ID here "42859", it has record of from which internal IP, devices MAC, ... to access this domain name at which time for how many times

```


## TODO  
 1. Configurable disable "Audit" functions to not record network access  
 2. All database information configurable   