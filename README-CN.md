# UmbrellaAgent    

[English](README.md) | 简体中文    

Umbrealla Agent需要和Umbreall Firewall一起工作， Umbrealla Agent 通过分析内网中的DNS流量来动态更改FreeBSD路由器
中的防火墙规则。    

Umbrealla Agent可以通过使用tcpdump来抓网卡的数据报文，然后分析其中的DNS报文来提供防火墙规则更新。 配置Umbrealla NightWatch
Umbrella Agent可以实现不使用tcpdump来进行流量分析和基于NightWatch的eBPF XDP/TC 数据流分析来过滤DNS数据报文。     

# SQLSchema    
Umbrealla Agent 使用SQL database （MariaDB） 来更新内网中所有设备的域名访问记录
并更新域名对应的解析IP地址到数据库

## 域名访问记录     
域名解析记录   
```
数据库表 dns_records:
| ? | ?.taobao.com.                                    | CNAME       | ?.queniuak.com.                                                                                 |
| ? | ?.queniuak.com.                                  | A           | ?                                                                                               |
...
| ? | ?.googlevideo.com.                               | CNAME       | ?.googlevideo.com.                                                                              |

```

域名访问记录   
```
数据库表 domain_names:
| ?.queniuak.com.                                                                                                     | ?-?-? ?:?:? | 42859 |
| ?.googlevideo.com.                                                                                                  | ?-?-? ?:?:? | 42860 |
| ?.googlevideo.com.                                                                                                  | ?-?-? ?:?:? | 42861 |


数据库表 access_recods:
| ? | ? |      1 | 2023-?-? ?:?:? |           42859 | 192.168.10.? |

根据数据库表 domain_names 中的条目每个域名对应的 ID, 例如 "42859", 从 表 access_records 中可以 找到对应的访问此域名的IP, 设备MAC地址等信息。    

```

# Umbrealla Agent 配置文件    
```
{
    "umbrella_firewall_endpoint": {                                      // Umbrealla Firewall的服务端点配置   
        "ip": "",                     
        "port": 6466
    },
    "umbrella_agent_ip": "",                                             // Umbrealla Agent的工作DMZ IP地址
    "known_devices_list": "/etc/umbrella/conf/known_device.list",        // 文件配置已知设备列表     
    "gfw_bypass_list": "/etc/umbrella/conf/fwd_name.list",               // 
    "dmz_allow_access_list": "/etc/umbrella/conf/dmz_allow_name.list",   // DMZ主机允许访问的域名列表     
    "firewall_timeout": 3600,                                            // 防火墙清理规则的timeout
    "databases": {                                                       // 数据记录数据库配置
        "dns_mon": {                                                     // DNS访问记录数据库    
            "host": "",
            "user": "",
            "password": "",
            "database": ""
        },
        "router_mon": {                                                  // 路由访问数据库     
            "host": "",
            "user": "",
            "password": "",
            "database": ""
        }
    },
    "nw_dns_log": {                                                      // NightWatch DNS 配置    
        "file": "/var/log/nw_dns_pkt.log",                               // NightWatch DNS filter抓包文件    
        "dns_endpoints": ["192.168.*.*"],                                // DMZ提供的对内网DNS服务器IP列表    
        "dns_upstreams": {                                               // DNS 上游服务器配置    
            "192.168.1.1": "",                                           // 内网DNS解析服务器    
            "192.168.1.*": "fwd"                                         // 外网DNS解析服务器    
        }
    }
}

```
