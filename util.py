def configure_net(net_list, host_list, router_list):
    net_list[0].child_hosts=[0,1]
    net_list[0].child_routers=[(0,1)] # R0 port 1
    net_list[0].net_ip = '192.168.0.0'
    host_list[0].ip = '192.168.0.2'
    host_list[1].ip = '192.168.0.7'
    router_list[0].ips[1] = '192.168.0.1'

    net_list[1].child_hosts=[2]
    net_list[1].child_routers=[(0,0)]
    net_list[1].net_ip = '192.168.1.0'
    host_list[2].ip = '192.168.1.3'
    router_list[0].ips[0] = '192.168.1.1'

    net_list[2].child_hosts=[3]
    net_list[2].child_routers=[(0,2),(1,0)]
    net_list[2].net_ip = '192.168.2.0'
    host_list[3].ip = '192.168.2.3'
    router_list[0].ips[2] = '192.168.2.1'
    router_list[1].ips[0] = '192.168.2.2'

    net_list[3].child_hosts=[4]
    net_list[3].child_routers=[(1,1)]
    net_list[3].net_ip = '192.168.3.0'
    host_list[4].ip = '192.168.3.2'
    router_list[1].ips[1] = '192.168.3.1'

    net_list[4].child_hosts=[5]
    net_list[4].child_routers=[(1,2)]
    net_list[4].net_ip = '192.168.4.0'
    host_list[5].ip = '192.168.4.2'
    router_list[1].ips[2] = '192.168.4.4'

    #### router table && mac cache 
    host_list[0].router_table['default']='192.168.0.1'
    host_list[1].router_table['default']='192.168.0.1'
    host_list[2].router_table['default']='192.168.1.1'
    host_list[3].router_table['default']='192.168.2.1'
    # host_list[0].mac_cache['192.168.0.1'] = router_list[0].macs[1]
    # host_list[0].mac_cache['192.168.0.7'] = host_list[1].mac
    # host_list[1].mac_cache['192.168.0.1'] = router_list[0].macs[1]
    # host_list[1].mac_cache['192.168.0.2'] = host_list[0].mac
    # host_list[2].mac_cache['192.168.1.1'] = router_list[0].macs[0]
    # host_list[3].mac_cache['192.168.2.1'] = router_list[0].macs[2]
    host_list[4].router_table['default']='192.168.3.1'
    host_list[5].router_table['default']='192.168.4.4'
    # host_list[4].mac_cache['192.168.3.1'] = router_list[1].macs[1]
    # host_list[5].mac_cache['192.168.4.4'] = router_list[1].macs[2]


    router_list[0].router_table['default']='192.168.2.2',2
    # router_list[0].mac_cache['192.168.2.2'] = router_list[1].macs[0]
    # router_list[0].mac_cache['192.168.0.2'] = host_list[0].mac
    # router_list[0].mac_cache['192.168.0.7'] = host_list[1].mac
    # router_list[0].mac_cache['192.168.1.3'] = host_list[2].mac
    # router_list[0].mac_cache['192.168.2.3'] = host_list[3].mac

    router_list[1].router_table['default']='192.168.2.1',0
    # router_list[1].mac_cache['192.168.2.1'] = router_list[0].macs[2]
    # router_list[1].mac_cache['192.168.2.3'] = host_list[3].mac
    # router_list[1].mac_cache['192.168.3.2'] = host_list[4].mac
    # router_list[1].mac_cache['192.168.4.2'] = host_list[5].mac

def mac_to_str(mac):
    return '.'.join([hex(e)[2:] for e in int.to_bytes(mac,6,'big')])

def macstr_to_int(mac_str):
    L = mac_str.split('.')
    s = 0
    a = 1
    for e in L[-1::-1]: #倒序
        s += a*int('0x'+e,16)
        a *= 255
    return int(s)

def put_bottom(cv,tag_id):
    tags = cv.find_below(tag_id)
    while len(tags)!=0:
        cv.tag_lower(tag_id,tags)
        tags = cv.find_below(tag_id)