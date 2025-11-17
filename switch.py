#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import binascii
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
MAC_table = {}

STP_COST = 10 
STP_MAX_AGE = 20 * 256     
STP_HELLO_TIME = 2 * 256   
STP_FORWARD_DELAY = 15 * 256 

root_bridge_ID = 0          
root_path_cost = 0          
root_port = -1              
ppdu_seq_num = 0            

class SwitchConfig:
    BID: int  # Bridge ID
    vlan_ports: dict  # port -> vlan_id
    trunk_ports: list  # List of trunk ports
    port_states: dict  # port -> STP state
    def __init__(self, config_file):
        self.vlan_ports = {}
        self.trunk_ports = []
        # Load configuration from file
        with open(config_file, "r") as f:
            port = 0
            self.BID = int(f.readline().strip())
            for line in f:
                (aux, vlan) = line.strip().split(" ")
                if (vlan == "T"):
                    self.trunk_ports.append(port)
                else:
                    self.vlan_ports[port] = int(vlan)
                port += 1




def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    vlan_tci = -1
    # Check for VLAN tag (0x8200 in network byte order is b'\x82\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id, vlan_tci

def create_vlan_tag(ext_id, vlan_id):
    # Use EtherType = 8200h for our custom 802.1Q-like protocol.
    # PCP and DEI bits are used to extend the original VID.
    #
    # The ext_id should be the sum of all nibbles in the MAC address of the
    # host attached to the _access_ port. Ignore the overflow in the 4-bit
    # accumulator.
    #
    # NOTE: Include these 4 extensions bits only in the check for unicast
    #       frames. For multicasts, assume that you're dealing with 802.1Q.
    return struct.pack('!H', 0x8200) + \
           struct.pack('!H', ((ext_id & 0xF) << 12) | (vlan_id & 0x0FFF))

def function_on_different_thread():
    while True:
        time.sleep(1)

def check_MAC_table(dest_mac, src_mac, interface):
    MAC_table[src_mac] = interface
    if int(dest_mac.split(":")[0], 16) & 1 == 0:  # unicast
        if dest_mac in MAC_table:
            return MAC_table[dest_mac]
    return -1

def is_in_same_vlan(interface1, interface2, switch):  

    if interface1 in switch.trunk_ports or interface2 in switch.trunk_ports:
        return True

    if switch.vlan_ports[interface1] == switch.vlan_ports[interface2]:
        if interface1 != interface2:
            return True
    return False

def build_vlan_ext(mac):
    return (sum(int(x, 16)//16 + int(x, 16) % 16 for x in mac.split(':')) & 0xf)


def initialize_bridge(switch):
    global root_bridge_ID, root_path_cost, root_port

    root_bridge_ID = switch.config_id
    root_path_cost = 0
    root_port = -1 

    for port, (name, vlan_type, _) in switch.vlans.items():
        if vlan_type == "T":
            switch.vlans[port] = (name, vlan_type, "DESIGNATED")
        else:
            switch.vlans[port] = (name, vlan_type, "FORWARDING")

def send_ppdu(port, switch, src_mac):
    
    dest_mac = binascii.unhexlify("01:80:c2:00:00:00".replace(':', ''))
    llc_len = 44
    llc_header = struct.pack("!HBBB", llc_len, 0x42, 0x42, 0x03)
    
    protocol_id = 0x0002
    protocol_version = 0
    type = 0x80
    header = struct.pack("!HBB I", protocol_id, protocol_version, type, ppdu_seq_num)
    ppdu_seq_num = (ppdu_seq_num + 1) % 100 

    port_id = 0x8000 | port 
    flags = 0
    message_age = 0 
    
    data = struct.pack("!B Q I Q H H H H H",  # 1+8+4+8+2+2+2+2+2 = 31 bytes
                            flags,
                            root_bridge_ID,
                            root_path_cost,
                            switch.BID,
                            port_id,
                            message_age,
                            STP_MAX_AGE,
                            STP_HELLO_TIME,
                            STP_FORWARD_DELAY)

    frame = dest_mac + src_mac + llc_header + header + data
    send_to_link(port, len(frame), frame)


def receive_ppdu(switch, data, port):
    global root_bridge_ID, root_path_cost, root_port
    
    # 1. Validate frame
    if len(data) < 56:  # ✅ Minimum PPDU frame size
        return
    
    # Verify LLC Control byte (byte 16)
    if data[16] != 0x03:
        return
    
    # Verify PPDU Type (byte 20)
    if data[20] != 0x80:
        return
    
    # 2. Extract PPDU_CONFIG (starts at byte 25)
    # Skip flags (byte 25), extract main fields
    ppdu_flags = data[25]
    ppdu_root_bridge, ppdu_root_path, ppdu_sender_id = struct.unpack("!QIQ", data[26:46])
    ppdu_port_id, ppdu_msg_age, ppdu_max_age = struct.unpack("!HHH", data[46:52])
    
    # 3. Calculate cost via this port
    cost_via_port = ppdu_root_path + STP_COST
    
    # 4. Determine if this PPDU is better than current root
    is_ppdu_better = (
        ppdu_root_bridge < root_bridge_ID or
        (ppdu_root_bridge == root_bridge_ID and cost_via_port < root_path_cost) or
        (ppdu_root_bridge == root_bridge_ID and cost_via_port == root_path_cost and 
         ppdu_sender_id < switch.BID)
    )
    
    # 5. Update root information if better PPDU received
    if is_ppdu_better:
        # If we had a different root port, change its state
        if root_port != -1 and root_port != port and root_port in switch.trunk_ports:
            # Old root port becomes designated
            pass  # Update state here
        
        # Update root info
        root_bridge_ID = ppdu_root_bridge
        root_path_cost = cost_via_port
        root_port = port
        
        # Mark this port as ROOT port
        # (You need a data structure to store port states)
        
    else:
        # This is not a better path to root
        if port == root_port:
            # Update cost if needed
            if cost_via_port < root_path_cost:
                root_path_cost = cost_via_port
            return
        
        # Determine if this port should be DESIGNATED or BLOCKED
        is_local_designated = (
            cost_via_port > root_path_cost or
            (cost_via_port == root_path_cost and switch.BID < ppdu_sender_id)
        )
        
        if is_local_designated:
            # Set port to DESIGNATED state
            pass
        else:
            # Set port to BLOCKED state
            pass
    
    # 6. If we are root, all our ports are DESIGNATED
    if switch.BID == root_bridge_ID:
        # Set all trunk ports to DESIGNATED
        pass

def send_hello(port, src_mac):
    dest_mac = binascii.unhexlify("ff:ff:ff:ff:ff:ff".replace(':', ''))
    ethertype = struct.pack("!H", 0x0800)
    payload = b'Hello!:p'
    frame = dest_mac + src_mac + ethertype + payload
    send_to_link(port, len(frame), frame)

def send_hello_every_sec(switch, src_mac):
    """Thread-ul care trimite HPDU și ppdu periodic (la fiecare 1 sec)."""
    while True:
        for i in switch.trunk_ports:
            send_hello(i, src_mac)
        for i in switch.vlan_ports.keys():
            send_hello(i, src_mac)
                # 2. Trimite PPDU DOAR pe porturile trunk în stare DESIGNATED
        for port in switch.trunk_ports:
            if switch.port_states[port] == "DESIGNATED":
                send_ppdu(port, switch)
        time.sleep(1)
    


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    switch = SwitchConfig("configs/switch" + switch_id + ".cfg")
    print("-----------------------------")
    print("Switch BID:", switch.BID)
    print("Switch VLAN ports configuration:")
    print(switch.vlan_ports)
    print("Switch Trunk ports:")
    print(switch.trunk_ports)
    print("-----------------------------")


    # Example of running a function on a separate thread.
    my_mac = ':'.join(f'{b:02x}' for b in get_switch_mac())
    t = threading.Thread(target=send_hello_every_sec, args=(switch, my_mac, ))
    t.start()

    if ':'.join(f'{b:02x}' for b in get_switch_mac()) == "01:80:c2:00:00:00":
        receive_ppdu(switch, data, interface)

    # Printing interface names
    for i in interfaces:
        print(i, get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id, vlan_tci = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(5, 10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)



        # TODO: Implement forwarding with learning
        out_interface = check_MAC_table(dest_mac, src_mac, interface)

        if (out_interface == -1):
            # Flood-> caz diferit in fct de vlan uri
            if vlan_id == -1 and interface in switch.trunk_ports:
                print("IFK")
                # for i in interfaces:
                #     if i != interface:
                #         send_to_link(i, length, data)            
            elif vlan_id == -1 and interface not in switch.trunk_ports:
                for i in switch.vlan_ports.keys():
                    if is_in_same_vlan(i, interface, switch) and i != interface:
                        send_to_link(i, length, data)
                for i in switch.trunk_ports:
                    # Build a VLAN tag based on the src MAC
                    if i != interface:
                        ext_id = build_vlan_ext(src_mac)
                        vlan_id = switch.vlan_ports[interface]
                        tagged_frame = data[0:12] + create_vlan_tag(ext_id, vlan_id) + data[12:]
                        send_to_link(i, length + 4, tagged_frame)
            else:
                for i in switch.vlan_ports.keys():
                    if switch.vlan_ports[i] == vlan_id and i != interface:
                        untagged_frame = data[0:12] + data[16:]
                        send_to_link(i, len(untagged_frame), untagged_frame)
                for i in switch.trunk_ports:
                    if i != interface:
                        send_to_link(i, length, data)
        else:
            if is_in_same_vlan(out_interface, interface, switch):
                if out_interface != interface:
                    #trunk-access
                    if vlan_id != -1 and out_interface in switch.vlan_ports:
                        if build_vlan_ext(dest_mac) == ((vlan_tci >> 12) & 0x0F):
                            untagged_frame = data[0:12] + data[16:]
                            send_to_link(out_interface, len(untagged_frame), untagged_frame)
                    # access-trunk
                    elif vlan_id == -1 and out_interface in switch.trunk_ports:
                        ext_id = build_vlan_ext(src_mac)
                        vlan_id_to_use = switch.vlan_ports[interface]
                        tagged_frame = data[0:12] + create_vlan_tag(ext_id, vlan_id_to_use) + data[12:]
                        send_to_link(out_interface, len(tagged_frame), tagged_frame)
                    # trunk-trunk : trimite ca atare
                    else:
                        send_to_link(out_interface, length, data)

        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
