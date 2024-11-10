#!/usr/bin/python3

# SPDX-License-Identifier: EUPL-1.2
# Copyright Mitran Andrei-Gabriel + RL team 2023

import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# Flag that signals the BPDU thread to stop
stop_flag = threading.Event()

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec(stop_flag, own_bridge_id, root_bridge_id, interfaces, interface_vlan):
    # As long as switch is root, sends BDPU every second
    while not stop_flag.is_set():
        time.sleep(1)

        # Check if switch is root
        if own_bridge_id == root_bridge_id:
            # Send BDPU on all trunk ports
            root_bridge_id = own_bridge_id
            sender_bridge_id = own_bridge_id
            sender_path_cost = 0
            for interface in interfaces:
                if interface_vlan[get_interface_name(interface)] == sys.maxsize:
                    send_to_link(interface, create_bdpu(root_bridge_id, sender_bridge_id, sender_path_cost), 16)

# Creates a BDPU
def create_bdpu(root_bridge_id, sender_bridge_id, sender_path_cost):
    return struct.pack('!I', 25) + struct.pack('!I', root_bridge_id) + struct.pack('!I', sender_bridge_id) + struct.pack('!I', sender_path_cost)

# Parses a BDPU
def parse_bdpu(data):
    root_bridge_id = int.from_bytes(data[4:8], byteorder='big')
    sender_bridge_id = int.from_bytes(data[8:12], byteorder='big')
    sender_path_cost = int.from_bytes(data[12:16], byteorder='big')
    return root_bridge_id, sender_bridge_id, sender_path_cost

# Updates the port states, after receiving a BDPU
def update_port_states(port_states, own_bridge_id, root_bridge_id, root_path_cost, root_port, interface_vlan, bpdu_data, bpdu_interface, interfaces):
    # Retrieves the relevant information from the BDPU
    bpdu_root_bridge_id, bpdu_sender_bridge_id, bpdu_sender_path_cost = parse_bdpu(bpdu_data)

    # Checks if the sender has a lower bridge ID than the current root
    if bpdu_root_bridge_id < root_bridge_id:
        # If the sender is the root, then the switch is no longer the root
        currently_root_bridge = False
        if root_bridge_id == own_bridge_id:
            currently_root_bridge = True
        
        # If we were the root, then we need to change the port states to BLOCKING, except for the port that received the BDPU
        if currently_root_bridge:
            for interface in interfaces:
                if interface != bpdu_interface and interface_vlan[get_interface_name(interface)] == sys.maxsize:
                    port_states[interface] = "BLOCKING"

        # Update the root bridge information
        root_bridge_id = bpdu_root_bridge_id
        root_path_cost = bpdu_sender_path_cost + 10
        root_port = bpdu_interface

        # Makes sure that the port that received the BDPU is in the LISTENING state
        if port_states[root_port] == "BLOCKING":
            port_states[root_port] = "LISTENING"
        
        # Sends a BDPU on all trunk ports, except for the port that received the BDPU
        for interface in interfaces:
            if interface != bpdu_interface and interface_vlan[get_interface_name(interface)] == sys.maxsize:
                sender_bridge_id = own_bridge_id
                sender_path_cost = root_path_cost
                send_to_link(interface, create_bdpu(root_bridge_id, sender_bridge_id, sender_path_cost), 16)
    
    # Sender is the root
    elif bpdu_root_bridge_id == root_bridge_id:
        # If the data was received on the root port and we have a lower cost, then we need to update the root path cost
        if bpdu_interface == root_port and bpdu_sender_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_sender_path_cost + 10
    
        # If the data was not received on the root port
        elif bpdu_interface != root_port:
            # If the sender has a greater path cost, this port needs to be "LISTENING"
            if bpdu_sender_path_cost > root_path_cost:
                if port_states[bpdu_interface] == "BLOCKING":
                    port_states[bpdu_interface] = "LISTENING"
    
    # Own packet was sent back to us, so we need to change the port state to "BLOCKING"
    elif bpdu_sender_bridge_id == own_bridge_id:
        port_states[bpdu_interface] = "BLOCKING"
    
    # Switch is the root, all trunk ports need to be in the "LISTENING" state
    if own_bridge_id == root_bridge_id:
        for interface in interfaces:
            if interface_vlan[get_interface_name(interface)] == sys.maxsize:
                port_states[interface] = "LISTENING"
    
    return port_states, root_bridge_id, root_path_cost, root_port

# Checks if the MAC address is not broadcast
def is_unicast(mac):
    return mac != "ff:ff:ff:ff:ff:ff"

def parse_config(switch_id):
    # Creates the file name
    file_name = f"configs/switch{switch_id}.cfg"

    # Initializes an empty dictionary to store the interface names and VLANs
    interface_vlan = {}

    # Opens the file and reads its contents
    with open(file_name, 'r') as file:
        lines = file.readlines()

        # The first line is the switch prio
        switch_prio = int(lines[0].strip())
        
        # Iterates over the rest of the lines and parses the information
        for line in lines[1:]:
            interface_name, vlan = line.split()

            # Trunk is marked with sys.maxsize
            if vlan != "T":
                interface_vlan[interface_name] = int(vlan)
            else:
                interface_vlan[interface_name] = sys.maxsize

    return switch_prio, interface_vlan

# Initializes the port states, root bridge ID, root path cost and root port
def initialize(interfaces, switch_prio, interface_vlan):
    port_states = {}

    for interface in interfaces:
        if interface_vlan[get_interface_name(interface)] == sys.maxsize:
            port_states[interface] = "BLOCKING"
        else:
            port_states[interface] = "LISTENING"

    own_bridge_id = switch_prio
    root_bridge_id = own_bridge_id
    root_path_cost = 0
    root_port = None

    if own_bridge_id == root_bridge_id:
        for interface in interfaces:
                port_states[interface] = "LISTENING"

    return port_states, own_bridge_id, root_bridge_id, root_path_cost, root_port

def main():
    # Init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # Init for VLANs
    switch_prio, interface_vlan = parse_config(switch_id)

    # Init for STP
    port_states, own_bridge_id, root_bridge_id, root_path_cost, root_port = initialize(interfaces, switch_prio, interface_vlan)

    # Creates and starts a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(stop_flag, own_bridge_id, root_bridge_id, interfaces, interface_vlan,))
    t.start()

    # Initialize MAC table
    MAC_table = {}

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        # Checks if the packet is a BDPU
        if int.from_bytes(data[0:4], byteorder='big') == 25:
            # Updates the port states
            port_states, root_bridge_id, root_path_cost, root_port = update_port_states(port_states, own_bridge_id, root_bridge_id, root_path_cost, root_port, interface_vlan, data, interface, interfaces)

            # Checks if the switch is no longer the root, and if so, stops sending BDPU
            if own_bridge_id != root_bridge_id:
                stop_flag.set()
                t.join()
        else:
            # Checks if the port is in the BLOCKING state, as the packet is not a BDPU
            if (port_states[interface] == "BLOCKING"):
                continue

            # Gets the MAC addresses and the VLAN ID
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

            # Human readable MAC addresses
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            # Updates the MAC table
            MAC_table[src_mac] = interface

            # Tags the packet if it is untagged, must have come from an access port
            if vlan_id == -1:
                vlan_id = interface_vlan[get_interface_name(interface)]
                data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                length += 4

            # Checks if the destination MAC address is in the MAC table
            if is_unicast(dest_mac) and dest_mac in MAC_table:
                # Checks if the destination MAC address is on the same VLAN, meaning the port is access
                if interface_vlan[get_interface_name(MAC_table[dest_mac])] == vlan_id:
                    # Untags the packet and sends it
                    data = data[0:12] + data[16:]
                    length -= 4
                    send_to_link(MAC_table[dest_mac], data, length)
                # Checks if the port to be sent on is a trunk port and is in the LISTENING state
                elif interface_vlan[get_interface_name(MAC_table[dest_mac])] == sys.maxsize and port_states[MAC_table[dest_mac]] == "LISTENING":
                    send_to_link(MAC_table[dest_mac], data, length)
            else:
                # Broadcasts the packet on all LISTENING ports, except for the port it was received on
                for i in interfaces:
                    if i != interface:
                        # Port is access, so must not be tagged
                        if interface_vlan[get_interface_name(i)] == vlan_id:
                            untagged_frame = data[0:12] + data[16:]
                            new_length = length - 4
                            send_to_link(i, untagged_frame, new_length)
                        elif interface_vlan[get_interface_name(i)] == sys.maxsize and port_states[i] == "LISTENING":
                            send_to_link(i, data, length)

        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
