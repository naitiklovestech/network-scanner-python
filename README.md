# network-scanner-python
This is a network scan tool written in Python which can be directly run in the system terminal locally

## Dependencies 
This tool has minimum dependencies which can be easily installed by using pip command 
- socket
This library is used to establish network connections over the network protocols such as TCP and UDP to send and receive data packets
```
python3 -m pip install socket
```
- scapy
This library is used for interacting with packets on the network
```
python3 -m pip install scapy
```
- thread
```
python3 -m pip install thread
```
- lock
```
python3 -m pip install lock
```

## Getting Started
1. Install the ```scapy``` library and necessary modules ```socket, scapy, lock, thread```
2. Define all the functions - scanHost, scanRange, tcp_scan, network_scan
3. Use ```socket``` to create TCP connections to every port within the specified range
4. Print all the open ports if the connection is successful, if not give error message 
5. Use ```scapy``` to create ARP packets and send them to discover devices in the network
6. Extract IP and MAC addresses from the received responses and print your discoveries

## Contributing
This repository does not require any setup before contrbution, you can just fork this to your github, and then test the script directly in your system to get started 

After you've tried out the script, start trying to optimize the script or making more functions to expand the working, and test the functions that you've built and open a fresh PR to become a contributor