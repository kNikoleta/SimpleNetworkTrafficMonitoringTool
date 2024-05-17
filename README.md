# Network traffic monitoring using the Packet Capture library


## Build and Usage Instructions

### Building the Program

To build the program, run the following command in your terminal:

```bash
make
```

### Running the Program

1. To capture packets from a network interface and save them in log.txt, use:
```bash
sudo ./pcap_ex -i eth0
```
2. To read packets from a capture file and print the outputs in the terminal, use:
```bash
./pcap_ex -r test_pcap_5mins.pcap

```
3. To apply a filter expression for a network interface, use:
```bash
sudo ./pcap_ex -i eth0 -f "port 8080"
```
4. To apply a filter expression for a capture file, use:
```bash
./pcap_ex -r test_pcap_5mins.pcap -f "port 80"
```

### Cleaning up
To clean up the compiled file, use:
```bash
make clean
```

## Comments

### Retransmission
The retransmitted packages are marked with a flag: 0 if it is not a retransmission or 1 if it is, and it is printed with all the other information of the packages. We devised a logic for determining if a packet is a retransmission by checking if the current packet’s source and destination IP addresses match those of the previous packet (stored in ud). If they do, it then checks if the sequence number of the current packet is less than or equal to the sequence number of the previous packet from the same source. If it is, the packet is considered retransmitted. For the code to work it assumes that packets will always arrive in order.

This code does not handle the case where there are multiple concurrent connections involving the same IP addresses and it should not be trusted, as the project is for educational purposes and there was no time for making this specific part better.

### Filtering
For filtering, we couldn’t use pcap_compile and pcap_setfilter due to assignment's description, so we used tcpdump command and returned the results unmodified.

### Statistics
If the mode is -i, the statistics at the end are kept in a text file (statistics.txt). Also, for this mode, in order to stop the packet capturing you have to terminate the program (ctrl +c).

