all:
		gcc -o pcap_ex pcap_ex.c -lpcap
clean:
		rm -rf pcap_ex
