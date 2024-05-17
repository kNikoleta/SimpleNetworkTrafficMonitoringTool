#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h> 
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>  
#include <netinet/ip.h>    
#include <arpa/inet.h>    

#define MAX_LENGTH 65535

typedef struct{
  char *select;
  char *ip4_src;
  char *ip4_dst;
  char *ip6_src;
  char *ip6_dst;
  uint16_t port_src;
  uint16_t port_dst;
  char *protocol;
  uint32_t sequence_number_src;
  uint32_t sequence_number_dst;
  int ntwFlows;
  int TCPntwFlows;
  int UDPntwFlows;
  int totalpck;
  int TCPpck;
  int UDPpck;
  long int TCPbytes;
  long int UDPbytes;
}userData;

void pckHandler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
  struct ethhdr *eth_header = (struct ethhdr *)packet;
  uint16_t ethernet_type = ntohs(eth_header->h_proto);
  struct iphdr *ip_header;
  struct ip6_hdr *ip6_header;
  int total_length = -1;
  int headers_length = -1; 
  int payload_length = -1;
  const u_char *payload;
  int ip = -1;
  char *ip4_src_c;
  char *ip4_dst_c;
  char *ip6_src_c;
  char *ip6_dst_c;
  char *protocol_c;
  uint16_t port_src_c = -1;
  uint16_t port_dst_c = -1;
  uint32_t sequence_number_c = -1;
  uint32_t acknowledgment_number_c = -1;
  userData *ud = (userData *)user_data;
  int retransmitted = -1;

  ip4_src_c = malloc(INET_ADDRSTRLEN); 
  ip4_dst_c = malloc(INET_ADDRSTRLEN);
  ip6_src_c = malloc(INET6_ADDRSTRLEN);
  ip6_dst_c = malloc(INET6_ADDRSTRLEN); 
  protocol_c = malloc(4);

  ud->totalpck++;

  if (ethernet_type == ETH_P_IP) {
    ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    ip = 4;
  }else if (ethernet_type == ETH_P_IPV6) {
    ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ethhdr));
    ip = 6;
  }else{
    //we only want ipv4 and ipv6
    return;
  } 

  if(strcmp(ud->select, "p") == 0){
    
    if(ip == 4){
      switch (ip_header->protocol) {
        case IPPROTO_TCP:
            ud->TCPpck++;
            printf("IP Version: %d\n", ip);
            
            strcpy(protocol_c, "TCP");
            printf("Protocol: %s\n", protocol_c);

            strcpy(ip4_src_c, inet_ntoa(*(struct in_addr *)&ip_header->saddr));
            strcpy(ip4_dst_c, inet_ntoa(*(struct in_addr *)&ip_header->daddr));

            printf("Source IP: %s\n", ip4_src_c);
            printf("Destination IP: %s\n", ip4_dst_c);
            
            struct tcphdr *tcp_header = (struct tcphdr *)((uint8_t *)ip_header + (ip_header->ihl * 4));

            port_src_c = ntohs(tcp_header->source);
            port_dst_c = ntohs(tcp_header->dest);

            printf("TCP Source Port: %u\n", port_src_c);
            printf("TCP Destination Port: %u\n", port_dst_c);
            printf("TCP Header Length: %d bytes\n", tcp_header->doff * 4);
        
            //ethernet_header_length == 14
            headers_length = ip_header->ihl * 4 + tcp_header->doff * 4 + 14;
            payload_length = pkthdr->caplen - headers_length;
            printf("TCP Payload Length: %d bytes\n", payload_length);

            ud->TCPbytes += payload_length;

            payload = packet + headers_length;
            printf("Memory address of payload: %p\n", payload);
            
            ud->TCPbytes += pkthdr->caplen;

            sequence_number_c = ntohl(tcp_header->seq);

            //retransmission algorithm
            if((strcmp(ip4_src_c, ud->ip4_src) == 0 || strcmp(ip4_src_c, ud->ip4_dst) == 0) &&
            (strcmp(ip4_dst_c, ud->ip4_src) == 0 || strcmp(ip4_dst_c, ud->ip4_dst) == 0)){
      
              if((strcmp(ip4_src_c, ud->ip4_src) == 0)){
                
                if(ud->sequence_number_src == -1 || sequence_number_c > ud->sequence_number_src){
                  retransmitted = 0;
                  ud->sequence_number_src = sequence_number_c;
                }else{
                  retransmitted = 1;
                }
        
              }else if(strcmp(ip4_src_c, ud->ip4_dst) == 0){

                if(ud->sequence_number_dst == -1 || sequence_number_c > ud->sequence_number_dst){
                  retransmitted = 0;
                  ud->sequence_number_dst = sequence_number_c;
                }else{
                  retransmitted = 1;
                }

                uint32_t buf = ud->sequence_number_src;
                ud->sequence_number_src = ud->sequence_number_dst;
                ud->sequence_number_dst = buf;

              }

            }else{
              retransmitted = 0;
              ud->sequence_number_src = -1;
              ud->sequence_number_dst = -1;
            }
            
            printf("Retransmitted: %d\n\n", retransmitted);
                               
            break;

        case IPPROTO_UDP:
            ud->UDPpck++;
            printf("IP Version: %d\n", ip);
            
            strcpy(protocol_c, "UDP");
            printf("Protocol: %s\n", protocol_c);

            strcpy(ip4_src_c, inet_ntoa(*(struct in_addr *)&ip_header->saddr));
            strcpy(ip4_dst_c, inet_ntoa(*(struct in_addr *)&ip_header->daddr));

            printf("Source IP: %s\n", ip4_src_c);
            printf("Destination IP: %s\n", ip4_dst_c);
            
            struct udphdr *udp_header = (struct udphdr *)((uint8_t *)ip_header + (ip_header->ihl * 4));

            port_src_c = ntohs(udp_header->source);
            port_dst_c = ntohs(udp_header->dest);

            printf("UDP Source Port: %u\n", port_src_c);
            printf("UDP Destination Port: %u\n", port_dst_c);
            printf("UDP Header Length: 8 bytes\n");
        
            //ethernet_header_length = 14
            headers_length = ip_header->ihl * 4 + 8 + 14;
            payload_length = pkthdr->caplen - headers_length;
            printf("UDP Payload Length: %d bytes\n", payload_length);
            payload = packet + headers_length;
            printf("Memory address of payload: %p\n\n", payload);

            ud->UDPbytes += pkthdr->caplen;
            
            break;

          default:
            // Ignore other protocols
            break;
      }
    }else if(ip == 6){
      switch (ip6_header->ip6_nxt) {
        case IPPROTO_TCP:
            ud->TCPpck++;
            printf("IP Version: %d\n", ip);
            
            strcpy(protocol_c, "TCP");
            printf("Protocol: %s\n", protocol_c);

            inet_ntop(AF_INET6, &ip6_header->ip6_src, ip6_src_c, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6_header->ip6_dst, ip6_dst_c, INET6_ADDRSTRLEN);
            
            printf("Source IP: %s\n", ip6_src_c);
            printf("Destination IP: %s\n", ip6_dst_c);
            
            struct tcphdr *tcp_header = (struct tcphdr *)(ip6_header + 40);

            port_src_c = ntohs(tcp_header->source);
            port_dst_c = ntohs(tcp_header->dest);

            printf("TCP Source Port: %u\n", port_src_c);
            printf("TCP Destination Port: %u\n", port_dst_c);
            printf("TCP Header Length: %d bytes\n", tcp_header->doff * 4);
        
            headers_length = 40 + tcp_header->doff * 4 + 14;
            payload_length = pkthdr->caplen - headers_length;

            printf("TCP Payload Length: %d bytes\n", payload_length);
            
            payload = packet + headers_length;
            printf("Memory address of payload: %p\n", payload);

            ud->TCPbytes += pkthdr->caplen;

            sequence_number_c = ntohl(tcp_header->seq);
  
            //retransmission algorithm
            if((strcmp(ip6_src_c, ud->ip6_src) == 0 || strcmp(ip6_src_c, ud->ip6_dst) == 0) &&
            (strcmp(ip6_dst_c, ud->ip6_src) == 0 || strcmp(ip6_dst_c, ud->ip6_dst) == 0)){
      
              if((strcmp(ip6_src_c, ud->ip6_src) == 0)){
                
                if(ud->sequence_number_src == -1 || sequence_number_c > ud->sequence_number_src){
                  retransmitted = 0;
                  ud->sequence_number_src = sequence_number_c;
                }else{
                  retransmitted = 1;
                }
        
              }else if(strcmp(ip6_src_c, ud->ip6_dst) == 0){

                if(ud->sequence_number_dst == -1 || sequence_number_c > ud->sequence_number_dst){
                  retransmitted = 0;
                  ud->sequence_number_dst = sequence_number_c;
                }else{
                  retransmitted = 1;
                }

                uint32_t buf = ud->sequence_number_src;
                ud->sequence_number_src = ud->sequence_number_dst;
                ud->sequence_number_dst = buf;

              }

            }else{
              retransmitted = 0;
              ud->sequence_number_src = -1;
              ud->sequence_number_dst = -1;
            }
            
            printf("Retransmitted: %d\n\n", retransmitted);
                   
            break;

        case IPPROTO_UDP:
            ud->UDPpck++;
            printf("IP Version: %d\n", ip);
            
            strcpy(protocol_c, "UDP");
            printf("Protocol: %s\n", protocol_c);
            
            inet_ntop(AF_INET6, &ip6_header->ip6_src, ip6_src_c, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6_header->ip6_dst, ip6_dst_c, INET6_ADDRSTRLEN);
            
            printf("Source IP: %s\n", ip6_src_c);
            printf("Destination IP: %s\n", ip6_dst_c);

            struct udphdr *udp_header = (struct udphdr *)((uint8_t *)ip6_header + 40);

            port_src_c = ntohs(udp_header->source);
            port_dst_c = ntohs(udp_header->dest);
            
            printf("UDP Source Port: %u\n", port_src_c);
            printf("UDP Destination Port: %u\n", port_dst_c);
            printf("UDP Header Length: 8 bytes\n");
        
            headers_length = 40 + 8 + 14;
            payload_length = pkthdr->caplen - headers_length;

            printf("UDP Payload Length: %d bytes\n", payload_length);

            payload = packet + headers_length;
            printf("Memory address of payload: %p\n\n", payload);

            ud->UDPbytes += pkthdr->caplen;

            break;

          default:
            // Ignore other protocols
            break;
      }
    }

  }else if(strcmp(ud->select, "i") == 0){
    FILE *myfile = fopen("log.txt", "a");
    if(ip == 4){
      switch (ip_header->protocol) {
        case IPPROTO_TCP:
            ud->TCPpck++;
            fprintf(myfile, "IP Version: %d\n", ip);

            strcpy(protocol_c, "TCP");
            fprintf(myfile,"Protocol: %s\n", protocol_c);

            strcpy(ip4_src_c, inet_ntoa(*(struct in_addr *)&ip_header->saddr));
            strcpy(ip4_dst_c, inet_ntoa(*(struct in_addr *)&ip_header->daddr));

            fprintf(myfile,"Source IP: %s\n", ip4_src_c);
            fprintf(myfile,"Destination IP: %s\n", ip4_dst_c);
            
            struct tcphdr *tcp_header = (struct tcphdr *)((uint8_t *)ip_header + (ip_header->ihl * 4));

            port_src_c = ntohs(tcp_header->source);
            port_dst_c = ntohs(tcp_header->dest);

            fprintf(myfile,"TCP Source Port: %u\n", port_src_c);
            fprintf(myfile,"TCP Destination Port: %u\n", port_dst_c);
            fprintf(myfile,"TCP Header Length: %d bytes\n", tcp_header->doff * 4);
        
            headers_length = ip_header->ihl * 4 + tcp_header->doff * 4 + 14;
            payload_length = pkthdr->caplen - headers_length;

            fprintf(myfile, "TCP Payload Length: %d bytes\n", payload_length);

            payload = packet + headers_length;
            fprintf(myfile, "Memory address of payload: %p\n", payload);

            ud->TCPbytes += pkthdr->caplen;

            sequence_number_c = ntohl(tcp_header->seq);

            //retransmission algorithm
            if((strcmp(ip4_src_c, ud->ip4_src) == 0 || strcmp(ip4_src_c, ud->ip4_dst) == 0) &&
            (strcmp(ip4_dst_c, ud->ip4_src) == 0 || strcmp(ip4_dst_c, ud->ip4_dst) == 0)){
      
              if((strcmp(ip4_src_c, ud->ip4_src) == 0)){
                
                if(ud->sequence_number_src == -1 || sequence_number_c > ud->sequence_number_src){
                  retransmitted = 0;
                  ud->sequence_number_src = sequence_number_c;
                }else{
                  retransmitted = 1;
                }
        
              }else if(strcmp(ip4_src_c, ud->ip4_dst) == 0){

                if(ud->sequence_number_dst == -1 || sequence_number_c > ud->sequence_number_dst){
                  retransmitted = 0;
                  ud->sequence_number_dst = sequence_number_c;
                }else{
                  retransmitted = 1;
                }

                uint32_t buf = ud->sequence_number_src;
                ud->sequence_number_src = ud->sequence_number_dst;
                ud->sequence_number_dst = buf;

              }

            }else{
              retransmitted = 0;
              ud->sequence_number_src = -1;
              ud->sequence_number_dst = -1;
            }
            
            fprintf(myfile,"Retransmitted: %d\n\n", retransmitted);
                   
            break;

        case IPPROTO_UDP:
            ud->UDPpck++;

            fprintf(myfile, "IP Version: %d\n", ip);
            
            strcpy(protocol_c, "UDP");
            fprintf(myfile,"Protocol: %s\n", protocol_c);

            strcpy(ip4_src_c, inet_ntoa(*(struct in_addr *)&ip_header->saddr));
            strcpy(ip4_dst_c, inet_ntoa(*(struct in_addr *)&ip_header->daddr));

            fprintf(myfile,"Source IP: %s\n", ip4_src_c);
            fprintf(myfile,"Destination IP: %s\n", ip4_dst_c);
            
            struct udphdr *udp_header = (struct udphdr *)((uint8_t *)ip_header + (ip_header->ihl * 4));

            port_src_c = ntohs(udp_header->source);
            port_dst_c = ntohs(udp_header->dest);

            fprintf(myfile,"UDP Source Port: %u\n", port_src_c);
            fprintf(myfile,"UDP Destination Port: %u\n", port_dst_c);

            fprintf(myfile, "UDP Header Length: 8 bytes\n");
        
            headers_length = ip_header->ihl * 4 + 8 + 14;
            payload_length = pkthdr->caplen - headers_length;
            fprintf(myfile, "UDP Payload Length: %d bytes\n", payload_length);

            payload = packet + headers_length;
            fprintf(myfile, "Memory address of payload: %p\n\n", payload);

            ud->UDPbytes += pkthdr->caplen;

            break;

          default:
            // Ignore other protocols
            break;
      }
    }else if(ip == 6){
      switch (ip6_header->ip6_nxt) {
        case IPPROTO_TCP:
            ud->TCPpck++;

            fprintf(myfile, "IP Version: %d\n", ip);

            strcpy(protocol_c, "TCP");
            fprintf(myfile, "Protocol: %s\n", protocol_c);

            inet_ntop(AF_INET6, &ip6_header->ip6_src, ip6_src_c, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6_header->ip6_dst, ip6_dst_c, INET6_ADDRSTRLEN);
            
            fprintf(myfile, "Source IP: %s\n", ip6_src_c);
            fprintf(myfile, "Destination IP: %s\n", ip6_dst_c);
            
            struct tcphdr *tcp_header = (struct tcphdr *)(ip6_header + 40);

            port_src_c = ntohs(tcp_header->source);
            port_dst_c = ntohs(tcp_header->dest);

            fprintf(myfile, "TCP Source Port: %u\n", port_src_c);
            fprintf(myfile, "TCP Destination Port: %u\n", port_dst_c);
            fprintf(myfile, "TCP Header Length: %d bytes\n", tcp_header->doff * 4);
        
            headers_length = 40 + tcp_header->doff * 4 + 14;
            payload_length = pkthdr->caplen - headers_length;

            fprintf(myfile, "TCP Payload Length: %d bytes\n", payload_length);

            payload = packet + headers_length;
            fprintf(myfile, "Memory address of payload: %p\n", payload);
            
            ud->TCPbytes += pkthdr->caplen;

            sequence_number_c = ntohl(tcp_header->seq);

            //retransmission algorithm
            if((strcmp(ip6_src_c, ud->ip6_src) == 0 || strcmp(ip6_src_c, ud->ip6_dst) == 0) &&
            (strcmp(ip6_dst_c, ud->ip6_src) == 0 || strcmp(ip6_dst_c, ud->ip6_dst) == 0)){
      
              if((strcmp(ip6_src_c, ud->ip6_src) == 0)){
                
                if(ud->sequence_number_src == -1 || sequence_number_c > ud->sequence_number_src){
                  retransmitted = 0;
                  ud->sequence_number_src = sequence_number_c;
                }else{
                  retransmitted = 1;
                }
        
              }else if(strcmp(ip6_src_c, ud->ip6_dst) == 0){

                if(ud->sequence_number_dst == -1 || sequence_number_c > ud->sequence_number_dst){
                  retransmitted = 0;
                  ud->sequence_number_dst = sequence_number_c;
                }else{
                  retransmitted = 1;
                }

                uint32_t buf = ud->sequence_number_src;
                ud->sequence_number_src = ud->sequence_number_dst;
                ud->sequence_number_dst = buf;

              }

            }else{
              retransmitted = 0;
              ud->sequence_number_src = -1;
              ud->sequence_number_dst = -1;
            }
            
            fprintf(myfile,"Retransmitted: %d\n\n", retransmitted);
            
            break;

        case IPPROTO_UDP:
            ud->UDPpck++;

            fprintf(myfile, "IP Version: %d\n", ip);

            strcpy(protocol_c, "UDP");
            fprintf(myfile,"Protocol: %s\n", protocol_c);
            
            inet_ntop(AF_INET6, &ip6_header->ip6_src, ip6_src_c, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6_header->ip6_dst, ip6_dst_c, INET6_ADDRSTRLEN);
            
            fprintf(myfile,"Source IP: %s\n", ip6_src_c);
            fprintf(myfile,"Destination IP: %s\n", ip6_dst_c);

            struct udphdr *udp_header = (struct udphdr *)((uint8_t *)ip6_header + 40);

            port_src_c = ntohs(udp_header->source);
            port_dst_c = ntohs(udp_header->dest);
            
            fprintf(myfile, "UDP Source Port: %u\n", port_src_c);
            fprintf(myfile, "UDP Destination Port: %u\n", port_dst_c);
            fprintf(myfile, "UDP Header Length: 8 bytes\n");
        
            headers_length = 40 + 8 + 14;
            payload_length = pkthdr->caplen - headers_length;

            fprintf(myfile, "UDP Payload Length: %d bytes\n", payload_length);

            payload = packet + headers_length;
            fprintf(myfile, "Memory address of payload: %p\n\n", payload);
            ud->UDPbytes += pkthdr->caplen;

            break;

          default:
            // Ignore other protocols
            break;
      }
    }
  
    fclose(myfile);
    
  }else{
    printf("Something went wrong in user mode.\n");
  }
  
  if (ip == 4 && (strcmp(ip4_src_c, ud->ip4_src) != 0 || strcmp(ip4_dst_c, ud->ip4_dst) != 0 ||
      ud->port_dst != port_dst_c || ud->port_src != port_src_c ||
      strcmp(ud->protocol, protocol_c) != 0)) {
    
    ud->ntwFlows++;

    if(strcmp(protocol_c, "TCP") == 0){
      ud->TCPntwFlows++;
    }else if(strcmp(protocol_c, "UDP") == 0){
      ud->UDPntwFlows++;
    }

    strcpy(ud->ip4_src, ip4_src_c);
    strcpy(ud->ip4_dst, ip4_dst_c);
    ud->ip6_dst = NULL;
    ud->ip6_src = NULL;
    ud->port_dst = port_dst_c;
    ud->port_src = port_src_c;
    strcpy(ud->protocol, protocol_c);
    

  }else if(ip == 6 && (strcmp(ip6_src_c, ud->ip6_src) != 0 || strcmp(ip6_dst_c, ud->ip6_dst) != 0 
    || ud->port_dst != port_dst_c || ud->port_src != port_src_c 
    || strcmp(ud->protocol,protocol_c) != 0)){
        
    ud->ntwFlows++;
      
    if(strcmp(protocol_c, "TCP") == 0){
      ud->TCPntwFlows++;
    }else if(strcmp(protocol_c, "UDP") == 0){
      ud->UDPntwFlows++;
    }

    ud->ip4_dst = NULL;
    ud->ip4_src = NULL;
    strcpy(ud->ip6_src, ip6_src_c);
    strcpy(ud->ip6_dst, ip6_dst_c);
    ud->port_dst = port_dst_c;
    ud->port_src = port_src_c;
    strcpy(ud->protocol, protocol_c);

  }
  
  if(strcmp(ud->select, "i")){
    FILE *statsFile = fopen("statistic.txt","w");

    fprintf(statsFile,"\nTotal network flows: %d\n"
            "Number of TCP network flows captured: %d\n"
            "Number of UDP network flows captured: %d\n"
            "Total number of packets received: %d\n"
            "Total number of TCP packets received: %d\n"
            "Total number of UDP packets received: %d\n"
            "Total bytes of TCP packets received: %ld\n"
            "Total bytes of UDP packets received: %ld\n",
            ud->ntwFlows,ud->TCPntwFlows, ud->UDPntwFlows,ud->totalpck,ud->TCPpck,ud->UDPpck,ud->TCPbytes,ud->UDPbytes);
    
    fclose(statsFile);
} 

  free(protocol_c);
  free(ip4_src_c);
  free(ip4_dst_c);
  free(ip6_src_c);
  free(ip6_dst_c);
}

int interfaceSel(char *interface){
  pcap_if_t *allints;
  pcap_if_t *curInt;
  pcap_t *intfCapture;
  char errorBuffer[PCAP_ERRBUF_SIZE];
  bool found = false;
  userData *ud = malloc(sizeof(userData));

  //See if the interface exists
  if(pcap_findalldevs(&allints, errorBuffer) == -1) {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", errorBuffer);
    return -1;
  }

  for(curInt = allints; curInt != NULL; curInt = curInt->next) {
    if(strcmp(interface, curInt->name) == 0){
      found = true;
      break;
    }
  }

  if(found == 0){
    printf("Interface not found. Try another one\n");
    return -1;
  }

  for(curInt = allints; curInt != NULL; curInt = curInt->next) {
    printf("%s\n", curInt->name);
  }

  pcap_freealldevs(allints);

  intfCapture = pcap_open_live(interface, MAX_LENGTH, 0, 1000, errorBuffer);

  if (intfCapture == NULL) { 
    printf("Can't open interface %s\n", interface);
    return -1;
  }

  ud->select = "i"; //If it is an interface 
  ud->ip4_src = malloc(INET_ADDRSTRLEN); 
  ud->ip4_dst = malloc(INET_ADDRSTRLEN);
  ud->ip6_src = malloc(INET6_ADDRSTRLEN);
  ud->ip6_dst = malloc(INET6_ADDRSTRLEN); 
  ud->protocol = malloc(4); 
  ud->ntwFlows = 0;
  ud->TCPntwFlows = 0;
  ud->UDPntwFlows = 0;
  ud->totalpck = 0;
  ud->TCPpck = 0;
  ud->UDPpck = 0;
  ud->TCPbytes = 0;
  ud->UDPbytes = 0;
  ud->sequence_number_dst = -1;
  ud->sequence_number_src = -1;
  ud->port_src = -1;
  ud->port_dst = -1;

  //Capturing packets
  pcap_loop(intfCapture, 0, pckHandler, (u_char *)ud); //cnt is set to 0,so it will capture indefinitely until an error occurs or the user interrupts the process.

  pcap_close(intfCapture);
  free(ud->ip4_src);
  free(ud->ip4_dst);
  free(ud->ip6_src);
  free(ud->ip6_dst);
  free(ud->protocol);
  free(ud);
  return 0;
}

int pckCapture(char *inputFileName){

  char errorBuffer[PCAP_ERRBUF_SIZE];
  userData *ud = malloc(sizeof(userData));
  
  pcap_t *pcap = pcap_open_offline(inputFileName, errorBuffer);
  
  if (pcap == NULL) {
      printf("File %s can't be opened. Try again!\n", errorBuffer);
      return -1;
  }

  ud->select = "p";//For pcap file name
  ud->ip4_src = malloc(INET_ADDRSTRLEN); 
  ud->ip4_dst = malloc(INET_ADDRSTRLEN);
  ud->ip6_src = malloc(INET6_ADDRSTRLEN);
  ud->ip6_dst = malloc(INET6_ADDRSTRLEN);
  ud->protocol = malloc(4); 
  ud->ntwFlows = 0;
  ud->TCPntwFlows = 0;
  ud->UDPntwFlows = 0;
  ud->totalpck = 0;
  ud->TCPpck = 0;
  ud->UDPpck = 0;
  ud->TCPbytes = 0;
  ud->UDPbytes = 0;
  ud->sequence_number_dst = -1;
  ud->sequence_number_src = -1;
  ud->port_src = -1;
  ud->port_dst = -1;

  pcap_loop(pcap, 0, pckHandler, (u_char *)ud);

  printf("Total number of network flows captured: %d\n",ud->ntwFlows);
  printf("Number of TCP network flows captured: %d\n",ud->TCPntwFlows);
  printf("Number of UDP network flows captured: %d\n",ud->UDPntwFlows);
  printf("Total number of packets received: %d\n",ud->totalpck);
  printf("Total number of TCP packets received: %d\n",ud->TCPpck);
  printf("Total number of UDP packets received: %d\n",ud->UDPpck);
  printf("Total bytes of TCP packets received: %ld\n",ud->TCPbytes);
  printf("Total bytes of UDP packets received: %ld\n",ud->UDPbytes);

  pcap_close(pcap); 
  free(ud->ip4_src);
  free(ud->ip4_dst);
  free(ud->ip6_src);
  free(ud->ip6_dst);
  free(ud->protocol);
  free(ud);
  
  return 0;
}

int filterInString(char *inputString, char* interface, char *mode){
  char command[100];

  if(strcmp(mode,"r") == 0){
    printf("TCP\n");
    snprintf(command, sizeof(command), "tcpdump -%s %s \"tcp && %s\"", mode, interface, inputString);

    int ret = system(command);
    if (ret != 0) {
      printf("Error executing tcpdump.\n");
      return -1;
    }

    printf("UDP\n");
    snprintf(command, sizeof(command), "tcpdump -%s %s \"udp && %s\"", mode, interface, inputString);
    
     ret = system(command);
    if (ret != 0) {
      printf("Error executing tcpdump.\n");
      return -1;
    }
  }else if(strcmp(mode,"i") == 0){
    FILE * myfile = fopen("log.txt", "a");

    fprintf(myfile,"TCP\n");
    snprintf(command, sizeof(command), "tcpdump -%s %s \"tcp %s\" > log.txt", mode, interface, inputString);

    int ret = system(command);
    if (ret != 0) {
      printf("Error executing tcpdump.\n");
      return -1;
    }
    
    fprintf(myfile,"UDP\n");
    snprintf(command, sizeof(command), "tcpdump -%s %s \"udp %s\" > log.txt", mode, interface, inputString);

    ret = system(command);
    
    if (ret != 0) {
      printf("Error executing tcpdump.\n");
      return -1;
    }
    
    fclose(myfile);
  }
  return 0;
}

int main(int argc, char *argv[]){
  if(argc != 2 && argc != 3 && argc != 5)
    return -1;
  

  char *interface = NULL;
  char *inputFileName = NULL;
  char *inputString = malloc(50);

  for(int i = 1; i < argc; i++) {
    if(strcmp(argv[i], "-i") == 0 && argc == 3) { 
      interface = argv[++i];
      interfaceSel(interface);         
    }else if(strcmp(argv[i], "-r") == 0 && argc == 3) {           
      inputFileName = argv[++i]; 
      pckCapture(inputFileName);
    }else if(strcmp(argv[i], "-i") == 0 && strcmp(argv[i+2], "-f") == 0){
      interface = argv[++i];
      printf("THE INTERFACE: %s\n",interface);
      i++;
      strcat(inputString, argv[++i]);
      printf("THE filter:%s\n",inputString);
      filterInString(inputString, interface, "i");
    }else if(strcmp(argv[i], "-r") == 0 && strcmp(argv[i+2], "-f") == 0){
      inputFileName = argv[++i];
      printf("The file name : %s\n",inputFileName);
      i++;
      strcat(inputString, argv[++i]);
      printf("THE filter:%s\n",inputString);
      filterInString(inputString, inputFileName, "r");
    }else if(strcmp(argv[i], "-h") == 0) {
       printf("\n-----------------------------------------------------------------------------------------------------------------------------------------\n"
              "\n====================================== Network traffic monitoring using the Packet Capture library ======================================\n" 
              "1. Capture packets by selecting a interface:"
              "\n\tExample:\n\t\tsudo ./pcap_ex -i <interface name>\n"
              "2. Capture packets by pcap file name:"
              "\n\tExample:\n\t\t./pcap_ex -r test_pcap_5mins.pcap\n"
              "3. Filter expression in string format:"
              "\n\tExample:\n\t\t./pcap_ex -i eth0 -f “port 8080”\n"
              "------------------------------------------------------------------------------------------------------------------------------------------\n"
              "\tBefore run read the README file.\n"
              "------------------------------------------------------------------------------------------------------------------------------------------\n\n");
    }else{
      return -1;
    }
  }

return 0;
}
