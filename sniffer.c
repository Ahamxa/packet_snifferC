#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>


void print_hex_dump(const unsigned char *packet, int length) {
    int i, j;

    //loop through the packet data, printing in 16 bytes rows
    for (i = 0; i < length; i += 16) {

        //printing offset for current row in hexa decimal format
        printf("%08x ", i);

        //printing hexadecimal values for current row
        for (j = 0; j < 16; j++) {
            if (i + j < length)
                printf("%02x ", packet[i + j]); //printing one byte in hexadecimal format
            else
                printf("   "); //for spacing incase last line is not completed
        }

        printf(" "); //space between hex values and ASCII characters
        
        //print ASCII characters corresponding to Hex values
        for (j = 0; j < 16 && i + j < length; j++) {
            char ch = packet[i + j];
            printf("%c", isprint(ch) ? ch : '.');// print printable characters othre wise .
        }
        printf("\n"); //move to next line
    }
    printf("\n\n");
}



void process_pkt(unsigned char *args, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    
    //displaying details related to packet captured
printf("\n\n[ Packet Captured %ld:%06ld  %d bytes  %d bytes] Packet Captured! Analyzing Data.\n\n",pkthdr->ts.tv_sec,pkthdr->ts.tv_usec,pkthdr->caplen,pkthdr->len);

//printing HEX Dump
printf("[ HEX DUMP]\n\n");
print_hex_dump(packet,pkthdr->caplen);


//extracting the ethernet header from packet 
struct ether_header *eth_header = (struct ether_header *)packet;

printf("[ Data Link Layer ] \n");
//the ether_shost array represents MAC address as an array of 6 bytes, each element of the array represents a byte of MAC address

    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);


    //if ether_type is 0x0800 the its ipv4 header inside this ethernet frame
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        
        //extracting the ip header from packet 
        //adding sizeof ether_header pointer to the packet pointer gives the pointer from where ip header starts
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        printf("\n\n[ Network Layer (IP) ]\n");
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        // if ip protocol is 0x06 then its TCP header inside this ip header
        if (ip_header->ip_p == IPPROTO_TCP) {

        //extracting the TCP header from packet 
        //adding sizeof ether_header pointer and size of ip header  to the packet pointer gives the pointer from where TCP header starts
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            printf("\n\n[ Transport Layer (TCP) ]\n");
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

        } 
    }
    printf("\n_______________________________________\n");


};

int main(){

char errbuf[PCAP_ERRBUF_SIZE];
memset(errbuf,0,PCAP_ERRBUF_SIZE);
pcap_if_t *alldevs, *dev;
int MAXBYTES=2048;
pcap_t *handler;



//pacp_lookup_dev is depriciated so we are using pcap_findalldevs to find all available network interfaces
printf(">> Initiating Network Scan <<\n");
printf("============================\n\n");

printf("[ Initializing ] Initializing network scan....\n");
printf("[ Searching ] Searching for  network devices....\n");

if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[ Error ] error finding devices: %s\n", errbuf);
        return EXIT_FAILURE;
    }

//Using the first available device for capturing packets
dev=alldevs;
printf("[ Device Found ] Device Found: %s\n",dev->name);
printf("[ Access Granted ] Opening %s for packet capturing....\n",dev->name);


// Open the network interface in promiscous mode for packet capture
// we are capturing max 1024 bytes after every 1000 mili sec
    handler = pcap_open_live(dev->name, MAXBYTES, 1, 1000, errbuf);
    if (handler == NULL) {
        fprintf(stderr, "[ Access Denied ] Couldn't open device %s: %s.\n", dev->name, errbuf);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

printf("[ Device Opened ] %s Opened sucessfully....\n",dev->name);
printf("[ Capturing...] capturing packets...  please stand by.\n");
printf("\n_______________________________________\n");

//capture packets continously
pcap_loop(handler, -1, process_pkt, NULL);
pcap_freealldevs(alldevs);
pcap_close(handler);
printf("[ Done ]");


  


return 0;
}
