#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define TRUE 1
#define ETHER_ADDR_LEN 0x6

typedef struct libnet_ethernet_hdr{
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
}ether;

typedef struct libnet_ipv4_hdr {
    uint8_t ip_vhl;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
}ipv4;

typedef struct libnet_tcp_hdr{
    uint16_t 	th_sport;
    uint16_t 	th_dport;
    uint32_t 	th_seq;
    uint32_t 	th_ack;
    uint8_t     th_offx2;
    uint8_t 	th_flags;
    uint16_t 	th_win;
    uint16_t 	th_sum;
    uint16_t 	th_urp;
}tcp;


void usage(){
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void print_packet_ether (ether * eth_hdr){
    printf("ethernet src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_hdr->ether_shost[0],eth_hdr->ether_shost[1],eth_hdr->ether_shost[2],eth_hdr->ether_shost[3],eth_hdr->ether_shost[4],eth_hdr->ether_shost[5]);
    printf("ethernet dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_hdr->ether_dhost[0],eth_hdr->ether_dhost[1],eth_hdr->ether_dhost[2],eth_hdr->ether_dhost[3],eth_hdr->ether_dhost[4],eth_hdr->ether_dhost[5]);
}

void print_packet_ip(ipv4 * ip_hdr){
    uint8_t ip_src[4];
    uint8_t ip_dst[4];

    memcpy(ip_src, (const char*)&(ip_hdr->ip_src),4);
    memcpy(ip_dst, (const char*)&(ip_hdr->ip_dst),4);

    printf("ip src: %d.%d.%d.%d\n", ip_src[0],ip_src[1],ip_src[2],ip_src[3]);
    printf("ip dst: %d.%d.%d.%d\n", ip_dst[0],ip_dst[1],ip_dst[2],ip_dst[3]);
}

void print_packet_tcp(tcp* tcp_hdr){
    printf("tcp src port: %d\n", ntohs(tcp_hdr->th_sport));
    printf("tcp dst port: %d\n", ntohs(tcp_hdr->th_dport));
}

void print_packet_payload(uint8_t * payload, int length){

    if(length == 0){
        printf("No payload\n");
    } else {
        printf("payload : ");
        int print_len = length < 16 ? length : 16;
        for(int i = 0 ; i < print_len; i++)
            printf("%02X ", payload[i]);
        printf("\n");
    }

}

int main(int argc, char *argv[]) {
    if(argc != 2){
        usage();
        return -1;
    }

    char *dev = argv[1], errbuf[PCAP_ERRBUF_SIZE];

    // Set packet capture descriptor
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while(TRUE){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ether * eth_hdr = (ether *)packet;
        if(ntohs(eth_hdr->ether_type) != 0x0800) continue;

        ipv4 * ip_hdr = (ipv4 *)(packet + sizeof(ether));
        if(ip_hdr->ip_p != 0x06) continue;

        tcp * tcp_hdr = (tcp *)(packet + sizeof(ether) + sizeof(ipv4));
        uint8_t * payload = (uint8_t *)(packet + sizeof(ether) + sizeof(ipv4) + sizeof(tcp));

        printf("%u bytes captured\n", header->caplen);
        print_packet_ether(eth_hdr);
        print_packet_ip(ip_hdr);
        print_packet_tcp(tcp_hdr);

        int payload_len = ntohs(ip_hdr->ip_len) - (sizeof(ipv4) + sizeof(tcp));
        print_packet_payload(payload, payload_len);
        printf("===============================================================\n");
    }

    return 0;
}


