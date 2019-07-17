#include <cstdint>
#include <cstdio>
#include <pcap.h>
#include "pcap_test.h"

void print_mac(const uint8_t *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const uint8_t *ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2],ip[3]);
}

void print_port(const uint8_t *port) {
    printf("%d\n", (port[0] << 8 ) | port[1]);
}

ether_header set_eheader(const uint8_t *packet){
    ether_header header;
    int h_count=0;
    for (int i = 0; i<6; i++){
        header.ether_dhost.ether_addr_octet[i] = packet[h_count];
        h_count++;
    }
    for (int i = 0; i<6; i++){
        header.ether_shost.ether_addr_octet[i] = packet[h_count];
        h_count++;
    }
    header.ether_type = (packet[h_count] <<8) | packet[h_count+1];

    return header;
}

void pr_mac(ether_header header, int idx){
    if(idx== ether_dhost_idx)printf("Destination MAC : ");
    else printf("Source MAC : ");
    for (int i=0; i<6; i++){
        if(idx== ether_dhost_idx){
            if(header.ether_dhost.ether_addr_octet[i] < 0x10){
                printf("0%X",header.ether_dhost.ether_addr_octet[i]);
            }
            else {
                printf("%2X", header.ether_dhost.ether_addr_octet[i]);
            }

        }
        else {
            if(header.ether_shost.ether_addr_octet[i] < 0x10){
                printf("0%x",header.ether_shost.ether_addr_octet[i]);
            }
            else{
                printf("%2x", header.ether_shost.ether_addr_octet[i]);
            }
        }
        if(i!=5){
            printf(":");
        }
    }

    printf("\n");
}

ip_header set_iheader(const uint8_t *packet){
    ip_header header;
    int h_count=0;
    header.header_len = (packet[h_count] & 0xF)*4; //ip header 는 길이를 32bit단위로 나타냄
    h_count = h_count+2;
    header.total_len = (packet[h_count]<<8)|packet[h_count+1];
    h_count = h_count+7;
    header.protocol = packet[h_count];
    h_count = h_count+3;
    for(int i=0; i<4; i++){
        header.s_ip.ip_addr_octet[i] = packet[h_count];
        h_count++;
    }
    for(int i=0; i<4; i++){
        header.d_ip.ip_addr_octet[i] = packet[h_count];
        h_count++;
    }

    return header;
}

void pr_ip(ip_header header, int idx){
    if(idx==ip_s_addr_idx){
        printf("Destination IP : ");
        printf("%u.%u.%u.%u\n", header.d_ip.ip_addr_octet[0], header.d_ip.ip_addr_octet[1], header.d_ip.ip_addr_octet[2], header.d_ip.ip_addr_octet[3]);
    }
    if(idx==ip_d_addr_idx){
        printf("Source IP : ");
        printf("%u.%u.%u.%u\n", header.s_ip.ip_addr_octet[0], header.s_ip.ip_addr_octet[1], header.s_ip.ip_addr_octet[2], header.s_ip.ip_addr_octet[3]);
    }
}

tcp_header set_theader(const uint8_t *packet){
    tcp_header header;
    int h_count=0;

    header.s_port = (packet[h_count] <<8) | packet[h_count+1];

    h_count= h_count+2;
    header.d_port = (packet[h_count] <<8) | packet[h_count+1];
    h_count= h_count+10;
    header.header_len = (packet[h_count]>>4)*4;//tcp header 는 길이를 32bit단위로 나타냄
    return header;
}

void pr_port(tcp_header header, int idx){
    if(idx==s_port_idx){
        printf("Source port : %d\n", header.s_port);
    }
    if(idx==s_port_idx){
        printf("Destination port : %d\n", header.d_port);
    }
}
