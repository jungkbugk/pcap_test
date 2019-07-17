#include <cstdint>
#include <cstdio>
#include <pcap.h>

#ifndef PCAP_TEST_H
#define PCAP_TEST_H

#endif // PCAP_TEST_H


#define ether_dhost_idx 0
#define ether_shost_idx 1
#define ether_type_ip 0x0800
#define ether_type_arp 0x0806

#define ip_s_addr_idx 0
#define ip_d_addr_idx 1

#define ip_protocol_tcp 6
#define ip_protocol_udp 17

#define s_port_idx 0
#define d_port_idx 1

struct ether_addr{
    uint8_t ether_addr_octet[6];
};
struct ip_addr{
    uint8_t ip_addr_octet[4];
};

struct ether_header{
    struct ether_addr ether_dhost;
    struct ether_addr ether_shost;
    uint16_t ether_type;
};

struct ip_header{
    uint8_t header_len;
    uint8_t protocol;
    uint16_t total_len;
    struct ip_addr d_ip;
    struct ip_addr s_ip;
};

struct tcp_header{
    uint16_t s_port;
    uint16_t d_port;
    uint16_t header_len;
};

void pr_mac(ether_header header, int idx);
void print_mac(const uint8_t *mac);
void print_ip(const uint8_t *ip);
void print_port(const uint8_t *port);

ether_header set_eheader(const uint8_t *packet);
ip_header set_iheader(const uint8_t *packet);

void pr_mac(ether_header header, int idx);
int get_ether_type(ether_header header);
void pr_ip(ip_header header, int idx);


tcp_header set_theader(const uint8_t *packet);
void pr_port(tcp_header header, int idx);
