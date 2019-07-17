#include <pcap.h>
#include <stdio.h>
#include <cstdint>
#include "pcap_test.h"

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
    usage();//사용방법 출력
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const uint8_t * packet;
    int res = pcap_next_ex(handle, &header, &packet);//패킷이 어디로 들어왔나
    //포트 80인 경우에 앞에서 내용10 바이트 정도 출력

    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("------------------START------------------\n");
    ether_header e_header;
    e_header = set_eheader(packet);

    pr_mac(e_header, ether_dhost_idx);
    pr_mac(e_header, ether_shost_idx);

    //printf("\n ethernet type :%x \n", e_header.ether_type);
    if(e_header.ether_type ==ether_type_arp){
        printf("**************This is ARP***************\n");
    }
    if(e_header.ether_type ==ether_type_ip){
        printf("**************This is IP****************\n");
        packet = packet + 14;
        ip_header i_header;
        i_header = set_iheader(packet);
        printf("    Ip Header Length : %d\n", i_header.header_len);
        pr_ip(i_header, ip_d_addr_idx);
        pr_ip(i_header, ip_s_addr_idx);

        if(i_header.protocol == ip_protocol_tcp){
            printf("**************This is TCP****************\n");
            packet = packet + i_header.header_len;
            tcp_header t_header;


            t_header = set_theader(packet);
            pr_port(t_header, s_port_idx);
            pr_port(t_header, d_port_idx);
            printf("    TCP header Length : %d\n",t_header.header_len);
             packet = packet+t_header.header_len;
            int data_index;
            data_index = i_header.total_len - i_header.header_len - t_header.header_len;
            printf("       Data size : \t%d\n", data_index);
            if(data_index==0){
                printf("                NO Data\n");
            }
            else if(data_index <10){

                printf("content : ");
                for (int i=0; i<data_index; i++)
                     printf("%X ", packet[i]);
                printf("\n");
            }
            else{
                printf("content : ");
                for(int i=0; i<10; i++){
                    printf("%2X ", packet[i]);
                }
                printf("\n");
            }
        }
    }
    printf("-------------------END-------------------\n\n");
  }

  pcap_close(handle);
  return 0;
}
