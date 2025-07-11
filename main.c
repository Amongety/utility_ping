#define _DEFAULT_SOURCE
#include <stdio.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

#define ETH_ALEN 6

struct arphdr_total {
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
    /* Ethernet looks like this : This bit is variable sized
       however...  */
    unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char __ar_sip[4];		/* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char __ar_tip[4];		/* Target IP address.  */
};

struct if_PChdr {
    char ifa_name[16];		/* Name of this network interface.  */
    short int ifa_flags;	/* Flags as from SIOCGIFFLAGS ioctl.  */
    int ifa_ivalue;      /* Interface index */
    int ifa_mtu;              /* Maximum transmission unit */
  
    struct sockaddr ifa_addr;	/* Network address of this interface.  */
    struct sockaddr ifa_netmask; /* Netmask of this interface.  */
    struct sockaddr ifa_hwaddr; /* MAC address */
    struct sockaddr ifa_dgtwaddr;   /* Default gateway address*/
    struct sockaddr ifa_dgtwhwaddr;  /* Default  gateway MAC address*/
    union
    {
      /* At most one of the following two is valid.  If the IFF_BROADCAST
         bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
         IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
         It is never the case that both these bits are set at once.  */
      struct sockaddr ifu_broadaddr; /* Broadcast address of this interface. */
      struct sockaddr ifu_dstaddr; /* Point-to-point destination address.  */
    } ifa_ifu;
    /* These very same macros are defined by <net/if.h> for `struct ifaddr'.
       So if they are defined already, the existing definitions will be fine.  */
};

int default_gateway(struct if_PChdr *result) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) {
        printf("Error fopen in \"get_gateway\": %s\n", strerror(errno));
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char iface[32];
        unsigned long dest, gateway;
        int flags;

        if (sscanf(line, "%31s %lx %lx %X", iface, &dest, &gateway, &flags) == 4) {
            if (dest == 0) {  // Default route
                struct sockaddr_in default_gatway;
                default_gatway.sin_family = AF_INET;
                default_gatway.sin_addr.s_addr = gateway;

                memcpy(&result->ifa_dgtwaddr, &default_gatway, sizeof(struct sockaddr));
                break;
            }
        }
    }

    fclose(fp);
    return 0;
}

int formation_arp(const uint8_t *sender_hard, const uint8_t *target_hard, const in_addr_t sender_ip, const in_addr_t target_ip, int ifindex, struct arphdr_total *res) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd == -1) {
        printf("Error socket in \"formation_arp\" %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    char *send_buff = (char*)malloc(sizeof(char) * 4096);
    char *recv_buff = (char*)malloc(sizeof(char) * 4096);
    memset(send_buff, 0, 4096);
    memset(recv_buff, 0, 4096);

    struct ether_header ether_frame;
    memset(&ether_frame, 0, sizeof(struct ether_header));
    memcpy(ether_frame.ether_dhost, target_hard, ETH_ALEN);
    memcpy(ether_frame.ether_shost, sender_hard, ETH_ALEN);
    ether_frame.ether_type = htons(ETHERTYPE_ARP);

    struct arphdr_total arp_frame;
    memset(&arp_frame, 0, sizeof(struct arphdr_total));
    arp_frame.ar_hln = ETH_ALEN;
    arp_frame.ar_hrd = htons(ARPHRD_ETHER);
    arp_frame.ar_op = htons(ARPOP_REQUEST);
    arp_frame.ar_pln = 4;
    arp_frame.ar_pro = htons(ETHERTYPE_IP);
    memcpy(arp_frame.__ar_sha, sender_hard, ETH_ALEN);
    memcpy(arp_frame.__ar_sip, (char*)&sender_ip, 4);
    memcpy(arp_frame.__ar_tha, ether_aton("00:00:00:00:00:00")->ether_addr_octet, ETH_ALEN);
    memcpy(arp_frame.__ar_tip, (char*)&target_ip, 4);

    memcpy(send_buff, (char*)&ether_frame, sizeof(struct ether_header));
    memcpy(send_buff + sizeof(struct ether_header), (char*)&arp_frame, sizeof(struct arphdr_total));

    struct sockaddr_ll server;
    server.sll_family = AF_PACKET;
    server.sll_protocol = htons(ETH_P_ARP);
    server.sll_ifindex = ifindex;
    server.sll_hatype = htons(ARPHRD_ETHER);
    server.sll_pkttype = PACKET_BROADCAST;
    server.sll_halen = 6;
    memcpy(server.sll_addr, target_hard, 6);
    server.sll_addr[6] = 0x00;
    server.sll_addr[7] = 0x00;

    if(sendto(sockfd, send_buff, sizeof(struct ether_header) + sizeof(struct arphdr_total) + 18, 0, (struct sockaddr*)&server, sizeof(struct sockaddr_ll)) == -1) {
        printf("Error sendto in \"formation_arp\": %s", strerror(errno));
        free(send_buff);
        free(recv_buff);
        close(sockfd);
        return -1;
    }

    free(send_buff);
    
    if(recvfrom(sockfd, recv_buff, 4096, 0, NULL, NULL) == -1) {
        printf("Error recvfrom in \"formation_arp\": %s\n", strerror(errno));
        free(recv_buff);
        close(sockfd);
        return -1;
    }

    memcpy(res, recv_buff + sizeof(struct ether_header), sizeof(struct arphdr_total));

    free(recv_buff);
    close(sockfd);
    return 0;
}

int search_interface(struct if_PChdr *result) {
    struct ifaddrs *ifPC;

    if(getifaddrs(&ifPC) == -1) {
        printf("Error getifaddrs in \"search_interface\": %s\n", strerror(errno));
        freeifaddrs(ifPC);
        return -1;
    }

    for(struct ifaddrs *next = ifPC; next != NULL; next = next->ifa_next) {
        if((next->ifa_flags & IFF_UP) && (next->ifa_flags & IFF_BROADCAST) && (next->ifa_flags & IFF_RUNNING) && (next->ifa_flags & IFF_MULTICAST) && next->ifa_addr->sa_family == AF_INET) {
            result->ifa_flags = (short int)next->ifa_flags;
            if(next->ifa_name != NULL) memcpy(result->ifa_name, next->ifa_name, strlen(next->ifa_name));
            if(next->ifa_addr != NULL) memcpy(&result->ifa_addr, next->ifa_addr, sizeof(struct sockaddr));
            if(next->ifa_netmask != NULL) memcpy(&result->ifa_netmask, next->ifa_netmask, sizeof(struct sockaddr));
            if(next->ifa_ifu.ifu_broadaddr != NULL) memcpy(&result->ifa_ifu.ifu_broadaddr, next->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr));
            if(next->ifa_ifu.ifu_dstaddr != NULL )memcpy(&result->ifa_ifu.ifu_dstaddr, next->ifa_ifu.ifu_dstaddr, sizeof(struct sockaddr));

            int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if(sockfd == -1) {
                printf("Error socket in \"search_interface\": %s\n", strerror(errno));
                close(sockfd);
                freeifaddrs(ifPC);
                return -1;
            }
            
            struct ifreq call_ioctl;
            memset(&call_ioctl, 0, sizeof(struct ifreq));
            memcpy(call_ioctl.ifr_ifrn.ifrn_name, next->ifa_name, strlen(next->ifa_name));

            if(ioctl(sockfd, SIOCGIFHWADDR, &call_ioctl) == -1) {
                printf("Error ioclt in \"search_interface\": %s\n", strerror(errno));
                close(sockfd);
                freeifaddrs(ifPC);
                return -1;
            }
            memcpy(&result->ifa_hwaddr, &call_ioctl.ifr_ifru.ifru_hwaddr, sizeof(struct sockaddr));

            if(ioctl(sockfd, SIOCGIFINDEX, &call_ioctl) == -1) {
                printf("Error ioclt in \"search_interface\": %s\n", strerror(errno));
                close(sockfd);
                freeifaddrs(ifPC);
                return -1;
            }
            memcpy(&result->ifa_ivalue, &call_ioctl.ifr_ifru.ifru_ivalue, sizeof(int));

            if(ioctl(sockfd, SIOCGIFMTU, &call_ioctl) == -1) {
                printf("Error ioclt in \"search_interface\": %s\n", strerror(errno));
                close(sockfd);
                freeifaddrs(ifPC);
                return -1;
            }
            memcpy(&result->ifa_mtu, &call_ioctl.ifr_ifru.ifru_mtu, sizeof(int));

            if(default_gateway(result) == -1) {
                close(sockfd);
                freeifaddrs(ifPC);
                return -1;
            }

            struct arphdr_total macaddr_defaultgatway;
            if(formation_arp(result->ifa_hwaddr.sa_data,  ether_aton("ff:ff:ff:ff:ff:ff")->ether_addr_octet, ((struct sockaddr_in*)&result->ifa_addr)->sin_addr.s_addr, ((struct sockaddr_in*)&result->ifa_dgtwaddr)->sin_addr.s_addr, result->ifa_ivalue, &macaddr_defaultgatway) == -1) {
                close(sockfd);
                freeifaddrs(ifPC);
                return -1;
            }
            memcpy(&result->ifa_dgtwhwaddr.sa_data, macaddr_defaultgatway.__ar_sha, ETH_ALEN);

            close(sockfd);
            break;
        }
    }

    freeifaddrs(ifPC);
    return 0;
}

unsigned short checksum_ipv4(struct ip *iphdr, unsigned short *chksum) {
    uint64_t res = 0;
    uint16_t *hdr = (uint16_t*)iphdr;

    for(int i = 0; i < sizeof(struct ip) / 2; ++i) {
        if(i == 5) continue;
        res += ntohs(hdr[i]);
    }

    while(res > 65535) {
        res = (uint16_t)res + (uint16_t)(res >> 16);
    }
    
    res = ntohs(~res);

    memcpy(chksum, &res, sizeof(unsigned short));
    return res;
}

unsigned short cal_chksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while(nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if( nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int add_ethernet_packet(char *packet, uint8_t mac_destination[ETH_ALEN], uint8_t mac_source[ETH_ALEN], uint16_t packet_typeID) {
    struct ether_header ether_frame;
    memset(&ether_frame, 0, sizeof(struct ether_header));

    memcpy(ether_frame.ether_dhost, mac_destination, ETH_ALEN);
    memcpy(ether_frame.ether_shost, mac_source, ETH_ALEN);
    ether_frame.ether_type = htons(packet_typeID);

    memcpy(packet, &ether_frame, sizeof(struct ether_header));

    return 0;
}

int add_ipv4_packet(char *packet, uint8_t type_service, unsigned short total_len, unsigned short identification, unsigned short fragment_offset, uint8_t ttl, uint8_t protocol, in_addr_t source_address, in_addr_t destination_address) {
    struct ip ip_frame;
    memset(&ip_frame, 0, sizeof(struct ip));

    ip_frame.ip_hl = 5;
    ip_frame.ip_v = 4;
    ip_frame.ip_tos = type_service;
    ip_frame.ip_len = htons(total_len);
    ip_frame.ip_id = htons(identification);
    ip_frame.ip_off = htons(fragment_offset);
    ip_frame.ip_ttl = ttl;
    ip_frame.ip_p = protocol;
    ip_frame.ip_sum = htons(0);
    ip_frame.ip_src.s_addr = source_address;
    ip_frame.ip_dst.s_addr = destination_address;
    checksum_ipv4(&ip_frame, &ip_frame.ip_sum);

    memcpy(packet, &ip_frame, sizeof(struct ip));

    return 0;
}

int add_icmpv4_packet(char *packet, uint8_t type, uint8_t code, uint16_t id, uint16_t sequence) {
	struct icmphdr icmp;
	struct timeval *tval;
	memset(&icmp, 0, sizeof(struct icmphdr));

	icmp.type = type;
	icmp.code = code;
	icmp.checksum = 0;
	icmp.un.echo.id = htons(id);
	icmp.un.echo.sequence = htons(sequence);
	tval = (struct timeval*)packet + sizeof(struct icmphdr);
	gettimeofday(tval, NULL);
	icmp.checksum = cal_chksum((unsigned short *)&icmp, sizeof(struct icmphdr) + 56);

	memcpy((char*)packet, (char*)&icmp, sizeof(struct icmphdr) + 56);

	return 0;
}


int main(int argc, char *argv[]) 
{
	struct if_PChdr *PCinfo = (struct if_PChdr*)malloc(sizeof(struct if_PChdr));
    memset(PCinfo, 0, sizeof(struct if_PChdr));
    if(search_interface(PCinfo) == -1) {
		return -1;
	}
	
	char send_buf[1500];
	char recv_buf[1500];
	
	add_ethernet_packet(send_buf, PCinfo->ifa_dgtwhwaddr.sa_data, PCinfo->ifa_hwaddr.sa_data, ETHERTYPE_IP);
	
	unsigned short identification_ip = rand() % 65536;
	in_addr_t destIP = inet_addr(argv[1]);
	add_ipv4_packet(send_buf + sizeof(struct ether_header), 0, sizeof(struct ip) + sizeof(struct icmphdr) + 56, identification_ip, IP_DF, MAXTTL, IPPROTO_ICMP, ((struct sockaddr_in*)&PCinfo->ifa_addr)->sin_addr.s_addr, destIP);
	
	uint16_t id = rand() % 65536;
	uint16_t seq = 1;
	add_icmpv4_packet(send_buf + sizeof(struct ether_header) + sizeof(struct ip), ICMP_ECHO, ICMP_NET_UNREACH, id, seq);
	
	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sockfd == -1) {
		printf("Error create socket\n");
		return -1;
	}
	struct sockaddr_ll target_packet;
    memset(&target_packet, 0, sizeof(struct sockaddr_ll));
    target_packet.sll_family = AF_PACKET;
    target_packet.sll_protocol = ntohs(ETH_P_ALL);
    target_packet.sll_ifindex = PCinfo->ifa_ivalue;

    if(bind(sockfd, (struct sockaddr*)&target_packet, sizeof(struct sockaddr_ll)) == -1) {
        printf("Error bind in \"main\": %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

	while(1) {
		send(sockfd, send_buf, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr) + 56, 0);
		recv(sockfd, recv_buf, 1500, 0);
		struct ether_header *mac = (struct ether_header*)recv_buf;
		if(htons(mac->ether_type) == ETHERTYPE_IP && strcmp(mac->ether_shost, PCinfo->ifa_hwaddr.sa_data))
			printf("Mac: %s\n", ether_ntoa((struct ether_addr*)mac->ether_shost));

		identification_ip = rand() % 65536;
		add_ipv4_packet(send_buf + sizeof(struct ether_header), 0, sizeof(struct ip) + sizeof(struct icmphdr) + 56, identification_ip, IP_DF, MAXTTL, IPPROTO_ICMP, ((struct sockaddr_in*)&PCinfo->ifa_addr)->sin_addr.s_addr, destIP);
		
		id = rand() % 65536;
		add_icmpv4_packet(send_buf + sizeof(struct ether_header) + sizeof(struct ip), ICMP_ECHO, ICMP_NET_UNREACH, id, ++seq);

		sleep(2);
	}
		
	close(sockfd);
	return 0;
}
