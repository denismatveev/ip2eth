#ifndef bgw2liH
#define bgw2liH
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#define BUF_SIZE 1522 // ethernet packet can't be greater than 1522 bytes(if VLAN used). It won't be able to work with jumbo frames


void writeLog(const char *, ...);

typedef struct
{
  pcap_t *sendHandler; //where to send new packets by libpcap
}userArgs;


void processPacketWoModification(userArgs *, const struct pcap_pkthdr *, const u_char *);
void processPacketWModification(userArgs *, const struct pcap_pkthdr *, const u_char *);

#endif
