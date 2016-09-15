/*
 * Author: José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
 
/**
 * @file hsrd.c
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * @date 14 Sep 2016
 * @brief HSR Daemon
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <minipc.h>
#include "term.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <trace.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <pthread.h>



#define WB_HSR_BASE_ADDR 0x10061000
#define WB_BRAM_OFFSET 4
#define WB_BRAM_SIZE 200000
#define WB_BRAM_MASK (WB_BRAM_SIZE - 1)

#define LRE_C 		0x00000000
#define LRE_MAC_H 	0x00000008
#define LRE_MAC_L 	0x00000004
#define WR0_FWD 	0x0000000c
#define WR1_FWD 	0x00000010
#define WR0_DROP 	0x00000014
#define WR1_DROP 	0x00000018
#define WR0_ACC 	0x0000001c
#define WR1_ACC 	0x00000020

#define MAX_HSR_NODES	32

#define MY_DEST_MAC0	0x01
#define MY_DEST_MAC1	0x1b
#define MY_DEST_MAC2	0x19
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00

#define DEFAULT_IF	"wr1"
#define BUF_SIZ		1024

#define ETHER_TYPE	0x88fb

struct hsrInfo
{
	int enabled;
	int supSeq;
};

struct NodeTable
{
  uint8_t mac[6];
  int supseq;
  int ttl;
};

struct NodeTable hsr_nodes_table[MAX_HSR_NODES];
int n_current_nodes = 0;
int cop = 1;

void load_config(struct hsrInfo *hsr_config, char *filename){
	
	FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(filename, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
		if (strstr(line, "HSR_ENABLED") != NULL) {
			if(strstr(line, "y") != NULL) {
				hsr_config->enabled = 1;
			}else{
				hsr_config->enabled = 0;
			}
		}
    }

    fclose(fp);
    if (line)
        free(line);
}
void init_hsr(struct hsrInfo *hsr_config){
	
	int memfd;
    void *mapped_base, *mapped_dev_base; 
	
	off_t dev_base = WB_HSR_BASE_ADDR; 
	
	memfd = open("/dev/mem", O_RDWR | O_SYNC);
    if (memfd == -1) {
        printf("Can't open /dev/mem.\n");
        exit(0);
    }
	
	mapped_base = mmap(0, WB_BRAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, dev_base & ~WB_BRAM_MASK);
        if (mapped_base == (void *) -1) {
        printf("Can't map the memory to user space.\n");
        exit(0);
    }
  
    mapped_dev_base = mapped_base + (dev_base & WB_BRAM_MASK); 
    	
	if(hsr_config->enabled)
		*((volatile unsigned long *) (mapped_dev_base + LRE_C)) = (*((volatile unsigned long *) (mapped_dev_base + LRE_C)) | (1 << 1));
	else 
		*((volatile unsigned long *) (mapped_dev_base + LRE_C)) = (*((volatile unsigned long *) (mapped_dev_base + LRE_C)) & ~(1 << 1));
	
	//Clear all registers.
	*((volatile unsigned long *) (mapped_dev_base + LRE_C)) = (*((volatile unsigned long *) (mapped_dev_base + LRE_C)) | (1 << 10));
	

}

void hsrd_deamonize()
{
	pid_t pid, sid;

    /* already a daemon */
    if ( getppid() == 1 ) return;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    /* If we got a good PID, then we can exit the parent process. */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* At this point we are executing as the child process */

    /* Change the file mode mask */
    umask(0);

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory.  This prevents the current
       directory from being locked; hence not being able to remove it. */
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

	// just for debugging...
    ///* Redirect standard files to /dev/null */
    //freopen( "/dev/null", "r", stdin);
    //freopen( "/dev/null", "w", stdout);
    //freopen( "/dev/null", "w", stderr);
    
    ///* Open the log file */
    //openlog ("wrsw_hsrd", LOG_PID, LOG_DAEMON);
    // end just for debugging...

}

void send_HSR_supervision(char *iface, struct hsrInfo *hsr_config){
	
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
	
	/* Get interface name */
	strcpy(ifName, iface);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;
	/* Ethertype field */
	eh->ether_type = htons("0x88fb");
	tx_len += sizeof(struct ether_header);
	sendbuf[tx_len-2] = 0x88; //ethertype
	sendbuf[tx_len-1] = 0xfb; //ethertype
	/* Packet data */
	//sendbuf[tx_len++] = 0x88; //ethertype
	//sendbuf[tx_len++] = 0xfb; //ethertype
	sendbuf[tx_len++] = 0x00; //SupPath = 0
	sendbuf[tx_len++] = 0x01; //SupVersion = 1
	tx_len++;
	sendbuf[tx_len++] = (uint16_t)(hsr_config->supSeq); //SupSequenceNumber
	sendbuf[tx_len++] = 0x17; //TLV1.type = 23
	sendbuf[tx_len++] = 0x06; //TLV1.length = 6
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0]; //DANH MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1]; //DANH MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2]; //DANH MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3]; //DANH MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4]; //DANH MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]; //DANH MAC
	sendbuf[tx_len++] = 0x1E; //TLV2.type = 30
	sendbuf[tx_len++] = 0x06; //TLV2.length = 6
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0]; //REDBOX MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1]; //REDBOX MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2]; //REDBOX MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3]; //REDBOX MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4]; //REDBOX MAC
	sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]; //REDBOX MAC
	sendbuf[tx_len++] = 0x00; //TLV0.type = 0
	sendbuf[tx_len++] = 0x00; //TLV0.length = 0
	
	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;

	/* Send packet */
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");
	
	close(sockfd);
}

void *recv_HSR_supervision(char *iface){

	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t buf[BUF_SIZ];
	char ifName[IFNAMSIZ];
	
	uint8_t mac[6];
	int seq;
	
	//mac = (char *)malloc(12);
	
	/* Get interface name */
	strcpy(ifName, iface);

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buf;
	struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");	
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

repeat:	
	numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);


	/* Get source IP */
	((struct sockaddr_in *)&their_addr)->sin_addr.s_addr = iph->saddr;
	inet_ntop(AF_INET, &((struct sockaddr_in*)&their_addr)->sin_addr, sender, sizeof sender);

	/* Look up my device IP addr if possible */
	strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_ip) >= 0) { /* if we can't check then don't */
		printf("Source IP: %s\n My IP: %s\n", sender, 
				inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
		/* ignore if I sent it */
		if (strcmp(sender, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr)) == 0)	{
			printf("but I sent it :(\n");
			ret = -1;
			goto done;
		}
	}

	/* UDP payload length */
	ret = ntohs(udph->len) - sizeof(struct udphdr);

	
	while(!cop){
		//waiting for the resource.
	}
	// update entry
	cop = 0;
	
	mac[0]=buf[6];
    mac[1]=buf[7];
    mac[2]=buf[8];
    mac[3]=buf[9];
    mac[4]=buf[10];
    mac[5]=buf[11];
    
    seq = (int) buf[17];
	
	update_table(mac, seq);
	cop = 1;
	//free resource
	
	// bytes 7-11  mac origen
	

done:	goto repeat;

	close(sockfd);
	
}

int update_table(uint8_t *mac, int seq){
	
	int pos = 0;
	
	pos = check_entry(mac, seq);
	if (pos == -1){
		printf("Ring fully booked!\n");
		return -2;
	}else{
		strcpy(hsr_nodes_table[pos].mac,mac);
		hsr_nodes_table[pos].supseq = seq;
		hsr_nodes_table[pos].ttl = 60;
	}
}

int check_entry(uint8_t *mac){
	
	int pos = -1;
	int i = 0;
	
	for (i=0; i<n_current_nodes && pos==-1; i++){
		if(hsr_nodes_table[i].mac[0]==mac[0] && 
			hsr_nodes_table[i].mac[1]==mac[1] &&
			hsr_nodes_table[i].mac[2]==mac[2] &&
			hsr_nodes_table[i].mac[3]==mac[3] &&
			hsr_nodes_table[i].mac[4]==mac[4] &&
			hsr_nodes_table[i].mac[5]==mac[5])
			pos = i;
	}
	
	if (n_current_nodes == 32 && pos==-1)
		pos = -1;
	if (n_current_nodes != 32 && pos==-1)
		pos = n_current_nodes++;
	
	return pos;
}

void update_ttl(){
	
	int i;
	
	for (i=0; i<n_current_nodes; i++){
		hsr_nodes_table[i].ttl=hsr_nodes_table[i].ttl-2;
	
		if (hsr_nodes_table[i].ttl <= 0)
			forget_node(i);
	}
}

void forget_node(int i){
	
	int j;
	for (j=i; i<n_current_nodes-1; j++){
		hsr_nodes_table[j].mac[0] = hsr_nodes_table[j+1].mac[0];
		hsr_nodes_table[j].mac[1] = hsr_nodes_table[j+1].mac[1];
		hsr_nodes_table[j].mac[2] = hsr_nodes_table[j+1].mac[2];
		hsr_nodes_table[j].mac[3] = hsr_nodes_table[j+1].mac[3];
		hsr_nodes_table[j].mac[4] = hsr_nodes_table[j+1].mac[4];
		hsr_nodes_table[j].mac[5] = hsr_nodes_table[j+1].mac[5];
		hsr_nodes_table[j].supseq = hsr_nodes_table[j+1].supseq;
		hsr_nodes_table[j].ttl = hsr_nodes_table[j+1].ttl;
	}
	n_current_nodes--;
}

void print_table(){
	
	int i = 0;
	
	printf("\nHSR Supervision Table:");
	printf("\nNodes in ring: %d\n", n_current_nodes);
	if(n_current_nodes!=0) printf("\nOrig. MAC Addr\t\tSupSeqNumber\tTTL");
	for (i=0; i<n_current_nodes; i++){
		
		printf("\nNode: %02x:%02x:%02x:%02x:%02x:%02x\t\t%d\t%d\n", 
		hsr_nodes_table[i].mac[0], 
		hsr_nodes_table[i].mac[1], 
		hsr_nodes_table[i].mac[2],
		hsr_nodes_table[i].mac[3], 
		hsr_nodes_table[i].mac[4], 
		hsr_nodes_table[i].mac[5], 
		hsr_nodes_table[i].supseq,
		hsr_nodes_table[i].ttl);
	}
	
}
int main(int argc, char *argv[])
{
	struct hsrInfo hsr_config;
	
	pthread_t threads[2];
	int rc;
	
	load_config(&hsr_config, argv[1]);
	
	if (!hsr_config.enabled) 
		return 0;
		
	hsr_config.supSeq = 0;
	
	hsrd_deamonize();
	
	init_hsr(&hsr_config);
	
	syslog (LOG_NOTICE, "wrsw_hsrd daemon started.");
	
	//launch HSR receivers
	rc = pthread_create(&threads[0], NULL, recv_HSR_supervision, "wr1");
	if (rc){
	 printf("ERROR; return code from pthread_create() is %d\n", rc);
	 exit(-1);
	}
	rc = pthread_create(&threads[1], NULL, recv_HSR_supervision, "wr2");
	if (rc){
	 printf("ERROR; return code from pthread_create() is %d\n", rc);
	 exit(-1);
	}

    while (1)
    {
		send_HSR_supervision("wr1", &hsr_config);
		send_HSR_supervision("wr2", &hsr_config);
		hsr_config.supSeq++;
        sleep (2);
        update_ttl();
        print_table();
    }

    syslog (LOG_NOTICE, "wrsw_hsrd daemon terminated.");
    closelog();
    
    pthread_exit(NULL);

    return EXIT_SUCCESS;
	
	return 0;
}
