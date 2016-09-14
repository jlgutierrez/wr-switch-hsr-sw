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
 * @file wrsw_hsr_info.c
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * @date 14 Sep 2016
 * @brief Read HSR register values from WRSW_HSR_LRE module
 *
 * Reads WRSW_HSR_LRE registers to get: HSR enabled/disabled, number of 
 * frames dropped, duplicated and forwarded. It also gets the MAC address
 * associated to the HSR endpoints.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <minipc.h>

#include "term.h"

#define PTP_EXPORT_STRUCTURES
#include "ptpd_exports.h"

#include "hal_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

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

hexp_port_list_t port_list;

static struct minipc_ch *ptp_ch;

void show_all_loop(void){
		
	int memfd, c;
    void *mapped_base, *mapped_dev_base; 
	
	off_t dev_base = WB_HSR_BASE_ADDR; 
	
	memfd = open("/dev/mem", O_RDWR | O_SYNC);
    if (memfd == -1) {
        printf("Can't open /dev/mem.\n");
        exit(0);
    }
    printf("/dev/mem opened.\n"); 
	
	mapped_base = mmap(0, WB_BRAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, dev_base & ~WB_BRAM_MASK);
        if (mapped_base == (void *) -1) {
        printf("Can't map the memory to user space.\n");
        exit(0);
    }
    printf("Memory mapped at address %p.\n", mapped_base); 
  
    mapped_dev_base = mapped_base + (dev_base & WB_BRAM_MASK); 
    printf("mapped_dev_base = %p\n", mapped_dev_base);
	
	//test
	//*((volatile unsigned long *) (mapped_dev_base + LRE_MAC_L)) = 0xEFAB;
	//*((volatile unsigned long *) (mapped_dev_base + LRE_MAC_H)) = 0x12345678;
	
	do {
		system("/usr/bin/clear");
		printf("\n---------------------------------------------------------\n");
		printf("WR High-availability Seamless Redundancy Register Monitor\n");
		printf("---------------------------------------------------------");
		printf("\nLRE Control Register:\t\t%08x",*((volatile unsigned int *)(mapped_dev_base + LRE_C)));
		printf("\nLRE MAC:\t\t%08x%08x",*((volatile unsigned int *)(mapped_dev_base + LRE_MAC_L)), 
									*((volatile unsigned int *)(mapped_dev_base + LRE_MAC_H)));
		printf("\nWR0 forwarded frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR0_FWD)));
		printf("\nWR1 forwarded frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR1_FWD)));
		printf("\nWR0 dropped frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR0_DROP)));
		printf("\nWR1 dropped frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR1_DROP)));
		printf("\nWR0 accepted frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR0_ACC)));
		printf("\nWR1 accepted frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR1_ACC)));
		printf("\n\n");
		sleep(1);
	}while(1);
	
	// closing files and memory
    close(memfd);
	
}

void show_all_once(void){
	int memfd;
    void *mapped_base, *mapped_dev_base; 
	
	off_t dev_base = WB_HSR_BASE_ADDR; 
	
	memfd = open("/dev/mem", O_RDWR | O_SYNC);
    if (memfd == -1) {
        printf("Can't open /dev/mem.\n");
        exit(0);
    }
    printf("/dev/mem opened.\n"); 
	
	mapped_base = mmap(0, WB_BRAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, dev_base & ~WB_BRAM_MASK);
        if (mapped_base == (void *) -1) {
        printf("Can't map the memory to user space.\n");
        exit(0);
    }
    printf("Memory mapped at address %p.\n", mapped_base); 
  
    mapped_dev_base = mapped_base + (dev_base & WB_BRAM_MASK); 
    printf("mapped_dev_base = %p\n", mapped_dev_base);
    
	printf("\n---------------------------------------------------------\n");
	printf("WR High-availability Seamless Redundancy Register Monitor\n");
	printf("---------------------------------------------------------");
	printf("\nLRE Control Register:\t\t%08x",*((volatile unsigned int *)(mapped_dev_base + LRE_C)));
	printf("\nLRE MAC:\t\t%08x%08x",*((volatile unsigned int *)(mapped_dev_base + LRE_MAC_L)), 
								*((volatile unsigned int *)(mapped_dev_base + LRE_MAC_H)));
	printf("\nWR0 forwarded frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR0_FWD)));
	printf("\nWR1 forwarded frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR1_FWD)));
	printf("\nWR0 dropped frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR0_DROP)));
	printf("\nWR1 dropped frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR1_DROP)));
	printf("\nWR0 accepted frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR0_ACC)));
	printf("\nWR1 accepted frames:\t\t%d",*((volatile unsigned int *)(mapped_dev_base + WR1_ACC)));
	printf("\n\n");
	
	// closing files and memory
    close(memfd);
	
}

void show_help(char *argv[]){
	printf("\n---------------------------------------------------------\n");
	printf("WR High-availability Seamless Redundancy Register Monitor\n");
	printf("---------------------------------------------------------\n");
	printf("\tUsage %s: [-a|-l|-r|-h]\n", argv[0]);
	printf("\t -a --> shows all registers once\n");
	printf("\t -l --> shows constantly all registers\n");
	printf("\t -h --> shows this help message\n");
	printf("\t -r --> resets all registers\n");
}

void reset_counters(void){
	
	int memfd;
    void *mapped_base, *mapped_dev_base; 
	
	off_t dev_base = WB_HSR_BASE_ADDR; 
	
	memfd = open("/dev/mem", O_RDWR | O_SYNC);
    if (memfd == -1) {
        printf("Can't open /dev/mem.\n");
        exit(0);
    }
    printf("/dev/mem opened.\n"); 
	
	mapped_base = mmap(0, WB_BRAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, dev_base & ~WB_BRAM_MASK);
        if (mapped_base == (void *) -1) {
        printf("Can't map the memory to user space.\n");
        exit(0);
    }
    printf("Memory mapped at address %p.\n", mapped_base); 
  
    mapped_dev_base = mapped_base + (dev_base & WB_BRAM_MASK); 
    printf("mapped_dev_base = %p\n", mapped_dev_base);
    
    printf("Reseting all WR HSR registers...\n");
	
	*((volatile unsigned long *) (mapped_dev_base + LRE_C)) = 0x00000000;
	*((volatile unsigned long *) (mapped_dev_base + LRE_MAC_L)) = 0x00000000;
	*((volatile unsigned long *) (mapped_dev_base + LRE_MAC_H)) = 0x00000000;
	*((volatile unsigned long *) (mapped_dev_base + WR0_FWD)) = 0x00000000;
	*((volatile unsigned long *) (mapped_dev_base + WR1_FWD)) = 0x00000000;
	*((volatile unsigned long *) (mapped_dev_base + WR0_DROP)) = 0x00000000;
	*((volatile unsigned long *) (mapped_dev_base + WR1_DROP)) = 0x00000000;
	*((volatile unsigned long *) (mapped_dev_base + WR0_ACC)) = 0x00000000;
	*((volatile unsigned long *) (mapped_dev_base + WR1_ACC)) = 0x00000000;
	
	printf("All WR HSR registers should be now 0x0 ...\n");
	
	printf("\n---------------------------------------------------------\n");
	printf("WR High-availability Seamless Redundancy Register Monitor\n");
	printf("---------------------------------------------------------");
	printf("\nLRE Control Register:\t%08x",*((volatile unsigned int *)(mapped_dev_base + LRE_C)));
	printf("\nLRE MAC:\t%08x%08x",*((volatile unsigned int *)(mapped_dev_base + LRE_MAC_L)), 
								*((volatile unsigned int *)(mapped_dev_base + LRE_MAC_H)));
	printf("\nWR0 forwarded frames:\t%d",*((volatile unsigned int *)(mapped_dev_base + WR0_FWD)));
	printf("\nWR1 forwarded frames:\t%d",*((volatile unsigned int *)(mapped_dev_base + WR1_FWD)));
	printf("\nWR0 dropped frames:\t%d",*((volatile unsigned int *)(mapped_dev_base + WR0_DROP)));
	printf("\nWR1 dropped frames:\t%d",*((volatile unsigned int *)(mapped_dev_base + WR1_DROP)));
	printf("\nWR0 accepted frames:\t%d",*((volatile unsigned int *)(mapped_dev_base + WR0_ACC)));
	printf("\nWR1 accepted frames:\t%d",*((volatile unsigned int *)(mapped_dev_base + WR1_ACC)));
	printf("\n\n");
	// closing files and memory
    close(memfd);
}

int main(int argc, char *argv[])
{
	int opt;
	
	if (argc < 2){
		show_help(argv);
		return -1;
	}

	while((opt=getopt(argc, argv, "alrh")) != -1)
	{
		switch(opt)
		{
			case 'l':
				show_all_loop();
				break;
			case 'r':
				reset_counters();
				break;
			case 'a':
				show_all_once();
				break;
			case 'h':
				show_help(argv);
				break;	
		}
	}

	
	printf("\n");
	return 0;
}
