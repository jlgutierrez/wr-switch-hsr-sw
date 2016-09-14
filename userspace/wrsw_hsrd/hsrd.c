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

void init_hsr(void){
	
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
    	
	
	*((volatile unsigned long *) (mapped_dev_base + LRE_C)) = (*((volatile unsigned long *) (mapped_dev_base + LRE_C)) | (1 << 1));

}

int main(int argc, char *argv[])
{
	
	init_hsr();
	
	//while(1){
		
		
		
	//}
	
	return 0;
}
