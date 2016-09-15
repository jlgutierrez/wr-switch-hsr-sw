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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <trace.h>


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

struct hsrInfo
{
	int enabled;
};

struct NodeTable
{
  int mac[6];
  int SupSeq;
  int reserved_for_something;
};

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

    /* Redirect standard files to /dev/null */
    freopen( "/dev/null", "r", stdin);
    freopen( "/dev/null", "w", stdout);
    freopen( "/dev/null", "w", stderr);
    
    /* Open the log file */
    openlog ("wrsw_hsrd", LOG_PID, LOG_DAEMON);

}

int main(int argc, char *argv[])
{
	struct NodeTable hsr_nodes_table[MAX_HSR_NODES];
	struct hsrInfo hsr_config;
	
	load_config(&hsr_config, argv[1]);
	
	if (!hsr_config.enabled) 
	
		return 0;
	
	hsrd_deamonize();
	
	init_hsr(&hsr_config);
	
	

    while (1)
    {
        syslog (LOG_NOTICE, "wrsw_hsrd daemon started.");
        sleep (20);
    }

    syslog (LOG_NOTICE, "wrsw_hsrd daemon terminated.");
    closelog();

    return EXIT_SUCCESS;
	
	return 0;
}
