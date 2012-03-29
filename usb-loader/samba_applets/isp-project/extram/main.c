/* ----------------------------------------------------------------------------
 *         ATMEL Microcontroller Software Support
 * ----------------------------------------------------------------------------
 * Copyright (c) 2008, Atmel Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer below.
 *
 * Atmel's name may not be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * DISCLAIMER: THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ----------------------------------------------------------------------------
 */

//------------------------------------------------------------------------------
//         Headers
//------------------------------------------------------------------------------

#include "../common/applet.h"
#include "ddramc.h"
#include <board.h>
#include <board_lowlevel.h>
#include <board_memories.h>
#include <pio/pio.h>
#include <dbgu/dbgu.h>
#include <utility/assert.h>
#include <utility/trace.h>

#include <string.h>

//------------------------------------------------------------------------------
//         External definitions
//------------------------------------------------------------------------------
#ifndef __GIT__
#define __GIT__ ""
#endif

//------------------------------------------------------------------------------
//         Local definitions
//------------------------------------------------------------------------------

#if defined(at91sam9g45) || defined(at91sam9m10)
#define EXTRAM_ADDR AT91C_DDR2
#define EXTRAM_SIZE BOARD_DDRAM_SIZE
#elif at91sam3u4 
#define EXTRAM_ADDR BOARD_EBI_PSRAM
#define EXTRAM_SIZE BOARD_PSRAM_SIZE
#else
#define EXTRAM_ADDR AT91C_EBI_SDRAM
#define EXTRAM_SIZE BOARD_SDRAM_SIZE
#endif

/// External RAM is SDRAM
#define TYPE_SDRAM 0
/// External RAM is DDRAM
#define TYPE_DDRAM 1
/// External RAM is PSRAM
#define TYPE_PSRAM 2


//------------------------------------------------------------------------------
//         Local structure
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/// Structure for storing parameters for each command that can be performed by
/// the applet.
//------------------------------------------------------------------------------
struct _Mailbox {

    /// Command send to the monitor to be executed.
    unsigned int command;
    /// Returned status, updated at the end of the monitor execution.
    unsigned int status;

    /// Input Arguments in the argument area
    union {

        /// Input arguments for the Init command.
        struct {

            /// Communication link used.
            unsigned int comType;
            /// Trace level.
            unsigned int traceLevel;
            /// External memory voltage selection.
            unsigned int VddMemSel;
            /// External RAM type.
            unsigned int ramType;
            /// External RAM bus width.
            unsigned int dataBusWidth;
            /// External DDRAM Model.
            unsigned int ddrModel;

        } inputInit;

        /// Output arguments for the Init command.
        struct {

            /// Memory size.
            unsigned int memorySize;
            /// Buffer address.
            unsigned int bufferAddress;
            /// Buffer size.
            unsigned int bufferSize;
        } outputInit;
    } argument;
};


//------------------------------------------------------------------------------
//         Global variables
//------------------------------------------------------------------------------

/// Marks the end of program space.
extern unsigned int end;


//------------------------------------------------------------------------------
//         Local functions
//------------------------------------------------------------------------------

// ------------------------------------------------------------------------------
/// Go/No-Go test of the first 10K-Bytes of external RAM access.
/// \return 0 if test is failed else 1.
//------------------------------------------------------------------------------

int r_seed;

void my_srand(int seed)
{
    r_seed = seed;
}

int my_rand()
{
    r_seed *= 101028131;
    r_seed += 12345;
    return r_seed;
}
static unsigned char ExtRAM_TestOk(void)
{
    unsigned int i;
    unsigned int *ptr = (unsigned int *) EXTRAM_ADDR;

/*    for(;;)
    {
	ptr[0] = 0xdeadbeef;
	ptr[0x1000] = ~0xdeadbeef;
    } */
    
    my_srand(0);
    TRACE_INFO("testing External RAM");
    for (i = 0; i < 512 * 1024; ++i) {
        ptr[i] = my_rand();
    }

    my_srand(0);
    for (i = 0; i < 512 * 1024; ++i) {
        if (ptr[i] != my_rand()) {
        	TRACE_INFO( "fail: %x %x\n\r", i, ptr[i]);
                return 0;
            }
    }
    return 1;
}


void delay(int x)
{
    while(x--) asm volatile("nop");
}
//------------------------------------------------------------------------------
/// Applet code for initializing the external RAM.
//------------------------------------------------------------------------------
int main(int argc, char **argv)
{
    struct _Mailbox *pMailbox = (struct _Mailbox *) argv;
    unsigned int ramType = 0;
    unsigned int dataBusWidth = 0;
    unsigned int ddrModel = 0;

    LowLevelInit();

    TRACE_CONFIGURE_ISP(DBGU_STANDARD, 115200, BOARD_MCK);
    
    

/*    *AT91C_PMC_PCER = AT91C_ID_PIOA;
    *AT91C_PIOA_PDR = (1<<31);
    *AT91C_PIOA_OER = (1<<31);
    *AT91C_PIOA_BSR = (1<<31);
    *AT91C_PIOA_PER = (1<<0);
    *AT91C_PIOA_OER = (1<<0);
    
    *AT91C_PMC_PCKR = (1<<8); // select master clock
    *AT91C_PMC_SCER = (1<<8); // ENABLE PCK0*/
    
    TRACE_INFO("Statup: PMC_MCKR %x MCK = %d command = %d\n\r", *AT91C_PMC_MCKR, BOARD_MCK, pMailbox->command);
    // ----------------------------------------------------------
    // INIT:
    // ----------------------------------------------------------
    if (pMailbox->command == APPLET_CMD_INIT) {

        // Initialize PMC
//	BOARD_RemapRam();


        // Enable User Reset
        AT91C_BASE_RSTC->RSTC_RMR |= AT91C_RSTC_URSTEN | (0xA5<<24);
        

        ramType = pMailbox->argument.inputInit.ramType;
        dataBusWidth = pMailbox->argument.inputInit.dataBusWidth;
        ddrModel = pMailbox->argument.inputInit.ddrModel;

//#if (DYN_TRACES == 1)
//        traceLevel = pMailbox->argument.inputInit.traceLevel;
//#endif

        TRACE_INFO("-- EXTRAM ISP Applet %s --\n\r", SAM_BA_APPLETS_VERSION);
        TRACE_INFO("-- %s\n\r", BOARD_NAME);
        TRACE_INFO("-- Compiled: %s %s %s --\n\r", __DATE__, __TIME__, __GIT__);
        TRACE_INFO("INIT command:\n\r");

        TRACE_INFO("\tCommunication link type : %d\n\r", pMailbox->argument.inputInit.comType);
        TRACE_INFO("\tData bus width : %d bits\n\r", dataBusWidth);
        if (ramType == TYPE_SDRAM) {
           TRACE_INFO("\tExternal RAM type : %s\n\r", "SDRAM");
        }
        else {
            if (ramType == TYPE_DDRAM) {
                TRACE_INFO("\tExternal RAM type : %s\n\r", "DDRAM");
            }
            else {
                TRACE_INFO("\tExternal RAM type : %s\n\r", "PSRAM");
            }
        }

#if defined(at91cap9) || defined(at91sam9m10) || defined(at91sam9g45)
        TRACE_INFO("\tInit EBI Vdd : %s\n\r", (pMailbox->argument.inputInit.VddMemSel)?"3.3V":"1.8V");   
        BOARD_ConfigureVddMemSel(pMailbox->argument.inputInit.VddMemSel);
#endif //defined(at91cap9)

        if (pMailbox->argument.inputInit.ramType == TYPE_SDRAM) {
            // Configure SDRAM controller
            TRACE_INFO("\tInit SDRAM...\n\r");
#if defined(PINS_SDRAM)
            BOARD_ConfigureSdram(dataBusWidth);
#endif
        }
        else if (pMailbox->argument.inputInit.ramType == TYPE_PSRAM) {
            TRACE_INFO("\tInit PSRAM...\n\r");   
#if defined(at91sam3u4)            
            BOARD_ConfigurePsram();
#endif            
        }
        else { 
            // Configure DDRAM controller
#if defined(at91cap9dk) || defined(at91sam9m10) || defined(at91sam9g45)
            TRACE_INFO("\tInit DDRAM ... (model : %d)\n\r", ddrModel);
	    BOARD_ConfigureVddMemSel(VDDMEMSEL_1V8);
            BOARD_ConfigureDdram(0, dataBusWidth);
//	    ddramc_hw_init();
#endif
        }

        // Test external RAM access
        if (ExtRAM_TestOk()) {

            pMailbox->status = APPLET_SUCCESS;
        }
        else {
            pMailbox->status = APPLET_FAIL;
        }

        pMailbox->argument.outputInit.bufferAddress = ((unsigned int) &end);
        pMailbox->argument.outputInit.bufferSize = 0;
        pMailbox->argument.outputInit.memorySize = EXTRAM_SIZE;

        TRACE_INFO("\tInit successful.\n\r");
    }

    // Acknowledge the end of command
    TRACE_INFO("\tEnd of applet (command : %x --- status : %x)\n\r", pMailbox->command, pMailbox->status);

    // Notify the host application of the end of the command processing
    pMailbox->command = ~(pMailbox->command);

    return 0;
}

