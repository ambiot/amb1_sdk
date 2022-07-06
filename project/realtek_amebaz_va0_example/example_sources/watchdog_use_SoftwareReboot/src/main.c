/*
 *  Routines to access hardware
 *
 *  Copyright (c) 2015 Realtek Semiconductor Corp.
 *
 *  This module is a confidential and proprietary property of RealTek and
 *  possession or use of this module requires written permission of RealTek.
 */

#include "device.h"
#include "wdt_api.h"
#include "flash_api.h"



#define RUN_CALLBACK_IF_WATCHDOG_BARKS (1)
#define printf	DBG_8195A

/*	Need to make sure that watchdog_irq_handler and function it calls 
	are defined not in flash to prevent block when watchdog 
	barks during flash operation	
	*/
IMAGE2_RAM_TEXT_SECTION
void my_watchdog_irq_handler(uint32_t id) {
	CPU_ClkSet(CLK_125M);
	DelayUs(10);
	software_reboot();
}

#define FLASH_APP_BASE  0xFF000
void main(void) {

    watchdog_init(5000); // setup 5s watchdog

#if RUN_CALLBACK_IF_WATCHDOG_BARKS
    watchdog_irq_init(my_watchdog_irq_handler, 0);
#else
    // system would restart when watchdog barks
#endif

    watchdog_start();

/*	Add your own operation code	*/

	while(1);
}

