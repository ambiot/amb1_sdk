/* mbed Microcontroller Library
 *******************************************************************************
 * Copyright (c) 2014, Realtek Semiconductor Corp.
 * All rights reserved.
 *
 * This module is a confidential and proprietary property of RealTek and
 * possession or use of this module requires written permission of RealTek.
 *******************************************************************************
 */

#include "hal_misc.h"
#include "reset_reason_api.h"

/** Fetch the reset reason for the last system reset
 */
reset_reason_t hal_reset_reason_get(void)
{
    reset_reason_t reason = REASON_UNKNOWN;
    HAL_RESET_REASON hal_reason;

    hal_reason = HalGetResetCause();
    
    switch(hal_reason){
        case REASON_DEFAULT_RST:
            reason = RESET_REASON_POWER_ON;
            break;
        case REASON_SOFT_RESTART:
            reason = RESET_REASON_SOFTWARE;
            break;
        case REASON_WDT_RST:
            reason = RESET_REASON_WATCHDOG;
            break;
        default:
            break;
    }
    return reason;  
}


/** Set the reset reason to registers
 *
 * Set the value of the reset status registers, to let user applicatoin store
 * the reason before doing reset.
 */
void hal_reset_reason_set(reset_reason_t reason)
{
    HAL_RESET_REASON hal_reason = REASON_SOFT_RESTART;
    switch(reason){
        case RESET_REASON_SOFTWARE:
            hal_reason = REASON_SOFT_RESTART;
            break;
        case RESET_REASON_WATCHDOG:
            hal_reason = REASON_WDT_RST;
            break;
        default:
            break;
    }
    HalSetResetCause(hal_reason);
}

