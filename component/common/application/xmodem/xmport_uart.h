 /**
  ******************************************************************************
  * @file    xmodem_uart.h
  * @author
  * @version
  * @brief   This file provides user interface for xmodem uart
  ******************************************************************************
  * @attention
  *
  * This module is a confidential and proprietary property of RealTek and possession or use of this module requires written permission of RealTek.
  *
  * Copyright(c) 2016, Realtek Semiconductor Corporation. All rights reserved.
  ****************************************************************************** 
  */

#ifndef _XMPORT_UART_H_
#define _XMPORT_UART_H_

/** @addtogroup xmodem_uart   XMODEM_UART
 *  @ingroup    hal
 *  @brief      Xmodem UART function
 *  @{
 */

#include "xmodem.h"

/**
  * @brief  Initial xmodem Uart
  * @param  uart_idx  : Uart index
  * @param  pin_mux   : Uart pin mux
  * @param  baud_rate : Uart baudrate
  */
void xmodem_uart_init(u8 uart_idx, u8 pin_mux, u32 baud_rate);

/**
  * @brief  Assign xmodem hook function with polling function, put char function, get char function
  * @param  pXComPort : pointer of xmodem comport to save hook function
  */
void xmodem_uart_func_hook(XMODEM_COM_PORT *pXComPort);

/**
  * @brief  Deinit xmodem Uart
  */
void xmodem_uart_deinit(void);

/**
  * @Note   This function is not used in xmodem
  * @brief  Check the readable status of UART 
  * @return 1 : UART is readable
  *         0 : UART is not readable
  */
char xmodem_uart_readable(void);

/**
  * @brief  Check the writable status of UART 
  * @return 1 : UART is writable
  *         0 : UART is not writable
  */
char xmodem_uart_writable(void);

/**
  * @Note   This function is not used in xmodem
  * @brief  Read character by UART
  * @return The character read from UART
  */
char xmodem_uart_getc(void);

/**
  * @brief  Send character by UART
  * @param  c : The character to be sent
  */
void xmodem_uart_putc(char c);

/*\@}*/

#endif  // end of "#define _XMPORT_UART_H_"

