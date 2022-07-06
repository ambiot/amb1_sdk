 /**
  ******************************************************************************
  * @file    rtl_sec.h
  * @author
  * @version
  * @brief   This file provides user interface for efuse encrypt/ decrypt data
  ******************************************************************************
  * @attention
  *
  * This module is a confidential and proprietary property of RealTek and possession or use of this module requires written permission of RealTek.
  *
  * Copyright(c) 2016, Realtek Semiconductor Corporation. All rights reserved.
  ******************************************************************************
  */

#ifndef RTL_SEC_H
#define RTL_SEC_H

/** @addtogroup efuse_sec       EFUSE_SEC
 *  @ingroup    hal
 *  @brief      efuse secure data functions
 *  @{
 */

#include <platform_stdlib.h>

#define SEC_PROCESS_OPT_ENC   1
#define SEC_PROCESS_OPT_DEC   2
#define SEC_PROCESS_OPT_VERIFY   3
#define SEC_PROCESS_OPT_ENC_AES_256   4
#define SEC_PROCESS_OPT_DEC_AES_256   5

#define sec_process_data ProcessSecData

/**
  * @brief      Use efuse OTP key to encrypt/decrypt data
  * @param[in]  key_idx : the key index in efuse
  * @param[in]  opt : SEC_PROCESS_OPT_ENC => encrypt by AES 128
                      SEC_PROCESS_OPT_DEC => decrypt by AES 128
                      SEC_PROCESS_OPT_VERIFY => verify
                      SEC_PROCESS_OPT_ENC_AES_256 => encrypt by AES 256
                      SEC_PROCESS_OPT_DEC_AES_256 => decrypt by AES 256
  * @param[in]  iv : initialization vector
  * @param[in]  input_buf : input buffer that need to encrypt or decrypt
  * @param[in]  buf_len : input but length
  * @param[out] output_buf : output buffer that has been encrypted or decrypted
  *
  * @return 0 : failed, input_buf==NULL, output_buf==NULL, buf_len<0, buf_len>16000, buf_len isn't 16-Bytes align
  *             key_idx isn't 1 or 2, opt isn't 1~5
  *         1 : success
  */
uint32_t sec_process_data(uint8_t key_idx, uint32_t opt, uint8_t *iv, uint8_t *input_buf, uint32_t buf_len, uint8_t *output_buf);

/*\@}*/

#endif // RTL_SEC_H
