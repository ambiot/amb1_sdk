/******************************************************************************
  *
  * This module is a confidential and proprietary property of RealTek and
  * possession or use of this module requires written permission of RealTek.
  *
  * Copyright(c) 2016, Realtek Semiconductor Corporation. All rights reserved. 
  *
******************************************************************************/

//#define _LWIP_INTF_C_

#include <autoconf.h>
#include <lwip_intf.h>
#include <lwip/netif.h>
#include <lwip_netconf.h>
#include <ethernetif.h>
#include <osdep_service.h>
#include <wifi/wifi_util.h>
#ifdef CONFIG_TRACE_SKB
#include <drv_types.h>
#endif
//----- ------------------------------------------------------------------
// External Reference
//----- ------------------------------------------------------------------
#if (CONFIG_LWIP_LAYER == 1)
extern struct netif xnetif[];			//LWIP netif
#endif

/**
 *      rltk_wlan_set_netif_info - set netif hw address and register dev pointer to netif device
 *      @idx_wlan: netif index
 *			    0 for STA only or SoftAP only or STA in STA+SoftAP concurrent mode, 
 *			    1 for SoftAP in STA+SoftAP concurrent mode
 *      @dev: register netdev pointer to LWIP. Reserved.
 *      @dev_addr: set netif hw address
 *
 *      Return Value: None
 */     
void rltk_wlan_set_netif_info(int idx_wlan, void * dev, unsigned char * dev_addr)
{
#if (CONFIG_LWIP_LAYER == 1)
	rtw_memcpy(xnetif[idx_wlan].hwaddr, dev_addr, 6);
	xnetif[idx_wlan].state = dev;
#endif
}

//*********************************************************************************************************//
#ifdef CONFIG_TRACE_SKB

#define TRACE_SKB_MAX_DEPTH 50

static uint32_t get_sp(void)
{
	register uint32_t result;
	__asm("MOV %0, sp" : "=r" (result));
	return(result);
}

static uint32_t get_lr(void)
{
	register uint32_t result;
	__asm("MOV %0, lr" : "=r" (result));
	return(result);
}

static uint32_t get_psp(void)
{
	register uint32_t result;
	__asm("MRS %0, psp" : "=r" (result));
	return(result);
}
	
void skb_trace(void)
{
    uint32_t stack_pointer = 0, pc = 0;		
	uint32_t buffer[TRACE_SKB_MAX_DEPTH] = {0};
	size_t depth = 0;
	
	uint32_t code_start_addr, sdram_code_start_addr;
	size_t sdram_code_enable, code_size, sdram_code_size;
	
#if defined(__ICCARM__)	
	#if defined(CONFIG_PLATFORM_8711B)	
		#pragma section=".text"
		code_start_addr = (uint32_t)__section_begin(".text");
		code_size = (uint32_t)__section_end(".text") - code_start_addr;
	#elif defined(CONFIG_PLATFORM_8195A)
		#pragma section=".heap.stdlib"
		#pragma section="CPP_INIT"
		#pragma section="CODE"	
		#pragma section=".sdram.text"
		sdram_code_enable = 0;
		code_start_addr = (uint32_t)__section_begin("CPP_INIT");
		code_size = (uint32_t)__section_end("CODE") - code_start_addr;
		sdram_code_start_addr = (uint32_t)__section_begin(".sdram.text");
		sdram_code_size = (uint32_t)__section_end(".sdram.text") - sdram_code_start_addr;
		if(sdram_code_size != 0 || (sdram_code_start_addr&0x30000000) == 0x30000000)
		{
			sdram_code_enable = 1;
		}
	#endif		
#elif defined(__GNUC__)
	extern const int CMB_CSTACK_BLOCK_START;
    extern const int CMB_CSTACK_BLOCK_END;
    extern const int CMB_CODE_SECTION_START;
    extern const int CMB_CODE_SECTION_END;
	#if defined(CONFIG_PLATFORM_8711B)	
		extern u8 __flash_text_start__[];
		extern u8 __flash_text_end__[];
		code_start_addr = (uint32_t)__flash_text_start__;
		code_size = (uint32_t)__flash_text_end__ - code_start_addr;
	#elif defined(CONFIG_PLATFORM_8195A)
		extern u8 __ram_image2_text_start__[];
		extern u8 __ram_image2_text_end__[];
		extern u8 __sdram_data_start__[];
		extern u8 __sdram_data_end__[];
		extern u8 __HeapLimit[];
		code_start_addr = (uint32_t)__ram_image2_text_start__;
		code_size = (uint32_t)__ram_image2_text_end__ - code_start_addr;

		sdram_code_start_addr = (uint32_t)__sdram_data_start__;
		sdram_code_size = (uint32_t)__sdram_data_end__ - sdram_code_start_addr;
		if(sdram_code_size != 0 || (sdram_code_start_addr&0x30000000) == 0x30000000)
		{
			sdram_code_enable = 1;
		}
	#endif	
#endif	
	
    /* delete saved R0~R3, R12, LR,PC,xPSR registers space */
	stack_pointer = get_psp() + sizeof(size_t) * 8;

#if (CMB_CPU_PLATFORM_TYPE == CMB_CPU_ARM_CORTEX_M4) || (CMB_CPU_PLATFORM_TYPE == CMB_CPU_ARM_CORTEX_M7)
#if defined(CONFIG_PLATFORM_8711B)	
	if ((get_lr() & (1UL << 4)) == 0)
		stack_pointer += sizeof(size_t) * 18;
#endif
#endif	

    uint32_t stack_start_addr = (uint32_t)vTaskStackAddr();
    size_t stack_size = vTaskStackSize() * sizeof( StackType_t );
	printf("\r\nstact addr 0x%x, size 0x%x, top 0x%x\r\n", stack_start_addr, stack_size, (uint32_t)vTaskStackTOPAddr());
	
	for (uint32_t sp = stack_pointer; sp < stack_start_addr + stack_size; sp += sizeof(size_t)) {
        pc = *((uint32_t *) sp) - sizeof(size_t);
		if((((pc >= code_start_addr) && (pc <= code_start_addr + code_size))
				||(sdram_code_enable && (pc >= sdram_code_start_addr) && (pc <= sdram_code_start_addr + sdram_code_size))) 
			&& (depth < TRACE_SKB_MAX_DEPTH) )
        	buffer[depth++] = pc;
    }
	
	printf("\r\nlook up stack message, please run: addr2line -e application.axf -a -f ");
	for (int i = 0; i < depth; i++) {
        printf("%8x ", buffer[i]);
    }
	printf("\r\n\r\n");

}
#endif
/**
 *      rltk_wlan_send - send IP packets to WLAN. Called by low_level_output().
 *      @idx: netif index
 *      @sg_list: data buffer list
 *      @sg_len: size of each data buffer
 *      @total_len: total data len
 *
 *      Return Value: None
 */     
int rltk_wlan_send(int idx, struct eth_drv_sg *sg_list, int sg_len, int total_len)
{
#if (CONFIG_LWIP_LAYER == 1)
	struct eth_drv_sg *last_sg;
	struct sk_buff *skb = NULL;
	int ret = 0;

	if(idx == -1){
		DBG_ERR("netif is DOWN");
		return -1;
	}
	DBG_TRACE("%s is called", __FUNCTION__);
	
	save_and_cli();
	if(rltk_wlan_check_isup(idx))
		rltk_wlan_tx_inc(idx);
	else {
		DBG_ERR("netif is DOWN");
		restore_flags();
		return -1;
	}
	restore_flags();

	skb = rltk_wlan_alloc_skb(total_len);
	if (skb == NULL) {
		//DBG_ERR("rltk_wlan_alloc_skb() for data len=%d failed!", total_len);
	  	#ifdef CONFIG_TRACE_SKB
	  	skb_trace();
		dump_skb_list();
		#endif
		ret = -1;
		goto exit;
	} else {
		#ifdef CONFIG_TRACE_SKB
		set_skb_list_flag(skb, SKBLIST_XMITBUF);
		#endif	
	}

	for (last_sg = &sg_list[sg_len]; sg_list < last_sg; ++sg_list) {
		rtw_memcpy(skb->tail, (void *)(sg_list->buf), sg_list->len);
		skb_put(skb,  sg_list->len);		
	}

	rltk_wlan_send_skb(idx, skb);

exit:
	save_and_cli();
	rltk_wlan_tx_dec(idx);
	restore_flags();
	return ret;
#endif
}

/**
 *      rltk_wlan_recv - indicate packets to LWIP. Called by ethernetif_recv().
 *      @idx: netif index
 *      @sg_list: data buffer list
 *      @sg_len: size of each data buffer
 *
 *      Return Value: None
 */     
void rltk_wlan_recv(int idx, struct eth_drv_sg *sg_list, int sg_len)
{
#if (CONFIG_LWIP_LAYER == 1)
	struct eth_drv_sg *last_sg;
	struct sk_buff *skb;
	
	DBG_TRACE("%s is called", __FUNCTION__);
	if(idx == -1){
		DBG_ERR("skb is NULL");
		return;
	}
	skb = rltk_wlan_get_recv_skb(idx);
	DBG_ASSERT(skb, "No pending rx skb");

	for (last_sg = &sg_list[sg_len]; sg_list < last_sg; ++sg_list) {
		if (sg_list->buf != 0) {
			rtw_memcpy((void *)(sg_list->buf), skb->data, sg_list->len);
			skb_pull(skb, sg_list->len);
		}
	}
#endif
}

int netif_is_valid_IP(int idx, unsigned char *ip_dest)
{
#if CONFIG_LWIP_LAYER == 1
	struct netif * pnetif = &xnetif[idx];
	struct ip_addr addr = { 0 };
#ifdef CONFIG_MEMORY_ACCESS_ALIGNED
	unsigned int temp;
	memcpy(&temp, ip_dest, sizeof(unsigned int));
	u32_t *ip_dest_addr = &temp;
#else
	u32_t *ip_dest_addr  = (u32_t*)ip_dest;
#endif
#if LWIP_VERSION_MAJOR >= 2
	ip_addr_set_ip4_u32(&addr, *ip_dest_addr);
#else
	addr.addr = *ip_dest_addr;
#endif

#if (LWIP_VERSION_MAJOR >= 2)
	if((ip_addr_get_ip4_u32(netif_ip_addr4(pnetif))) == 0)
		return 1;
#else

	if(pnetif->ip_addr.addr == 0)
		return 1;
#endif	
	
	if(ip_addr_ismulticast(&addr) || ip_addr_isbroadcast(&addr,pnetif)){
		return 1;
	}
		
	//if(ip_addr_netcmp(&(pnetif->ip_addr), &addr, &(pnetif->netmask))) //addr&netmask
	//	return 1;

	if(ip_addr_cmp(&(pnetif->ip_addr),&addr))
		return 1;

	DBG_TRACE("invalid IP: %d.%d.%d.%d ",ip_dest[0],ip_dest[1],ip_dest[2],ip_dest[3]);
#endif	
#ifdef CONFIG_DONT_CARE_TP
	if(pnetif->flags & NETIF_FLAG_IPSWITCH)
		return 1;
	else
#endif
	return 0;
}

int netif_get_idx(struct netif* pnetif)
{
#if CONFIG_LWIP_LAYER == 1
	int idx = pnetif - xnetif;

	switch(idx) {
	case 0:
		return 0;
	case 1:
		return 1;
	default:
		return -1;
	}
#else	
	return -1;
#endif
}

unsigned char *netif_get_hwaddr(int idx_wlan)
{
#if (CONFIG_LWIP_LAYER == 1)
	return xnetif[idx_wlan].hwaddr;
#else
	return NULL;
#endif
}

void netif_rx(int idx, unsigned int len)
{
#if (CONFIG_LWIP_LAYER == 1)
	ethernetif_recv(&xnetif[idx], len);
#endif
#if (CONFIG_INIC_EN == 1)
        inic_netif_rx(idx, len);
#endif
}

void netif_post_sleep_processing(void)
{
#if (CONFIG_LWIP_LAYER == 1)
	lwip_POST_SLEEP_PROCESSING();	//For FreeRTOS tickless to enable Lwip ARP timer when leaving IPS - Alex Fang
#endif
}

void netif_pre_sleep_processing(void)
{
#if (CONFIG_LWIP_LAYER == 1)
	lwip_PRE_SLEEP_PROCESSING();	
#endif
}

#ifdef CONFIG_WOWLAN
unsigned char *rltk_wlan_get_ip(int idx){
#if (CONFIG_LWIP_LAYER == 1)
	return LwIP_GetIP(&xnetif[idx]);
#else
	return NULL;
#endif
}
#endif

