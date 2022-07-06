/*
 * Copyright (c) 2014-2016 Alibaba Group. All rights reserved.
 *
 * Alibaba Group retains all right, title and interest (including all
 * intellectual property rights) in and to this computer program, which is
 * protected by applicable intellectual property laws.  Unless you have
 * obtained a separate written license from Alibaba Group., you are not
 * authorized to utilize all or a part of this computer program for any
 * purpose (including reproduction, distribution, modification, and
 * compilation into object code), and you must immediately destroy or
 * return to Alibaba Group all copies of this computer program.  If you
 * are licensed by Alibaba Group, your rights to utilize this computer
 * program are limited by the terms of that license.  To obtain a license,
 * please contact Alibaba Group.
 *
 * This computer program contains trade secrets owned by Alibaba Group.
 * and, unless unauthorized by Alibaba Group in writing, you agree to
 * maintain the confidentiality of this computer program and related
 * information and to not disclose this computer program and related
 * information to any other person or entity.
 *
 * THIS COMPUTER PROGRAM IS PROVIDED AS IS WITHOUT ANY WARRANTIES, AND
 * Alibaba Group EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED,
 * INCLUDING THE WARRANTIES OF MERCHANTIBILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, TITLE, AND NONINFRINGEMENT.
 */

#ifdef PLATFORM_LINUX
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h> 
#include <unistd.h>
#include <pthread.h>
#include <net/if.h>	      // struct ifreq
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>       // IP_MAXPACKET (65535)
#include <net/ethernet.h>     // ETH_P_ALL
#include <linux/if_packet.h>
#include "platform_config.h"
#endif

#include "alink2.0/include/alink_platform.h"
 
rtw_wifi_setting_t wifi_config;
extern int wlan_wrtie_reconnect_data_to_flash(u8 *data, uint32_t len);
#if CONFIG_LWIP_LAYER
extern struct netif xnetif[NET_IF_NUM]; 
#endif
 
#ifndef WPA_GET_BE24(a)
#define WPA_GET_BE24(a) ((((u32) (a)[0]) << 16) | (((u32) (a)[1]) << 8) | \
			 ((u32) (a)[2]))
#endif

//????????, ??????1-3min, APP?????1min??
int platform_awss_get_timeout_interval_ms(void)
{
    return 3 * 60 * 1000;
}

//??????????
int platform_awss_get_connect_default_ssid_timeout_interval_ms( void )
{
    return 0;
}

//????????????, ??200ms-400ms
int platform_awss_get_channelscan_interval_ms(void)
{
	return 200;
}

//wifi????,??1-13
void platform_awss_switch_channel(char primary_channel,
		char secondary_channel, uint8_t bssid[ETH_ALEN])
{
	wifi_set_channel(primary_channel);
}

#ifdef PLATFORM_LINUX
int open_socket(void)
{
	int fd;
#if 0
	if (getuid() != 0)
		err("root privilege needed!\n");
#endif
	//create a raw socket that shall sniff
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	assert(fd >= 0);

	struct ifreq ifr;
	int sockopt = 1;

	memset(&ifr, 0, sizeof(ifr));

	/* set interface to promiscuous mode */
	strncpy(ifr.ifr_name, WLAN_IFNAME, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		perror("ioctl(SIOCGIFFLAGS)");
		goto exit;
	}
	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl(SIOCSIFFLAGS)");
		goto exit;
	}

	/* allow the socket to be reused */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                &sockopt, sizeof(sockopt)) < 0) {
		perror("setsockopt(SO_REUSEADDR)");
		goto exit;
	}

	/* bind to device */
	struct sockaddr_ll ll;

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_protocol = htons(ETH_P_ALL);
	ll.sll_ifindex = if_nametoindex(WLAN_IFNAME);
	if (bind(fd, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
		perror("bind[PF_PACKET] failed");
		goto exit;
	}

	return fd;
exit:
	close(fd);
	exit(EXIT_FAILURE);
}

pthread_t monitor_thread;
char monitor_running;

void *monitor_thread_func(void *arg)
{
    platform_awss_recv_80211_frame_cb_t ieee80211_handler = arg;
    /* buffer to hold the 80211 frame */
    char *ether_frame = malloc(IP_MAXPACKET);
	assert(ether_frame);

    int fd = open_socket();
    int len, ret;
    fd_set rfds;
    struct timeval tv;

    while (monitor_running) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;//100ms

        ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        assert(ret >= 0);

        if (!ret)
            continue;

        //memset(ether_frame, 0, IP_MAXPACKET);
        len = recv(fd, ether_frame, IP_MAXPACKET, 0);
        if (len < 0) {
            perror ("recv() failed:");
            //Something weird happened
            continue;
        }

        /*
         * Note: use tcpdump -i wlan0 -w file.pacp to check link type and FCS
         */

        /* rtl8188: include 80211 FCS field(4 byte) */
        int with_fcs = 1;
        /* rtl8188: link-type IEEE802_11_RADIO (802.11 plus radiotap header) */
        int link_type = AWSS_LINK_TYPE_80211_RADIO;

        (*ieee80211_handler)(ether_frame, len, link_type, with_fcs);
    }

    free(ether_frame);
    close(fd);

    return NULL;
}
#endif

/****
aws库调用该函数来接收80211无线包
平台注册回调vendor_data_callback()来收包
将monitor模式下抓到的包传入该函数进行处理
参数：
	buf: frame buffer
	length: frame len
****/
platform_awss_recv_80211_frame_cb_t  p_handler_recv_data_callback;
static char monitor_running;

// callback for promisc packets, like rtk_start_parse_packet in SC, wf, 1021
void awss_wifi_promisc_rx(unsigned char* buf, unsigned int len, void* user_data)
{
	/* rtl8188: include 80211 FCS field(4 byte) */
	int with_fcs = 0;
	/* rtl8188: link-type IEEE802_11_RADIO (802.11 plus radiotap header) */
	int link_type = AWSS_LINK_TYPE_NONE;
	
#if CONFIG_UNSUPPORT_PLCPHDR_RPT
	int type = ((ieee80211_frame_info_t *)user_data)->type;
	if(type == RTW_RX_UNSUPPORT)
		link_type = AWSS_LINK_TYPE_HT40_CTRL;
#endif

	if (monitor_running) {
		p_handler_recv_data_callback((char *)buf, len, link_type, with_fcs);
	}
//	aws_80211_frame_handler((char *)buf, len, AWSS_LINK_TYPE_NONE, 0);
}

//杩涘叆monitor妯″紡, 骞跺仛濂戒竴浜涘噯澶囧伐浣滐紝濡?
//璁剧疆wifi宸ヤ綔鍦ㄩ粯璁や俊閬?
//鑻ユ槸linux骞冲彴锛屽垵濮嬪寲socket鍙ユ焺锛岀粦瀹氱綉鍗★紝鍑嗗鏀跺寘
//鑻ユ槸rtos鐨勫钩鍙帮紝娉ㄥ唽鏀跺寘鍥炶皟鍑芥暟aws_80211_frame_handler()鍒扮郴缁熸帴鍙?
void platform_awss_open_monitor(platform_awss_recv_80211_frame_cb_t cb)
{
	alink_printf(ALINK_DEBUG, "[%s], start monitor\n", __func__);
	monitor_running = 1;
	p_handler_recv_data_callback = cb;
	wifi_enter_promisc_mode();
	wifi_set_promisc(RTW_PROMISC_ENABLE_2, awss_wifi_promisc_rx, 1);
	wifi_set_channel(6);
}

//閫�鍑簃onitor妯″紡锛屽洖鍒皊tation妯″紡, 鍏朵粬璧勬簮鍥炴敹
void platform_awss_close_monitor(void)
{
	alink_printf(ALINK_DEBUG, "[%s], close monitor\n", __func__);
	monitor_running = 0;
	p_handler_recv_data_callback = NULL;
	wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);
}

int auth_trans(char encry)
{
	int auth_ret = -1;
	switch(encry){
	case AWSS_ENC_TYPE_NONE:
		auth_ret = RTW_SECURITY_OPEN;
		break;
	case AWSS_ENC_TYPE_WEP:
		auth_ret = RTW_SECURITY_WEP_PSK;
		break;
	case AWSS_ENC_TYPE_TKIP:
		auth_ret = RTW_SECURITY_WPA_TKIP_PSK;
		break;
	case AWSS_ENC_TYPE_AES:
	case AWSS_ENC_TYPE_TKIPAES:
		auth_ret = RTW_SECURITY_WPA2_AES_PSK;
		break;
	case AWSS_ENC_TYPE_INVALID:
	default:
		alink_printf(ALINK_INFO, "unknow security mode!\n");
	}
	return auth_ret;
}

// for getting ap encrypt
static int find_ap_from_scan_buf(char*buf, u32 buflen, char *target_ssid, void *user_data)
{
	rtw_wifi_setting_t *pwifi = (rtw_wifi_setting_t *)user_data;
	int plen = 0;
	
	while(plen < buflen){
		u8 len, ssid_len, security_mode;
		char *ssid;

		// len offset = 0
		len = (int)*(buf + plen);
		// check end
		if(len == 0) break;
		// ssid offset = 14
		ssid_len = len - 14;
		ssid = buf + plen + 14 ;
		if((ssid_len == strlen(target_ssid))
			&& (!memcmp(ssid, target_ssid, ssid_len)))
		{
			strcpy((char*)pwifi->ssid, target_ssid);
			// channel offset = 13
			pwifi->channel = *(buf + plen + 13);
			// security_mode offset = 11
			security_mode = (u8)*(buf + plen + 11);
			if(security_mode == IW_ENCODE_ALG_NONE)
				pwifi->security_type = RTW_SECURITY_OPEN;
			else if(security_mode == IW_ENCODE_ALG_WEP)
				pwifi->security_type = RTW_SECURITY_WEP_PSK;
			else if(security_mode == IW_ENCODE_ALG_CCMP)
				pwifi->security_type = RTW_SECURITY_WPA2_AES_PSK;
			break;
		}
		plen += len;
	}
	return 0;
}

int scan_networks_with_ssid(int (results_handler)(char*buf, u32 buflen, char *ssid, void *user_data), 
		OUT void* user_data, IN u32 scan_buflen, IN char* ssid, IN int ssid_len)
{
	int scan_cnt = 0, add_cnt = 0;
	scan_buf_arg scan_buf;
	int ret;

	scan_buf.buf_len = scan_buflen;
	scan_buf.buf = (char*)pvPortMalloc(scan_buf.buf_len);
	if(!scan_buf.buf){
		alink_err_printf("can't malloc memory(%d)", scan_buf.buf_len);
		return RTW_NOMEM;
	}
	//set ssid
	memset(scan_buf.buf, 0, scan_buf.buf_len);
	memcpy(scan_buf.buf, &ssid_len, sizeof(int));
	memcpy(scan_buf.buf+sizeof(int), ssid, ssid_len);

	//Scan channel	
	if(scan_cnt = (wifi_scan(RTW_SCAN_TYPE_ACTIVE, RTW_BSS_TYPE_ANY, &scan_buf)) < 0){
		alink_err_printf("wifi scan failed !\n");
		ret = RTW_ERROR;
	}else{
		if(NULL == results_handler)
		{
			int plen = 0;
			while(plen < scan_buf.buf_len){
				int len, rssi, ssid_len, i, security_mode;
				int wps_password_id;
				char *mac, *ssid;
				//u8 *security_mode;
				printf("\n\r");
				// len
				len = (int)*(scan_buf.buf + plen);
				printf("len = %d,\t", len);
				// check end
				if(len == 0) break;
				// mac
				mac = scan_buf.buf + plen + 1;
				printf("mac = ");
				for(i=0; i<6; i++)
					printf("%02x ", (u8)*(mac+i));
				printf(",\t");
				// rssi
				rssi = *(int*)(scan_buf.buf + plen + 1 + 6);
				printf(" rssi = %d,\t", rssi);
				// security_mode
				security_mode = (int)*(scan_buf.buf + plen + 1 + 6 + 4);
				switch (security_mode) {
					case IW_ENCODE_ALG_NONE:
						printf("sec = open    ,\t");
						break;
					case IW_ENCODE_ALG_WEP:
						printf("sec = wep     ,\t");
						break;
					case IW_ENCODE_ALG_CCMP:
						printf("sec = wpa/wpa2,\t");
						break;
				}
				// password id
				wps_password_id = (int)*(scan_buf.buf + plen + 1 + 6 + 4 + 1);
				printf("wps password id = %d,\t", wps_password_id);
				
				printf("channel = %d,\t", *(scan_buf.buf + plen + 1 + 6 + 4 + 1 + 1));
				// ssid
				ssid_len = len - 1 - 6 - 4 - 1 - 1 - 1;
				ssid = scan_buf.buf + plen + 1 + 6 + 4 + 1 + 1 + 1;
				printf("ssid = ");
				for(i=0; i<ssid_len; i++)
					printf("%c", *(ssid+i));
				plen += len;
				add_cnt++;
			}
		}
		ret = RTW_SUCCESS;
	}
	if(results_handler)
		results_handler(scan_buf.buf, scan_buf.buf_len, ssid, user_data);
		
	if(scan_buf.buf)
		vPortFree(scan_buf.buf);

	return ret;
}

void get_ap_bssid(IN char * target_ssid, IN int target_ssid_len, OUT u8 wifi_bssid[6])
{
	static u8 tmp_bssid[6] = {0};
	scan_buf_arg scan_buf;
		
	scan_buf.buf_len = 1024;	//1024
	scan_buf.buf = (char*)pvPortMalloc(scan_buf.buf_len);
	if(!scan_buf.buf){
		alink_err_printf("Can't malloc memory\r\n");
		return ;
	}
	//set ssid
	memset(scan_buf.buf, 0, scan_buf.buf_len);
	memcpy(scan_buf.buf, &target_ssid_len, sizeof(int));
	memcpy(scan_buf.buf+sizeof(int), target_ssid, target_ssid_len);
	
	//Scan channel	
	memset(scan_buf.buf, 0, scan_buf.buf_len);
	if((wifi_scan(RTW_SCAN_TYPE_ACTIVE, RTW_BSS_TYPE_ANY, &scan_buf)) < 0){
		alink_err_printf("\n wifi scan failed");
	} else {
		int plen = 0;
		while (plen < scan_buf.buf_len) {
			int len, ssid_len;
			uint8 *mac;
			char *ssid;
			// len offset = 0
			len = (int)*(scan_buf.buf + plen);
			// check end
			if(len == 0) 
				break;
			// mac
			mac = scan_buf.buf + plen + 1;
			// ssid offset = 14
			ssid_len = len - 14;
			ssid = scan_buf.buf + plen + 14 ;
			if((ssid_len == target_ssid_len)
				&& (!memcmp(ssid, target_ssid, ssid_len))) {
				/*copy bssid*/
				memcpy(wifi_bssid, mac, 6);
				memcpy(tmp_bssid, mac, 6);
				alink_printf(ALINK_INFO,"[%s], mac=%02x:%02x:%02x:%02x:%02x:%02x\n", 
						__FUNCTION__, wifi_bssid[0], wifi_bssid[1], wifi_bssid[2], wifi_bssid[3], wifi_bssid[4], wifi_bssid[5]);
				goto Exit;
			} 
			plen += len;
		}
		if (tmp_bssid[0] != 0) {
			wifi_bssid[0] = tmp_bssid[0];
			wifi_bssid[1] = tmp_bssid[1];
			wifi_bssid[2] = tmp_bssid[2];
			wifi_bssid[3] = tmp_bssid[3];
			wifi_bssid[4] = tmp_bssid[4];
			wifi_bssid[5] = tmp_bssid[5];
		}
		alink_printf(ALINK_INFO, "[%s]: get BSSID failed, set dafault MAC\n", __FUNCTION__);
	}
	alink_printf(ALINK_INFO,"[%s], tmp_bssid=%02x:%02x:%02x:%02x:%02x:%02x\n", 
			__FUNCTION__, tmp_bssid[0], tmp_bssid[1], tmp_bssid[2], tmp_bssid[3], tmp_bssid[4], tmp_bssid[5]);
Exit:
	if(scan_buf.buf)
		vPortFree(scan_buf.buf);
}

int get_ap_security_mode(IN char * ssid, OUT rtw_security_t *security_mode, OUT u8 * channel)
{
	rtw_wifi_setting_t wifi;
	u32 scan_buflen = 1000;

	memset(&wifi, 0, sizeof(wifi));

	if(scan_networks_with_ssid(find_ap_from_scan_buf, (void*)&wifi, scan_buflen, ssid, strlen(ssid)) != RTW_SUCCESS){
		alink_err_printf("get ap security mode failed!");
		return -1;
	}

	if(strcmp(wifi.ssid, ssid) == 0){
		*security_mode = wifi.security_type;
		*channel = wifi.channel;
		return 0;
	}

	return 0;
}

int rtl_check_ap_mode() 
{
	int mode;
	//Check if in AP mode
	wext_get_mode(WLAN0_NAME, &mode);

	if(mode == IW_MODE_MASTER) {
#if CONFIG_LWIP_LAYER
		dhcps_deinit();
#endif
		wifi_off();
		vTaskDelay(20);
		if (wifi_on(RTW_MODE_STA) < 0){
			alink_err_printf("Wifi on failed!Do zconfig reset!");
			platform_sys_reboot();
		}
	}
	return 0;
}

#if !(CONFIG_EXAMPLE_WLAN_FAST_CONNECT == 1)
void rtl_var_init()
{
	memset(&wifi_config, 0 , sizeof(rtw_wifi_setting_t));
	wifi_config.security_type = RTW_SECURITY_UNKNOWN;
}

void rtl_restore_wifi_info_to_flash()
{
	struct wlan_fast_reconnect * data_to_flash;
	data_to_flash = (struct wlan_fast_reconnect *)pvPortMalloc(sizeof(struct wlan_fast_reconnect));
		/*clean wifi ssid,key and bssid*/
	memset(data_to_flash, 0,sizeof(struct wlan_fast_reconnect));
	if(data_to_flash) {
		memcpy(data_to_flash->psk_essid, wifi_config.ssid, strlen(wifi_config.ssid));
		data_to_flash->psk_essid[strlen(wifi_config.ssid)] = '\0';
		memcpy(data_to_flash->psk_passphrase, wifi_config.password, strlen(wifi_config.password));	
		data_to_flash->psk_passphrase[strlen(wifi_config.password)] = '\0';
		if (wifi_config.channel> 0 && wifi_config.channel < 14) {
			data_to_flash->channel = (uint32_t)wifi_config.channel;
		} else {
			data_to_flash->channel = -1;
		}
		alink_printf(ALINK_INFO, "write wifi info to flash,: ssid = %s, pwd = %s,ssid length = %d, pwd length = %d, channel = %d, security =%d\n",
			       wifi_config.ssid, wifi_config.password, strlen(wifi_config.ssid), strlen(wifi_config.password), data_to_flash->channel, wifi_config.security_type);
		data_to_flash->security_type = wifi_config.security_type;
	}
	wlan_wrtie_reconnect_data_to_flash((u8 *)data_to_flash, sizeof(struct wlan_fast_reconnect));
	if(data_to_flash) {
		vPortFree(data_to_flash);
	}
}
#endif

int platform_awss_connect_ap(
        _IN_ uint32_t connection_timeout_ms,
        _IN_ char ssid[PLATFORM_MAX_SSID_LEN],
        _IN_ char passwd[PLATFORM_MAX_PASSWD_LEN],
        _IN_OPT_ enum AWSS_AUTH_TYPE auth,
        _IN_OPT_ enum AWSS_ENC_TYPE encry,
        _IN_OPT_ uint8_t bssid[ETH_ALEN],
        _IN_OPT_ uint8_t channel)
{
	alink_printf(ALINK_INFO, "[%s], ssid: %s, pwd: %s, channel: %d, auth: %d, encry: %d, BSSID: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
		__func__, ssid, passwd, channel, auth, encry, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
	u8 *ifname[2] = {WLAN0_NAME,WLAN1_NAME};
	rtw_wifi_setting_t setting;
	rtw_network_info_t wifi_info;
	memset(&wifi_info, 0 , sizeof(rtw_network_info_t));
	int ret;
	u8 pschannel = channel;
	int retry_connect = 0;
	
	memcpy(wifi_config.password, passwd, strlen(passwd));
	memcpy(wifi_config.ssid, ssid, strlen(ssid));

	rtl_check_ap_mode();

#if CONFIG_AUTO_RECONNECT
	wifi_set_autoreconnect(1);
#endif
	wifi_disable_powersave();//add to close powersave
	if (wifi_is_ready_to_transceive(RTW_STA_INTERFACE) == RTW_SUCCESS) {
		LwIP_DHCP(0, DHCP_RELEASE_IP);
		LwIP_DHCP(0, DHCP_STOP);
		vTaskDelay(10);
		fATWD(NULL);
		vTaskDelay(20);
		alink_printf(ALINK_INFO, "[%s], disconnect first\n", __FUNCTION__);
	}

  	wifi_info.password_len = strlen(passwd);
	wifi_info.ssid.len = strlen(ssid);
	memcpy(wifi_info.ssid.val, ssid, strlen(ssid));
	memset(wifi_info.bssid.octet, 0, sizeof(wifi_info.bssid.octet));
	wifi_info.password = (unsigned char *)passwd;
	
	ret = auth_trans(encry);
	if (ret >= 0) {
		wifi_config.security_type = (rtw_security_t)ret;
		wifi_info.security_type = wifi_config.security_type;
	} else {
		if(get_ap_security_mode((char*)wifi_info.ssid.val, &wifi_info.security_type, &pschannel) != 0) {
			pschannel = 0;
			wifi_info.security_type = RTW_SECURITY_WPA2_AES_PSK;
			wifi_config.security_type = wifi_info.security_type;
			alink_printf(ALINK_WARNING, "Warning : unknow security type, default set to WPA2_AES");
		} else {
			wifi_config.security_type = wifi_info.security_type;
		}
	}
	if (wifi_info.security_type == RTW_SECURITY_WEP_PSK) {
		if(wifi_info.password_len == 10) {
			u32 p[5];
			u8 pwd[6], i = 0; 
			sscanf((const char*)wifi_info.password, "%02x%02x%02x%02x%02x", &p[0], &p[1], &p[2], &p[3], &p[4]);
			for(i=0; i< 5; i++)
				pwd[i] = (u8)p[i];
			pwd[5] = '\0';
			memset(wifi_info.password, 0, 33);
			strcpy((char*)wifi_info.password, (char const*)pwd);
		} else if (wifi_info.password_len == 26) {
			u32 p[13];
			u8 pwd[14], i = 0;
			sscanf((const char*)wifi_info.password, "%02x%02x%02x%02x%02x%02x%02x"\
				"%02x%02x%02x%02x%02x%02x", &p[0], &p[1], &p[2], &p[3], &p[4],\
				&p[5], &p[6], &p[7], &p[8], &p[9], &p[10], &p[11], &p[12]);
			for(i=0; i< 13; i++)
				pwd[i] = (u8)p[i];
			pwd[13] = '\0';
			memset(wifi_info.password, 0, 33);
			strcpy((char*)wifi_info.password, (char const*)pwd);
		}
		memset(wifi_config.password, 0, 65);
		memcpy(wifi_config.password, wifi_info.password, strlen(wifi_info.password));
	}
	unsigned long tick1 = xTaskGetTickCount();
	unsigned long tick2 = 0;
	unsigned long tick3 = 0;
	while (tick2 < connection_timeout_ms) {
		u8 pscan_config = PSCAN_ENABLE;
		if(pschannel > 0 && pschannel < 14) {
			if(wifi_set_pscan_chan(&pschannel, &pscan_config, 1) < 0) {
				alink_printf(ALINK_WARNING, "wifi set partial scan channel fail\n");
			}	
		} 
		if ((bssid[0] == 0 && bssid[1] == 0 &&
			bssid[2] == 0 && bssid[3] == 0 &&
			bssid[4] == 0 && bssid[5] == 0) || (retry_connect > 1) || (bssid == NULL)) {
			alink_printf(ALINK_INFO, "wifi_connect....\n");
			ret = wifi_connect((char*)wifi_info.ssid.val, 
						wifi_info.security_type, 
						(char*)wifi_info.password, 
						wifi_info.ssid.len, 
						wifi_info.password_len,
						0,
						NULL);
		} else {
			alink_printf(ALINK_INFO, "wifi_connect_bssid....\n");
			ret = wifi_connect_bssid(bssid,
						(char*)wifi_info.ssid.val,  
						wifi_info.security_type, 
						(char*)wifi_info.password,  
						6,
						wifi_info.ssid.len, 
						wifi_info.password_len,
						0,
						NULL);
			retry_connect++;
		}
		if (ret == 0) {
			ret = LwIP_DHCP(0, DHCP_START);
			int i = 0;
			for(i=0;i<NET_IF_NUM;i++){
				if(rltk_wlan_running(i)){
					wifi_get_setting((const char*)ifname[i],&setting);
				}
			}
			wifi_config.channel = setting.channel;
			tick3 = xTaskGetTickCount();
			alink_printf(ALINK_INFO, "Connect ok, time consuming: %d ms\n", tick3 - tick1);
#if !(CONFIG_EXAMPLE_WLAN_FAST_CONNECT == 1)
			rtl_restore_wifi_info_to_flash();
#endif
			return 0;
		}
		platform_msleep(200);
		if (retry_connect >1) {
			if(get_ap_security_mode((char*)wifi_info.ssid.val, &wifi_info.security_type, &pschannel) != 0) {
					pschannel = 0;
					wifi_info.security_type = RTW_SECURITY_WPA2_AES_PSK;
					wifi_config.security_type = wifi_info.security_type;
					alink_printf(ALINK_WARNING, "Warning : unknow security type, default set to WPA2_AES");
			} else {
					wifi_config.security_type = wifi_info.security_type;
			}
		}
		tick3 = xTaskGetTickCount();
		tick2 = tick3 - tick1;
	}
	return -1;
}

typedef  struct  _ApList_str  
{  
        char ssid[PLATFORM_MAX_SSID_LEN];
        uint8_t bssid[ETH_ALEN];
        enum AWSS_AUTH_TYPE auth;
        enum AWSS_ENC_TYPE encry;
        uint8_t channel;
        char rssi;
        int is_last_ap;
}ApList_str; 

//store ap list
typedef  struct  _UwtPara_str  
{  
    char ApNum;       //AP number
    ApList_str * ApList; 
} UwtPara_str;  

UwtPara_str apList_t;
platform_wifi_scan_result_cb_t p_handler_scan_result_callback;
#define RTW_WIFI_APLIST_SIZE		40
volatile int apScanCallBackFinished  = 0;

static char security_to_encryption(rtw_security_t security)
{
	char encryption;
	switch(security){
	case RTW_SECURITY_OPEN:
		encryption = AWSS_ENC_TYPE_NONE;
		break;
	case RTW_SECURITY_WEP_PSK:
	case RTW_SECURITY_WEP_SHARED:
		encryption = AWSS_ENC_TYPE_WEP;
		break;
	case RTW_SECURITY_WPA_TKIP_PSK:
	case RTW_SECURITY_WPA2_TKIP_PSK:
		encryption = AWSS_ENC_TYPE_TKIP;
		break;
	case RTW_SECURITY_WPA_AES_PSK:
	case RTW_SECURITY_WPA2_AES_PSK:
		encryption = AWSS_ENC_TYPE_AES;
		break;
	case RTW_SECURITY_WPA2_MIXED_PSK:
		encryption = AWSS_ENC_TYPE_MAX;
		break;
	default:
		encryption = AWSS_ENC_TYPE_INVALID;
		alink_err_printf("unknow security mode!\n");
		break;
	}

	return encryption;
}

static char security_to_auth(rtw_security_t security)
{
	alink_printf(ALINK_DEBUG, "[%s]\n", __func__);
	char auth_ret = -1;
	switch(security){
	case RTW_SECURITY_OPEN:
		auth_ret = AWSS_AUTH_TYPE_OPEN;
		break;
	case RTW_SECURITY_WEP_PSK:
	case RTW_SECURITY_WEP_SHARED:
		auth_ret = AWSS_AUTH_TYPE_SHARED;
		break;
	case RTW_SECURITY_WPA_TKIP_PSK:
	case	RTW_SECURITY_WPA_AES_PSK:
		auth_ret = AWSS_AUTH_TYPE_WPAPSK;
		break;
	case RTW_SECURITY_WPA2_AES_PSK:
	case	RTW_SECURITY_WPA2_TKIP_PSK:
	case	RTW_SECURITY_WPA2_MIXED_PSK:
		auth_ret = AWSS_AUTH_TYPE_WPA2PSK;
		break;
	case RTW_SECURITY_WPA_WPA2_MIXED_PSK:
		auth_ret = AWSS_AUTH_TYPE_MAX;
		break;
	default:
		auth_ret = AWSS_AUTH_TYPE_INVALID;
		alink_err_printf("unknow security mode!\n");
		break;
	}
	return auth_ret;
}

rtw_result_t store_ap_list(char *ssid,
								char *bssid,
								char ssid_len,
								char rssi,
								char channel,
								char encry,
								char auth)
{
	alink_printf(ALINK_DEBUG, "[%s], store ap list\n", __func__);
	int length;
	if(apList_t.ApNum < RTW_WIFI_APLIST_SIZE) {
		if (ssid_len) {
			length =  ((ssid_len+1) > PLATFORM_MAX_SSID_LEN) ? PLATFORM_MAX_SSID_LEN : ssid_len;
			rtw_memcpy(apList_t.ApList[apList_t.ApNum].ssid, ssid, ssid_len);
			apList_t.ApList[apList_t.ApNum].ssid[length] = '\0';
		}
		rtw_memcpy(apList_t.ApList[apList_t.ApNum].bssid, bssid, 6);
		apList_t.ApList[apList_t.ApNum].rssi = rssi;
		apList_t.ApList[apList_t.ApNum].channel = channel;
		apList_t.ApList[apList_t.ApNum].encry = encry;
		apList_t.ApList[apList_t.ApNum].auth = auth;
		apList_t.ApList[apList_t.ApNum].is_last_ap= 0;
		apList_t.ApNum++;
	}
	return RTW_SUCCESS;
}

static rtw_result_t rtl_scan_result_handler(rtw_scan_handler_result_t *malloced_scan_result)
{
	if (malloced_scan_result->scan_complete != RTW_TRUE){
		rtw_scan_result_t* record = &malloced_scan_result->ap_details;
		record->SSID.val[record->SSID.len] = 0; /* Ensure the SSID is null terminated */
		store_ap_list((char*)record->SSID.val,
					(char*)record->BSSID.octet,
					record->SSID.len,
					record->signal_strength,
					record->channel,
					security_to_encryption(record->security),
					security_to_auth(record->security));
	
	} else {
		int i;
		apList_t.ApList[apList_t.ApNum - 1].is_last_ap= 1;
		alink_printf(ALINK_INFO, "[%s] scan ap number: %d\n", __func__, apList_t.ApNum);	
		for(i=0; i<apList_t.ApNum; i++) {
			/*
			alink_printf(ALINK_INFO, "\n\r[%d]: \t%d\t%d\t%d\t%02x:%02x:%02x:%02x:%02x:%02x\t%s", i, 
									apList_t.ApList[i].rssi, 
									apList_t.ApList[i].channel, 
									apList_t.ApList[i].encry, 
									(unsigned char)apList_t.ApList[i].bssid[0],
									(unsigned char)apList_t.ApList[i].bssid[1],
									(unsigned char)apList_t.ApList[i].bssid[2],
									(unsigned char)apList_t.ApList[i].bssid[3],
									(unsigned char)apList_t.ApList[i].bssid[4],
									(unsigned char)apList_t.ApList[i].bssid[5],
									apList_t.ApList[i].ssid);
			*/
			if (NULL != p_handler_scan_result_callback)
				p_handler_scan_result_callback(apList_t.ApList[i].ssid, apList_t.ApList[i].bssid, apList_t.ApList[i].auth, 
					apList_t.ApList[i].encry, apList_t.ApList[i].channel, apList_t.ApList[i].rssi, apList_t.ApList[i].is_last_ap);
		}
		if(apList_t.ApList != NULL) {
			rtw_free(apList_t.ApList);
			apList_t.ApList = NULL;
			apList_t.ApNum = 0;
		}
	}
	apScanCallBackFinished = 1;
	return RTW_SUCCESS;
}

int platform_wifi_scan(platform_wifi_scan_result_cb_t cb)
{
	alink_printf(ALINK_DEBUG, "[%s]\n", __func__);
   	apScanCallBackFinished = 0;

	if(apList_t.ApList) {
		rtw_free(apList_t.ApList);
		apList_t.ApList = NULL;
	}
	apList_t.ApList = (ApList_str *)rtw_zmalloc(RTW_WIFI_APLIST_SIZE * sizeof(ApList_str));
	if(!apList_t.ApList) {
		alink_err_printf(" malloc ap list failed\n");
		return -1;
	}
	apList_t.ApNum = 0;
	p_handler_scan_result_callback = cb;
	wifi_scan_networks(rtl_scan_result_handler, NULL );

	while (0 == apScanCallBackFinished){
		platform_msleep(50);
	}

	return 0;
}

p_aes128_t platform_aes128_init(
    const uint8_t* key,
    const uint8_t* iv,
    AES_DIR_t dir)
{
	alink_printf(ALINK_INFO, "[%s]\n", __FUNCTION__);
//	u_print_data(iv, 16);
//	u_print_data(key, 16);

	aes_content_t *aes_ctx=NULL;
	int u = 0;
//	unsigned char iv_buf[16] ;
	aes_ctx = (aes_content_t *)pvPortMalloc(sizeof(aes_content_t));
	if (aes_ctx == NULL) {
		alink_err_printf("malloc aes_ctx iv_buf failed\n");
		return  NULL;
	} else {
		memset( aes_ctx->iv_buf , 0, IV_BUF_LEN);
		aes_ctx->ctx = init_aes_content();
		if(aes_ctx->ctx == NULL){
			alink_err_printf("malloc aes_ctx ctx failed\n");
			vPortFree(aes_ctx);
			return  NULL;
		}
	}
	alink_aes_init( aes_ctx->ctx );
	if (dir == PLATFORM_AES_ENCRYPTION) {
		alink_aes_setkey_enc( aes_ctx->ctx, key, 128 + u * 64 );
	} else {
		alink_aes_setkey_dec( aes_ctx->ctx, key, 128 + u * 64 );
	}
	
	strncpy(aes_ctx->iv_buf,  iv, IV_BUF_LEN);
	return (p_aes128_t)aes_ctx;

}

int platform_aes128_destroy(
    p_aes128_t aes)
{
	alink_printf(ALINK_DEBUG, "[%s]\n", __FUNCTION__);
	aes_content_t *aes_ctx = (aes_content_t *)aes;
	alink_aes_free(aes_ctx->ctx);
	vPortFree(aes_ctx->ctx);
	vPortFree(aes_ctx);
	return 0;
}

int platform_aes128_cbc_encrypt(
    p_aes128_t aes,
    const void *src,
    size_t blockNum,
    void *dst )
{
	alink_printf(ALINK_INFO, "[%s]\n", __FUNCTION__);
	aes_content_t *aes_ctx = (aes_content_t *)aes;

//	u_print_data(aes_ctx->iv_buf, 16);
//	u_print_data((unsigned char *)src, 64);

	alink_aes_crypt_cbc( aes_ctx->ctx, 1, 16*blockNum, aes_ctx->iv_buf, src, dst );
//	u_print_data((unsigned char *)dst, 64);
	return 0;
}

int platform_aes128_cbc_decrypt(
    p_aes128_t aes,
    const void *src,
    size_t blockNum,
    void *dst )
{
	alink_printf(ALINK_INFO, "[%s] blockNum: %d\n", __FUNCTION__, blockNum);
//	u_print_data((unsigned char *)src, 64);

	aes_content_t *aes_ctx = (aes_content_t *)aes;
	alink_aes_crypt_cbc( aes_ctx->ctx, 0, 16*blockNum, aes_ctx->iv_buf, src, dst );
//	u_print_data((unsigned char *)dst, 64);

	return 0;
}

int platform_wifi_get_ap_info(
    char ssid[PLATFORM_MAX_SSID_LEN],
    char passwd[PLATFORM_MAX_PASSWD_LEN],
    uint8_t bssid[ETH_ALEN])
{
	u8 *ifname[2] = {WLAN0_NAME,WLAN1_NAME};
	rtw_wifi_setting_t wifi_setting;
	static int tmp = 0;
	int i = 0;

	if (wifi_is_ready_to_transceive(RTW_STA_INTERFACE) == RTW_SUCCESS) {
		for(i=0; i<NET_IF_NUM; i++){
			if(rltk_wlan_running(i)){
				wifi_get_setting((const char*)ifname[i],&wifi_setting);
			}
		}
		memcpy(ssid, wifi_setting.ssid, strlen((char*)wifi_setting.ssid));
		memcpy(passwd, wifi_setting.password, strlen((char*)wifi_setting.password));
		if ((ssid != NULL) && (passwd != NULL) && (bssid != NULL)) {
			get_ap_bssid(wifi_setting.ssid,  strlen((char*)wifi_setting.ssid), bssid);
			alink_printf(ALINK_INFO,"[%s], [%s], [%s], mac=%02x:%02x:%02x:%02x:%02x:%02x\n", 
						__FUNCTION__, ssid, passwd, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
		}
	} else {
		if (tmp % 100 == 0) {
			tmp = 0;
			alink_printf(ALINK_INFO, "[%s], disconnect with AP.", __FUNCTION__);
		} 		
		tmp++;
		return -1;
	}
	
	return 0;
}


int platform_wifi_low_power(int timeout_ms)
{
	alink_printf(ALINK_INFO, "[%s]\n", __FUNCTION__);
	rtl_check_ap_mode();
	wifi_enable_powersave();
	platform_msleep(timeout_ms);
	wifi_disable_powersave();
   	return 0;
}

/*
      frame_type:
            bit0--beacon, bit1--probe request, bit2--probe response
      ie:
            vendor specific ie
      ie_len:
            ie struct len
      callback:
            wifi驱动监听到符合oui, oui_type的特定管理帧(frame_type指定)
后，通过该回调函数通知应用层
*/

//int (*g_vendor_mgnt_filter_callback)(const u8 *ie, char *ie_len, int frame_type) = 0;
platform_wifi_mgnt_frame_cb_t g_vendor_mgnt_filter_callback;

extern int (*p_wlan_mgmt_filter)(u8 *ie, u16 ie_len, u16 frame_type);
//management_frame_callback *g_vendor_mgnt_filter_callback;
unsigned int g_vendor_oui = 0;
uint32_t g_vendor_frame_type = 0;

#ifndef BIT
#define BIT(n)                   (1<<n)
#endif

enum WIFI_FRAME_TYPE {
	WIFI_MGT_TYPE  =	(0),
	WIFI_CTRL_TYPE =	(BIT(2)),
	WIFI_DATA_TYPE =	(BIT(3)),
	WIFI_QOS_DATA_TYPE	= (BIT(7)|BIT(3)),	//!< QoS Data	
};

enum WIFI_FRAME_SUBTYPE {

    // below is for mgt frame
    WIFI_ASSOCREQ       = (0 | WIFI_MGT_TYPE),
    WIFI_ASSOCRSP       = (BIT(4) | WIFI_MGT_TYPE),
    WIFI_REASSOCREQ     = (BIT(5) | WIFI_MGT_TYPE),
    WIFI_REASSOCRSP     = (BIT(5) | BIT(4) | WIFI_MGT_TYPE),
    WIFI_PROBEREQ       = (BIT(6) | WIFI_MGT_TYPE),
    WIFI_PROBERSP       = (BIT(6) | BIT(4) | WIFI_MGT_TYPE),
    WIFI_BEACON         = (BIT(7) | WIFI_MGT_TYPE),
    WIFI_ATIM           = (BIT(7) | BIT(4) | WIFI_MGT_TYPE),
    WIFI_DISASSOC       = (BIT(7) | BIT(5) | WIFI_MGT_TYPE),
    WIFI_AUTH           = (BIT(7) | BIT(5) | BIT(4) | WIFI_MGT_TYPE),
    WIFI_DEAUTH         = (BIT(7) | BIT(6) | WIFI_MGT_TYPE),
    WIFI_ACTION         = (BIT(7) | BIT(6) | BIT(4) | WIFI_MGT_TYPE),

    // below is for control frame
    WIFI_PSPOLL         = (BIT(7) | BIT(5) | WIFI_CTRL_TYPE),
    WIFI_RTS            = (BIT(7) | BIT(5) | BIT(4) | WIFI_CTRL_TYPE),
    WIFI_CTS            = (BIT(7) | BIT(6) | WIFI_CTRL_TYPE),
    WIFI_ACK            = (BIT(7) | BIT(6) | BIT(4) | WIFI_CTRL_TYPE),
    WIFI_CFEND          = (BIT(7) | BIT(6) | BIT(5) | WIFI_CTRL_TYPE),
    WIFI_CFEND_CFACK    = (BIT(7) | BIT(6) | BIT(5) | BIT(4) | WIFI_CTRL_TYPE),

    // below is for data frame
    WIFI_DATA           = (0 | WIFI_DATA_TYPE),
    WIFI_DATA_CFACK     = (BIT(4) | WIFI_DATA_TYPE),
    WIFI_DATA_CFPOLL    = (BIT(5) | WIFI_DATA_TYPE),
    WIFI_DATA_CFACKPOLL = (BIT(5) | BIT(4) | WIFI_DATA_TYPE),
    WIFI_DATA_NULL      = (BIT(6) | WIFI_DATA_TYPE),
    WIFI_CF_ACK         = (BIT(6) | BIT(4) | WIFI_DATA_TYPE),
    WIFI_CF_POLL        = (BIT(6) | BIT(5) | WIFI_DATA_TYPE),
    WIFI_CF_ACKPOLL     = (BIT(6) | BIT(5) | BIT(4) | WIFI_DATA_TYPE),
    WIFI_QOS_DATA_NULL	= (BIT(6) | WIFI_QOS_DATA_TYPE),
};


/* Parsed Information Elements */
struct i802_11_elems {
	u8 *ie;
	u8 len;
};

/* Information Element IDs */
#define WLAN_EID_VENDOR_SPECIFIC 221

static int parse_vendor_specific(u8 *pos, u8 elen,  struct i802_11_elems *elems)
{
	alink_printf(ALINK_DEBUG, "[%s]\n", __FUNCTION__);
	unsigned int oui;
	int ret = -1;

	/* first 3 bytes in vendor specific information element are the IEEE
	 * OUI of the vendor. The following byte is used a vendor specific
	 * sub-type. */
	if (elen < 4) {
		return ret;
	}
	
	oui = WPA_GET_BE24(pos);
	if ( g_vendor_oui == oui ) {
		elems->ie = pos;
		elems->len = elen;
		ret = 0;
		alink_printf(ALINK_DEBUG, "oui = %x\n", oui);
	}
	
	return ret;
}

int wlan_mgmt_filter(u8 *start, u16 len, u16 frame_type)
{
//	alink_printf(ALINK_DEBUG, "[%s]\n", __FUNCTION__);

//type 0xDD
	/*bit0--beacon, bit1--probe request, bit2--probe response*/
	int alink_frame_type = 0;
	int value_find= -1;
	struct i802_11_elems elems;
	elems.ie = NULL;
	elems.len = len;
	
	switch (frame_type) {
		 case WIFI_BEACON:
		 	alink_frame_type = BIT(1);
			break;
		case WIFI_PROBEREQ:
			alink_frame_type = BIT(2);
			alink_printf(ALINK_DEBUG,"g_vendor_frame_type: %d, frame_type: %d\n", g_vendor_frame_type, alink_frame_type);
			break;
		case WIFI_PROBERSP:
			alink_frame_type = BIT(3);
			break;
		default:
			printf("Unsupport  management frames\n");
			return -1;
	}
//	unsigned int vendor_oui = 0;
//	vendor_oui = WPA_GET_BE24(ie);
	if (g_vendor_frame_type & (uint32_t)alink_frame_type) {
		u8 *pos = start;
		u8 id, elen;
		while (len >=  2) {
			id = *pos++;
			elen = *pos++;
			len -= 2;
			if (elen > len) {
				return -1;
			}
	//		printf("%s(): id = %d\n", __FUNCTION__, id);
			if (id == WLAN_EID_VENDOR_SPECIFIC) {
				value_find = parse_vendor_specific(pos, elen, &elems);
				if (value_find == 0) {
					pos = pos - 2;
					if (g_vendor_mgnt_filter_callback) {
//						u_print_data((unsigned char *)pos, elems.len+2);
						g_vendor_mgnt_filter_callback((uint8_t *)pos, elems.len+2, 0, 1);
						return 0;
					}
				}
			}
			len -= elen;
			pos += elen;		
			
		}
	}
	
	return -1;
}

int platform_wifi_enable_mgnt_frame_filter(
            _IN_ uint32_t filter_mask,
            _IN_OPT_ uint8_t vendor_oui[3],
            _IN_ platform_wifi_mgnt_frame_cb_t callback)
{
	g_vendor_oui = WPA_GET_BE24(vendor_oui);
	g_vendor_frame_type = (int) filter_mask;
	g_vendor_mgnt_filter_callback = callback;
	alink_printf(ALINK_DEBUG, "[%s], oui = %x, frame_type = %o\n", __FUNCTION__, g_vendor_oui, filter_mask);
	if (callback) {
		p_wlan_mgmt_filter = wlan_mgmt_filter;
	} else {
		p_wlan_mgmt_filter = 0;
		return -1;
	}
   	return 0;
}

int platform_wifi_send_80211_raw_frame(_IN_ enum platform_awss_frame_type type,
        _IN_ uint8_t *buffer, _IN_ int len)
{
	int ret = -2;
	const char *ifname = WLAN0_NAME;
	if (type == FRAME_BEACON || type == FRAME_PROBE_REQ) {
		ret = wext_send_mgnt(ifname, (char*)buffer, len, 1);
	}
	alink_printf(ALINK_DEBUG, "[%s] ret = %d type = %d\n", __FUNCTION__, ret, type);
//        u_print_data((unsigned char *)buffer, len);
	return ret;
}

