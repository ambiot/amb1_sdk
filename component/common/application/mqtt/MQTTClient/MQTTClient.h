 /**
  ******************************************************************************
  * @file    MQTTClient.h
  * @author
  * @version
  * @brief   This file provides user interface for MQTT client.
  ******************************************************************************
  * @attention
  *
  * This module is a confidential and proprietary property of RealTek and possession or use of this module requires written permission of RealTek.
  *
  * Copyright(c) 2016, Realtek Semiconductor Corporation. All rights reserved.
  ****************************************************************************** 
  */
#if !defined(__MQTT_CLIENT_C_)
#define __MQTT_CLIENT_C_

/** @addtogroup mqtt       MQTT
 *  @ingroup    network
 *  @brief      MQTT client functions
 *  @{
 */

#if defined(__cplusplus)
 extern "C" {
#endif

#if defined(WIN32_DLL) || defined(WIN64_DLL)
  #define DLLImport __declspec(dllimport)
  #define DLLExport __declspec(dllexport)
#elif defined(LINUX_SO)
  #define DLLImport extern
  #define DLLExport  __attribute__ ((visibility ("default")))
#else
  #define DLLImport
  #define DLLExport
#endif

#include "../MQTTPacket/MQTTPacket.h"
#include "stdio.h"
#include "MQTTFreertos.h"

#define MQTT_TASK
#if !defined(MQTT_TASK)
#define WAIT_FOR_ACK
#endif

#define MQTT_SENDBUF_LEN  1024
#define MQTT_READBUF_LEN  1024

enum mqtt_status{
	MQTT_START       = 0,
	MQTT_CONNECT  = 1,
	MQTT_SUBTOPIC = 2,
	MQTT_RUNNING  = 3
};

#if defined(MQTTCLIENT_PLATFORM_HEADER)
/* The following sequence of macros converts the MQTTCLIENT_PLATFORM_HEADER value
 * into a string constant suitable for use with include.
 */
#define xstr(s) str(s)
#define str(s) #s
#include xstr(MQTTCLIENT_PLATFORM_HEADER)
#endif

#define MAX_PACKET_ID 65535 /* according to the MQTT specification - do not change! */

#if !defined(MAX_MESSAGE_HANDLERS)
#define MAX_MESSAGE_HANDLERS 5 /* redefinable - how many subscriptions do you want? */
#endif

enum QoS { QOS0, QOS1, QOS2 };

/* all failure return codes must be negative */
enum returnCode { BUFFER_OVERFLOW = -2, FAILURE = -1 };//, SUCCESS = 0

/* The Platform specific header must define the Network and Timer structures and functions
 * which operate on them.
 *
typedef struct Network
{
	int (*mqttread)(Network*, unsigned char* read_buffer, int, int);
	int (*mqttwrite)(Network*, unsigned char* send_buffer, int, int);
} Network;*/

/* The Timer structure must be defined in the platform specific header,
 * and have the following functions to operate on it.  */
extern void TimerInit(Timer*);
extern char TimerIsExpired(Timer*);
extern void TimerCountdownMS(Timer*, unsigned int);
extern void TimerCountdown(Timer*, unsigned int);
extern int TimerLeftMS(Timer*);

typedef struct MQTTMessage
{
    enum QoS qos;
    unsigned char retained;
    unsigned char dup;
    unsigned short id;
    void *payload;
    size_t payloadlen;
} MQTTMessage;

typedef struct MessageData
{
    MQTTMessage* message;
    MQTTString* topicName;
} MessageData;

typedef void (*messageHandler)(MessageData*);

typedef struct MQTTClient
{
    unsigned int next_packetid,
      command_timeout_ms;
    size_t buf_size,
      readbuf_size;
    unsigned char *buf,
      *readbuf;
    unsigned int keepAliveInterval;
    char ping_outstanding;
    int isconnected;

    struct MessageHandlers
    {
        const char* topicFilter;
        void (*fp) (MessageData*);
    } messageHandlers[MAX_MESSAGE_HANDLERS];      /* Message handlers are indexed by subscription topic */

    void (*defaultMessageHandler) (MessageData*);

    Network* ipstack;
    Timer ping_timer;

    Timer cmd_timer;
    int mqttstatus;
} MQTTClient;

#define DefaultClient {0, 0, 0, 0, NULL, NULL, 0, 0, 0}


/**
 * @brief   Create an MQTT client object
 * @param   client             : The context of MQTT client
 * @param   network            : The Network context
 * @param   command_timeout_ms : The command timeout of MQTT
 * @param   sendbuf            : The array of MQTT send buffer
 * @param   sendbuf_size       : The size of send buffer
 * @param   readbuf            : The array of MQTT receive buffer
 * @param   readbuf_size       : The size of receive buffer
 * @return  none
 */
DLLExport void MQTTClientInit(MQTTClient* client, Network* network, unsigned int command_timeout_ms,
		unsigned char* sendbuf, size_t sendbuf_size, unsigned char* readbuf, size_t readbuf_size);

/** 
 * @brief   Send an MQTT connect packet down the network and wait for a Connack
 *          The nework object must be connected to the network endpoint before calling this function
 * @param   client  c
 * @param   options : The connect options of MQTT
 * @return   0      : success   
 *          -1      : failed 
 */
DLLExport int MQTTConnect(MQTTClient* client, MQTTPacket_connectData* options);

/** 
 * @brief   Send an MQTT publish packet and wait for all acks to complete for all QoSs
 * @param   client  : The context of MQTT client
 * @param   topic   : The MQTT topic to publish
 * @param   message : The message to send
 * @return   0      : success   
 *          -1      : failed 
 */
DLLExport int MQTTPublish(MQTTClient* client, const char*, MQTTMessage*);

/** 
 * @brief   Send an MQTT subscribe packet and wait for suback before returning.
 * @param   client         : The context of MQTT client
 * @param   topicFilter    : The topic filter to subscribe
 * @param   QoS            : The MQTT QOS value
 * @param   messageHandler : The MQTT message handler
 * @return   0      : success   
 *          -1      : failed 
 */
DLLExport int MQTTSubscribe(MQTTClient* client, const char* topicFilter, enum QoS, messageHandler);

/** 
 * @brief   Send an MQTT unsubscribe packet and wait for unsuback before returning.
 * @param   client         : The context of MQTT client
 * @param   topicFilter    : The topic filter to unsubscribe
 * @return   0      : success   
 *          -1      : failed 
 */
DLLExport int MQTTUnsubscribe(MQTTClient* client, const char* topicFilter);

/**
 * @brief    Send an MQTT disconnect packet and close the connection
 * @param    client : The context of MQTT client
 * @return   0      : success   
 *          -1      : failed 
 */
DLLExport int MQTTDisconnect(MQTTClient* client);

/** 
 * @brief   MQTT receive packet background function
 * @param   client  : The context of MQTT client
 * @param   time    : The timeout of receive MQTT packets, in milliseconds
 * @return   0      : success   
 *          -1      : failed 
 */
DLLExport int MQTTYield(MQTTClient* client, int time);

#if defined(MQTT_TASK)
void MQTTSetStatus(MQTTClient* c, int mqttstatus);
int MQTTDataHandle(MQTTClient* c, fd_set *readfd, MQTTPacket_connectData *connectData, messageHandler messageHandler, char* address, int port, char* topic);
#endif

#if defined(__cplusplus)
     }
#endif

/*\@}*/

#endif
