#include <FreeRTOS.h>
#include <task.h>
#include <platform/platform_stdlib.h>
#include <httpc/httpc.h>
#include <string.h>
#include <stdlib.h>
#include <device_lock.h>
#include <sntp/sntp.h>
#include <hal_crypto.h>
#include <cjson.h>
#include <osdep_service.h>
#include <stdio.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>

#define TEXT_TXT				1
#define IMAGE_JPG				2

/* Set download server parameters */
#define DL_File_TYPE			IMAGE_JPG  //download file format (TEXT_TXT , IMAGE_JPG)
#define DL_SERVER_HOST    		"192.168.0.101"  //download server host address
#define DL_SERVER_PORT    		8082  //download server port number
#define BUFFER_SIZE    			2048  //download buffer size
#define RECV_TO        			5000  //receive timeout in ms

/* Show information for debugging */
#define SHOW_INFO				1
#define SHOW_PROGRESS			1

/* Set file to be downloaded and saved as */
#define DL_RESOURCE       		"test_image.jpg"  //file in download server
#define S3_RESOURCE 			"S3_image.jpg" //file name and format that will be shown in S3 server

/* Set Security Credentials */
#define SESSION_TOKEN			0
#if SESSION_TOKEN
//temporary security credentials 
#define S3_KEY_ID 				"AFIA3AVW256YUEXAMPLE"
#define S3_KEY_SECRET 			"trwieEhsWFqauERw4BkNg13Z9RJ0S1qSoEXAMPLE"
#define S3_SESSION_TOKEN		"FQoGZXIvYEXAMPLE//////////wEaDBcEXAMPLEhozDHTCLwARX2vPunHUXXUv9OXsS+EXAMPLEWBDglFSpxLaf7eY6ywzgIsxYTcq09mXeWtwSYfbvc8BHEXAMPLEdq9F3udTY8dxBfvA1BzJj50P59pRabkkLZzBvrs8yjmpbiXcBOJM9C+EXAMPLE8/XpO4E6AAjLBsZOeUPfYDZ9tbkWyV9+TYV/xohD1dDKI555Mrd7y7t/mwLOD79w7EXAMPLEhZXO8LmpE8hDw+zrOc2QZmgIeVqbCF0MCQv8IGe03RdGwlBb+Y1zBnmA0vlEXAMPLEZaK8cmEzrGsR/+DeW2Fsm/EmvFS2SKikq2GGEXAMPLEQ=="
#define ADD_IN_FORM_FIELD		1
#define ADD_IN_POLICY			1
#define ADD_IN_REQUEST_HEADER	1
#else
//long-term credentials
#define S3_KEY_ID 				"AKIAJWHJCGO5OEXAMPLE" 	
#define S3_KEY_SECRET 			"PBVQIwZVy3kDjZPcnLeemnYJ2MPgtV9FOEXAMPLE"
#define ADD_IN_FORM_FIELD		0
#define ADD_IN_POLICY			0
#define ADD_IN_REQUEST_HEADER	0
#endif

/* Set S3 server parameters */
#define UPLOAD_METHOD  			"POST"
#define S3_BUCKET 				"bucket_name"
#define S3_KEY 					"AWS "
#define S3_REGION 				"ap-southeast-1"
#define S3_SERVICE 				"s3"
#define S3_SERVER_HOST			S3_BUCKET"."S3_SERVICE"-"S3_REGION".amazonaws.com"
#define S3_PORT					"443"
#define S3_POLICY_EXPIRATION	"2020-07-30T12:00:00.000Z" //policy expriation time
#define S3_ALGORITHM			"AWS4-HMAC-SHA256"
#define S3_ACL					"public-read-write"
#define HTTP_CRLF    			"\r\n"

#if (DL_File_TYPE == 1)
#define CONTENT_TYPE 			"text/txt"
#elif (DL_File_TYPE == 2)
#define CONTENT_TYPE 			"image/jpeg"
#endif

typedef struct {
	u8 *s3_expiration;
	u8 *bucket;
	u8 *s3_key;
	u8 *s3_acl;
	u8 *content_type;
	u8 *x_amz_meta_tag;
	u8 *x_amz_crd;
	u8 *x_amz_alg;
	u8 *x_amz_date;
#if ADD_IN_POLICY	
	u8 *x_amz_security_token;
#endif
}policy;

/* Generate random number for 'boundary' */
extern int rtw_get_random_bytes(void* dst, u32 size);

/* Generate post policy */
char * generate_s3_policy(policy policy_element)
{
	cJSON_Hooks memoryHook;
	memoryHook.malloc_fn = malloc;
	memoryHook.free_fn = free;
	cJSON_InitHooks(&memoryHook);
	char *policy = NULL;
	cJSON *object = NULL;
	cJSON *s3_conditions = NULL;
	cJSON *try_conditions = NULL;
	cJSON *s3_bucket = NULL;
	cJSON *key_sw = NULL;
	cJSON *s3_acl_obj = NULL;
	cJSON *cont_type_sw = NULL;
	cJSON *meta_tag_sw = NULL;
	cJSON *amz_crd = NULL;
	cJSON *amz_alg = NULL;
	cJSON *amz_date = NULL;
#if ADD_IN_POLICY
	cJSON *amz_security_token = NULL;
#endif

	if((object = cJSON_CreateObject()) != NULL) {
		cJSON_AddItemToObject(object, "expiration", cJSON_CreateString(policy_element.s3_expiration));
		cJSON_AddItemToObject(object, "conditions", s3_conditions = cJSON_CreateArray());
		cJSON_AddItemToArray(s3_conditions, s3_bucket = cJSON_CreateObject());
		cJSON_AddItemToObject(s3_bucket, "bucket", cJSON_CreateString(policy_element.bucket));
		cJSON_AddItemToArray(s3_conditions, key_sw = cJSON_CreateArray());
		cJSON_AddItemToArray(key_sw, cJSON_CreateString("starts-with"));
		cJSON_AddItemToArray(key_sw, cJSON_CreateString(policy_element.s3_key));
		cJSON_AddItemToArray(key_sw, cJSON_CreateString(""));
		cJSON_AddItemToArray(s3_conditions, s3_acl_obj  = cJSON_CreateObject());
		cJSON_AddItemToObject(s3_acl_obj , "acl", cJSON_CreateString(policy_element.s3_acl));
		cJSON_AddItemToArray(s3_conditions, cont_type_sw = cJSON_CreateArray());
		cJSON_AddItemToArray(cont_type_sw, cJSON_CreateString("starts-with"));
		cJSON_AddItemToArray(cont_type_sw, cJSON_CreateString(policy_element.content_type));
#if (DL_File_TYPE == 1)
		cJSON_AddItemToArray(cont_type_sw, cJSON_CreateString("text/"));
#elif (DL_File_TYPE == 2)
		cJSON_AddItemToArray(cont_type_sw, cJSON_CreateString("image/"));
#endif
		cJSON_AddItemToArray(s3_conditions, meta_tag_sw = cJSON_CreateArray());
		cJSON_AddItemToArray(meta_tag_sw, cJSON_CreateString("starts-with"));
		cJSON_AddItemToArray(meta_tag_sw, cJSON_CreateString(policy_element.x_amz_meta_tag));
		cJSON_AddItemToArray(meta_tag_sw, cJSON_CreateString(""));
		cJSON_AddItemToArray(s3_conditions, amz_crd = cJSON_CreateObject());
		cJSON_AddItemToObject(amz_crd, "x-amz-credential", cJSON_CreateString(policy_element.x_amz_crd));
		cJSON_AddItemToArray(s3_conditions, amz_alg = cJSON_CreateObject());
		cJSON_AddItemToObject(amz_alg, "x-amz-algorithm", cJSON_CreateString(policy_element.x_amz_alg));
		cJSON_AddItemToArray(s3_conditions, amz_date = cJSON_CreateObject());
		cJSON_AddItemToObject(amz_date, "x-amz-date", cJSON_CreateString(policy_element.x_amz_date));
#if ADD_IN_POLICY
		cJSON_AddItemToArray(s3_conditions, amz_security_token = cJSON_CreateObject());
		cJSON_AddItemToObject(amz_security_token, "x-amz-security-token", cJSON_CreateString(policy_element.x_amz_security_token));
#endif
		policy = cJSON_Print(object);
		cJSON_Delete(object);
	}
	return policy;
}

/* Generate html form */
int create_form (u8 *form_content, u8 *boundary, char *form_name, char *form_value, int file_upload)
{
	int strLength=0;
	unsigned int content_disposition_length = 256 + strlen(boundary) + strlen(form_name) + strlen(form_value);
	char *content_disposition = malloc(content_disposition_length);
	
	if(!content_disposition) {
		printf("malloc failed for content_disposition\r\n");
		return -1;
	}
	strLength = 0;
	memset(content_disposition, 0, content_disposition_length);
	memcpy(content_disposition, boundary, strlen(boundary));
	strLength = strlen(boundary);
	memcpy(content_disposition+strLength, HTTP_CRLF, 2);
	strLength += 2;
	memcpy(content_disposition+strLength, "Content-Disposition: form-data; name=\"", 38);
	strLength += 38;
	memcpy(content_disposition+strLength, form_name, strlen(form_name));
	strLength += strlen(form_name);
	
	if(file_upload!=0) {
		memcpy(content_disposition+strLength, "\"; filename=\"", 13);
		strLength += 13;
		memcpy(content_disposition+strLength, form_value, strlen(form_value));
		strLength += strlen(form_value);
		memcpy(content_disposition+strLength, "\"", 1);
		strLength += 1;
		memcpy(content_disposition+strLength, HTTP_CRLF, 2);
		strLength += 2;
		memcpy(content_disposition+strLength, "Content-Type: ", 14);
		strLength += 14;
		memcpy(content_disposition+strLength, CONTENT_TYPE, strlen(CONTENT_TYPE));
		strLength += strlen(CONTENT_TYPE);
	}
	else {
		memcpy(content_disposition+strLength, "\"", 1);
		strLength += 1;
	}
	memcpy(content_disposition+strLength, HTTP_CRLF, 2);
	strLength += 2;
	memcpy(content_disposition+strLength, HTTP_CRLF, 2);
	strLength += 2;
	
	if(file_upload == 0) {
	memcpy(content_disposition+strLength, form_value, strlen(form_value));
	strLength += strlen(form_value);
	memcpy(content_disposition+strLength, HTTP_CRLF, 2);
	strLength += 2;
	}
	memcpy(form_content,content_disposition,strLength);
	free (content_disposition);
	
	return strLength;
}


static void example_s3_upload_thread(void *param)
{
	/* To avoid gcc warnings */
	( void ) param;

	struct httpc_conn *conn = NULL;
	int ret;
	int str_len = 0;
	int form_len = 0;
	int end_b_len = 0;
	u8 *date = NULL;
	u8 *canonical_URI = NULL;
	u8 *stringtosign = NULL;
	u8 *authorization_header = NULL;
	u8* content = NULL;
	u8 file_content_digest[32]={0};
	u8 canonical_request_digest[32]={0};
	u8 datekey_digest[32]={0};
	u8 dateregionkey_digest[32]={0};
	u8 dateregionservicekey_digest[32]={0};
	u8 signingkey_digest[32]={0};
	u8 sha256_signature[32]={0};
	u8 *ISO_hour = NULL;
	u8 *ISO_min = NULL;
	u8 *ISO_sec = NULL;
	u8 *ISO_year = NULL;
	u8 *ISO_mth = NULL;
	u8 *ISO_day = NULL;
	u8 *day_space = NULL;
	u8 *day_num = NULL;
	u8 *s3_daystamp = NULL;
	u8 *s3_timestamp = NULL;
	u8 *s3_credential = NULL;
	u8 *s3_scope = NULL;
	u8 *hex_sha256_file_content = NULL;
	u8 *hex_sha256_canonical_request = NULL;
	u8 *host_header = NULL;
	u8 *content_type_header = NULL;
	u8 *canonical_headers = NULL;
	u8 *x_amz_content_sha256 = NULL; 
	u8 *x_amz_date = NULL;
#if SESSION_TOKEN	
	u8 *x_amz_security_token = NULL;
#endif
	u8 *canonical_request = NULL;
	u8 *datekey_str = NULL;
	u8 *signature = NULL; 
	u8 *payload_content = NULL;
	u8 *boundary = NULL;
	u8 *multipart_datatype = NULL;
	u8 *form_boundary = NULL;
	u8 *end_boundary = NULL;
	char *form_content = NULL;
	char *s3_policy = NULL;
	u8 base64_len = 128;
	u8 base64_hmac_len = 128;
	u8 md5_digest[16] = {0};
	u8 hmac_digest[20] = {0};
	u8 base64_buffer[128] = {0};
	u8 base64_hmac_buffer[128] = {0};
	u8 boundary_buffer[16] = {0}; 
#if SHOW_PROGRESS
	int progress = 0;
	int current_work = 0;
	int dividend = 0;
	int last_rs = 0;
#endif
	int server_fd = -1;
	struct sockaddr_in server_addr;
	struct hostent *server_host;

	// Delay to wait for IP by DHCP
	vTaskDelay(10000);

	printf("\nExample: S3 file upload using HTTP POST (Sig_V4)\n");
	
	if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("ERROR: socket\n");
		goto exit;
	}
	else {
		int recv_timeout_ms = RECV_TO;
#if defined(LWIP_SO_SNDRCVTIMEO_NONSTANDARD) && (LWIP_SO_SNDRCVTIMEO_NONSTANDARD == 0)	// lwip 1.5.0
		struct timeval recv_timeout;
		recv_timeout.tv_sec = recv_timeout_ms / 1000;
		recv_timeout.tv_usec = recv_timeout_ms % 1000 * 1000;
		setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
#else	// lwip 1.4.1
		setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout_ms, sizeof(recv_timeout_ms));
#endif
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DL_SERVER_PORT);

	// Support DL_SERVER_HOST in IP or domain name
	server_host = gethostbyname(DL_SERVER_HOST);
	memcpy((void *) &server_addr.sin_addr, (void *) server_host->h_addr, 4);

	/* Connect Download Server */
	if(connect(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == 0) {		
		unsigned char buf[BUFFER_SIZE + 1];
		int pos = 0, read_size = 0, resource_size = 0, content_len = 0, header_removed = 0;

		/* Connect S3 Server */ 
		conn = httpc_conn_new(HTTPC_SECURE_TLS, NULL, NULL, NULL);
		if(conn) {
			if(httpc_conn_connect(conn, S3_SERVER_HOST, 443, 0) == 0) {
				
				/* Get Date */
				int should_stop = 0;
				sntp_init();
				date=malloc(50);
				if(!date) {
					printf("malloc failed for date\r\n");
					goto exit;
				}
				
				while(1) {
					unsigned int update_tick = 0;
					long update_sec = 0, update_usec = 0;
					sntp_get_lasttime(&update_sec, &update_usec, &update_tick);
					if(update_tick) {
						long tick_diff_sec, tick_diff_ms, current_sec, current_usec;
						unsigned int current_tick = xTaskGetTickCount();
						tick_diff_sec = (current_tick - update_tick) / configTICK_RATE_HZ;
						tick_diff_ms = (current_tick - update_tick) % configTICK_RATE_HZ / portTICK_RATE_MS;
						update_sec += tick_diff_sec;
						update_usec += (tick_diff_ms * 1000);
						current_sec = update_sec + update_usec / 1000000;
						memset(date, 0, 50);
						memcpy(date, ctime(&current_sec), strlen(ctime(&current_sec))-1);
						vTaskDelay(1000);
						break;
					}
				}

				/* Re-format date to ISO8601 format */
				ISO_hour = malloc(10);
				if(!ISO_hour) {
					printf("malloc failed for ISO_hour\r\n");
					goto exit;
				}
				ISO_min = malloc(10);
				if(!ISO_min) {
					printf("malloc failed for ISO_min\r\n");
					goto exit;
				}
				ISO_sec = malloc(10);
				if(!ISO_sec) {
					printf("malloc failed for ISO_sec\r\n");
					goto exit;
				}
				ISO_year = malloc(10);
				if(!ISO_year) {
					printf("malloc failed for ISO_year\r\n");
					goto exit;
				}
				ISO_mth = malloc(10);
				if(!ISO_mth) {
					printf("malloc failed for ISO_mth\r\n");
					goto exit;
				}
				ISO_day = malloc(10);
				if(!ISO_day) {
					printf("malloc failed for ISO_day\r\n");
					goto exit;
				}
				day_space = malloc(10);
				if(!day_space) {
					printf("malloc failed for day_space\r\n");
					goto exit;
				}
				day_num = malloc(10);
				if(!day_num) {
					printf("malloc failed for day_num\r\n");
					goto exit;
				}
				memset(ISO_hour, 0, 10);
				memset(ISO_min, 0, 10);
				memset(ISO_sec, 0, 10);
				memset(ISO_year, 0, 10);
				memset(ISO_mth, 0, 10);
				memset(ISO_day, 0, 10);
				memcpy(ISO_hour, date+11, 2);
				memcpy(ISO_min, date+14, 2);
				memcpy(ISO_sec, date+17, 2);
				memcpy(ISO_year, date+20, 4);
				memcpy(ISO_mth, date+4, 3);
				memcpy(ISO_day, date+8, 2);
				if(strcmp(ISO_mth, "Jan") == 0) {
					memcpy(ISO_mth, "01", 2);
				}
				else if(strcmp(ISO_mth, "Feb") == 0) {
					memcpy(ISO_mth, "02", 2);
				}
				else if(strcmp(ISO_mth, "Mar") == 0) {
					memcpy(ISO_mth, "03", 2);
				}
				else if(strcmp(ISO_mth, "Apr") == 0) {
					memcpy(ISO_mth, "04", 2);
				}
				else if(strcmp(ISO_mth, "May") == 0) {
					memcpy(ISO_mth, "05", 2);
				}
				else if(strcmp(ISO_mth, "Jun") == 0) {
					memcpy(ISO_mth, "06", 2);	
				}
				else if(strcmp(ISO_mth, "Jul") == 0) {
					memcpy(ISO_mth, "07", 2);
				}
				else if(strcmp(ISO_mth, "Aug") == 0) {
					memcpy(ISO_mth, "08", 2);
				}
				else if(strcmp(ISO_mth, "Sep") == 0) {
					memcpy(ISO_mth, "09", 2);
				}
				else if(strcmp(ISO_mth, "Oct") == 0) {
					memcpy(ISO_mth, "10", 2);
				}
				else if(strcmp(ISO_mth, "Nov") == 0) {
					memcpy(ISO_mth, "11", 2);
				}
				else if(strcmp(ISO_mth, "Dec") == 0) {
					memcpy(ISO_mth, "12", 2);
				}
				memset(day_space, 0, 10);
				memcpy(day_space, ISO_day, 1);
				if(strcmp(day_space, " ") == 0) {
					memset(day_num, 0, 10);
					memcpy(day_num, ISO_day+1, 1);
					str_len = 0;
					memset(ISO_day, 0, 10);
					memcpy(ISO_day, "0", 1);
					str_len = 1;
					memcpy(ISO_day+str_len, day_num, 1);
					str_len += 1;
				}
				s3_daystamp = malloc(50);
				if(!s3_daystamp) {
					printf("malloc failed for s3_daystamp\r\n");
					goto exit;
				}
				str_len = 0;
				memset(s3_daystamp, 0, 50);
				memcpy(s3_daystamp, ISO_year, 4);
				str_len = 4;
				memcpy(s3_daystamp+str_len, ISO_mth, 2);
				str_len += 2;
				memcpy(s3_daystamp+str_len, ISO_day, 2);
				str_len += 2;
				s3_timestamp = malloc(50);
				if(!s3_timestamp) {
					printf("malloc failed for s3_timestamp\r\n");
					goto exit;
				}
				str_len = 0;
				memset(s3_timestamp, 0, 50);
				memcpy(s3_timestamp, s3_daystamp, 8);
				str_len = 8;
				memcpy(s3_timestamp+str_len, "T", 1);
				str_len += 1;
				memcpy(s3_timestamp+str_len, ISO_hour, 2);
				str_len += 2;
				memcpy(s3_timestamp+str_len, ISO_min, 2);
				str_len += 2;
				memcpy(s3_timestamp+str_len, ISO_sec, 2);
				str_len += 2;
				memcpy(s3_timestamp+str_len, "Z", 1);
				str_len += 1;

				/* Get x-amz-credential */
				s3_credential = malloc(128);
				if(!s3_credential) {
					printf("malloc failed for s3_credential\r\n");
					goto exit;
				}
				str_len = 0;
				memset(s3_credential, 0, 128);
				memcpy(s3_credential, S3_KEY_ID, strlen(S3_KEY_ID));
				str_len = strlen(S3_KEY_ID);
				memcpy(s3_credential+str_len, "/", 1);
				str_len += 1;
				memcpy(s3_credential+str_len, s3_daystamp, 8);
				str_len += 8;
				memcpy(s3_credential+str_len, "/", 1);
				str_len += 1;
				memcpy(s3_credential+str_len, S3_REGION, strlen(S3_REGION));
				str_len += strlen(S3_REGION);
				memcpy(s3_credential+str_len, "/", 1);
				str_len += 1;
				memcpy(s3_credential+str_len, S3_SERVICE, strlen(S3_SERVICE));
				str_len += strlen(S3_SERVICE);
				memcpy(s3_credential+str_len, "/", 1);
				str_len += 1;
				memcpy(s3_credential+str_len, "aws4_request", strlen("aws4_request"));
				str_len += strlen("aws4_request");

				/* Constuct Policy */	
				policy policy_element;
				policy_element.s3_expiration = S3_POLICY_EXPIRATION;
				policy_element.bucket = S3_BUCKET;
				policy_element.s3_key = "$key";
				policy_element.s3_acl = S3_ACL;
				policy_element.content_type = "$Content-Type";
				policy_element.x_amz_meta_tag = "$x-amz-meta-tag";
				policy_element.x_amz_crd = s3_credential;
				policy_element.x_amz_alg = S3_ALGORITHM;
				policy_element.x_amz_date = s3_timestamp;
#if ADD_IN_POLICY				
				policy_element.x_amz_security_token = S3_SESSION_TOKEN;
#endif				
				s3_policy = generate_s3_policy(policy_element);

#if SHOW_INFO
				printf(" ---------------\r\n");
				printf("|  POST Policy  |\r\n");
				printf(" ---------------\r\n%s",s3_policy);
#endif

				/* Build StringToSign */
				stringtosign = malloc(2048);
				if(!stringtosign) {
					printf("malloc failed for stringtosign\r\n");
					goto exit;
				}
				memset(stringtosign, 0, 2048);
				if((ret = httpc_base64_encode(s3_policy, strlen(s3_policy), stringtosign, 2048)) != 0) {
					printf("base64 encode failed for s3_policy\r\n");
					goto exit;
				}
				
				/* Construct SigningKey */
				datekey_str = malloc(128);
				if(!datekey_str) {
					printf("malloc failed for datekey_str\r\n");
					goto exit;
				}
				memset(datekey_str, 0, 128);
				str_len = 0;
				memcpy(datekey_str, "AWS4", 4);
				str_len = 4;
				memcpy(datekey_str+str_len, S3_KEY_SECRET, strlen(S3_KEY_SECRET));
				str_len += strlen(S3_KEY_SECRET);

				/* SHA-256 Encryption */
				device_mutex_lock(RT_DEV_LOCK_CRYPTO);
				ret = rtl_crypto_hmac_sha2(SHA2_256, s3_daystamp, strlen(s3_daystamp), datekey_str, strlen(datekey_str), datekey_digest);
				ret += rtl_crypto_hmac_sha2(SHA2_256, S3_REGION, strlen(S3_REGION), datekey_digest, 32, dateregionkey_digest);
				ret += rtl_crypto_hmac_sha2(SHA2_256, S3_SERVICE, strlen(S3_SERVICE), dateregionkey_digest, 32, dateregionservicekey_digest);
				ret += rtl_crypto_hmac_sha2(SHA2_256, "aws4_request", 12, dateregionservicekey_digest, 32, signingkey_digest); 
				ret += rtl_crypto_hmac_sha2(SHA2_256, stringtosign, strlen(stringtosign), signingkey_digest, 32, sha256_signature); //sha256 signature
				device_mutex_unlock(RT_DEV_LOCK_CRYPTO);
				if(ret != 0 ) {
					printf("sha256 failed %d\r\n", ret);
					goto exit;
				}

				/* Construct Signature */	
				signature = malloc(1024);
				if(!signature) {
					printf("malloc failed for signature\r\n");
					goto exit;
				}			
				memset(signature, 0, 1024);

				/* Represent in Hex form */
				for(int i=0;i<32;i++) {
					sprintf(signature+2*i, "%02x", sha256_signature[i]);
				}

				/* Construct Multipart form-data */
				boundary = malloc(64);
				if(!boundary) {
					printf("malloc failed for boundary\r\n");
					goto exit;
				}
				memset(boundary, 0, 64);
				rtw_get_random_bytes(boundary_buffer, 16);
				for(int i=0;i<16;i++) {
					sprintf(boundary+2*i, "%02x", boundary_buffer[i]);
				}
				multipart_datatype = malloc(100);
				if(!multipart_datatype) {
					printf("malloc failed for multipart_datatype\r\n");
					goto exit;
				}
				str_len = 0;
				memset(multipart_datatype, 0, 100);
				memcpy(multipart_datatype+str_len, "multipart/form-data; boundary=", 30);
				str_len = 30;
				memcpy(multipart_datatype+str_len, boundary, strlen(boundary));
				str_len += strlen(boundary);
				form_boundary=malloc(64);
				if(!form_boundary) {
					printf("malloc failed for form_boundary\r\n");
					goto exit;
				}
				str_len = 0;
				memset(form_boundary, 0, 64);
				memcpy(form_boundary+str_len, "--", 2);
				str_len = 2;
				memcpy(form_boundary+str_len, boundary, strlen(boundary));
				str_len += strlen(boundary);
				end_boundary=malloc(64);
				if(!end_boundary) {
					printf("malloc failed for end_boundary\r\n");
					goto exit;
				}
				end_b_len = 0;
				memset(end_boundary, 0, 64);
				memcpy(end_boundary+end_b_len, HTTP_CRLF, 2);
				end_b_len += 2;
				memcpy(end_boundary+end_b_len, form_boundary, strlen(form_boundary));
				end_b_len += strlen(form_boundary);
				memcpy(end_boundary+end_b_len, "--", 2);
				end_b_len += 2;
				payload_content=malloc(4096);
				if(!payload_content) {
					printf("malloc failed for payload_content\r\n");
					goto exit;
				}
				memset(payload_content, 0, 4096);
				form_len = 0;
				form_len += create_form(payload_content + form_len, form_boundary, "key", S3_RESOURCE, 0);
				form_len += create_form(payload_content + form_len, form_boundary, "acl", S3_ACL, 0);
				form_len += create_form(payload_content + form_len, form_boundary, "Content-Type", CONTENT_TYPE, 0);
				form_len += create_form(payload_content + form_len, form_boundary, "X-Amz-Credential", s3_credential, 0);
				form_len += create_form(payload_content + form_len, form_boundary, "X-Amz-Algorithm", S3_ALGORITHM, 0);
				form_len += create_form(payload_content + form_len, form_boundary, "X-Amz-Date", s3_timestamp, 0);
#if ADD_IN_FORM_FIELD
				form_len += create_form(payload_content + form_len, form_boundary, "x-amz-security-token", S3_SESSION_TOKEN, 0);
#endif
				form_len += create_form(payload_content + form_len, form_boundary, "X-Amz-Meta-Tag", "", 0);
				form_len += create_form(payload_content + form_len, form_boundary, "Policy", stringtosign, 0);
				form_len += create_form(payload_content + form_len, form_boundary, "X-Amz-Signature", signature, 0);
				form_len += create_form(payload_content + form_len, form_boundary, "file", S3_RESOURCE, 1);

				/* Send GET request to download server */
				content = malloc(BUFFER_SIZE);
				if(!content) {
					printf("malloc failed for content\r\n");
					goto exit;
				}
				memset(content, 0, BUFFER_SIZE);
				sprintf(buf, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", DL_RESOURCE, DL_SERVER_HOST); 
				write(server_fd, buf, strlen(buf));
				
				/* Start receiving data from download server*/
				while((read_size = read(server_fd, buf + pos, BUFFER_SIZE - pos)) > 0) {
					if(header_removed == 0) {
						char *header = NULL;
						pos += read_size;
						buf[pos] = 0;
						header = strstr(buf, "\r\n\r\n");
						if(header) {
							char *body, *content_len_pos;
							body = header + strlen("\r\n\r\n");
							*(body - 2) = 0;
							header_removed = 1;
							printf("\n-- Download Server --\r\n");
							printf("HTTP Header: %s\n", buf);
							//Remove header size to get first read size of data from body head
							read_size = pos - ((unsigned char *) body - buf);
							pos = 0;
							content_len_pos = strstr(buf, "Content-Length: ");
							if(content_len_pos) {
								content_len_pos += strlen("Content-Length: ");
								*(char*)(strstr(content_len_pos, "\r\n")) = 0;
								content_len = atoi(content_len_pos);
							}
						}
						else {
							if(pos >= BUFFER_SIZE){
								printf("ERROR: HTTP header\n");
								goto exit;
							}
							continue;
						}
						printf("\n-- S3 Server --\r\n");
						/* Start building request header */
						httpc_request_write_header_start(conn, UPLOAD_METHOD, "/", multipart_datatype, (form_len+content_len+end_b_len));
#if	ADD_IN_REQUEST_HEADER
						httpc_request_write_header(conn, "x-amz-security-token", S3_SESSION_TOKEN);
#endif
						httpc_request_write_header(conn, "Accept", "*/*");
						httpc_request_write_header(conn, "Expect", "100 Continue");
						
						/* Send request header */
						httpc_request_write_header_finish(conn);
						
						/* Send request body */
						httpc_request_write_data(conn, (uint8_t*)payload_content, strlen(payload_content));
#if SHOW_INFO
						printf(" ---------------\r\n");
						printf("|   HTML Form   |\r\n");
						printf(" ---------------\r\n%s",payload_content);
#endif
						printf("Uploading (%s) ...\r\n",DL_RESOURCE);
#if SHOW_PROGRESS
						dividend = content_len/50;
						printf("0%%--------------------------------------------100%%\r\n");
#endif
					}
#if SHOW_PROGRESS
					last_rs += read_size;
					current_work = last_rs/dividend - progress;
					for(int i=0;i<current_work;i++)
						printf(">");
					progress += current_work;
#endif
					memcpy(content, buf, read_size); 
					resource_size += read_size;
					
					/* Send data to S3 server */
					httpc_request_write_data(conn, (uint8_t*)content, read_size);
				}
				
				/* Send end boundary to end the form */
				httpc_request_write_data(conn, (uint8_t*)end_boundary, strlen(end_boundary));
#if SHOW_INFO
				printf("\nSaved as (%s) in server.\r\n",S3_RESOURCE);	
				printf("%s\r\n",end_boundary);
#endif
				// Receive response header
				if(httpc_response_read_header(conn) == 0) {
					httpc_conn_dump_header(conn);
					
					// Receive response body
					if(httpc_response_is_status(conn, "200 OK")) {
						uint8_t buf[1024];
						int rd_size = 0; 
						uint32_t total_size = 0;
						
						while(1) {
							memset(buf, 0, sizeof(buf));
							rd_size = httpc_response_read_data(conn, buf, sizeof(buf) - 1);

							if(rd_size > 0) {
								total_size += rd_size;	
								printf("%s", buf);
							}
							else {
								break;
							}
							if(conn->response.content_len && (total_size >= conn->response.content_len))
								break;
						}
					}
				}
			}
		}
		else {
			printf("\nERROR: httpc_conn_connect\n");
		}
		printf("\nEnd of S3 upload example\n");
		httpc_conn_close(conn);
		httpc_conn_free(conn);
	}
	else {
		printf("ERROR: connect\n");
	}
	exit:			   
	if(server_fd >= 0)
		close(server_fd);
	if(content)
		free(content);	
	if(date)
		free(date);
	if(canonical_URI)
		free(canonical_URI);
	if(stringtosign)
		free(stringtosign);
	if(authorization_header)
		free(authorization_header);
	if(ISO_hour)
		free(ISO_hour);
	if(ISO_min)
		free(ISO_min);
	if(ISO_sec)
		free(ISO_sec);
	if(ISO_year)
		free(ISO_year);
	if(ISO_mth)
		free(ISO_mth);
	if(ISO_day)
		free(ISO_day);
	if(day_space)
		free(day_space);
	if(day_num)
		free(day_num);
	if(s3_daystamp)
		free(s3_daystamp);
	if(s3_timestamp)
		free(s3_timestamp);
	if(s3_credential)
		free(s3_credential);
	if(s3_scope)
		free(s3_scope);
	if(hex_sha256_file_content)
		free(hex_sha256_file_content);
	if(hex_sha256_canonical_request)
		free(hex_sha256_canonical_request);
	if(host_header)
		free(host_header);
	if(content_type_header)
		free(content_type_header);
	if(canonical_headers)
		free(canonical_headers);	
	if(x_amz_content_sha256)
		free(x_amz_content_sha256);
	if(x_amz_date)
		free(x_amz_date);	
	if(canonical_request)
		free(canonical_request);
	if(datekey_str)
		free(datekey_str);
	if(signature)
		free(signature);
	if(payload_content)
		free(payload_content);
	if(boundary)
		free(boundary);
	if(multipart_datatype)
		free(multipart_datatype);
	if(form_boundary)
		free(form_boundary);
	if(end_boundary)
		free(end_boundary);
	if(form_content)
		free(form_content);
	if(s3_policy)
		free(s3_policy);
	printf("Exit\r\n");
	vTaskDelete(NULL);
}

void example_s3_upload(void)
{
	if(xTaskCreate(example_s3_upload_thread, ((const char*)"example_s3_upload_thread"), 2048, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS)
		printf("\n\r%s xTaskCreate(example_s3_upload_thread) failed", __FUNCTION__);
}
