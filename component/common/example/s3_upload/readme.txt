S3 UPLOAD EXAMPLE

Description:
This example is to upload a file to AWS S3 server.

Configuration:
[platform_opts.h]
	#define CONFIG_EXAMPLE_S3_UPLOAD         1

Execution:
Please provide and set below macros correctly

#define DL_File_TYPE			// The format of file to be downloaded
#define DL_SERVER_HOST			// Download server host address (cmd->ipconfig->IPv4 Address)
#define DL_SERVER_PORT			// Download server port number (set same as in ‘start.bat’)
#define SHOW_INFO				// Set to 1 to see the POST policy and HTML form
#define SHOW_PROGRESS			// Set to 1 to see the upload progress bar
#define DL_RESOURCE				// Name of file to be downloaded
#define S3_RESOURCE				// Name of file to be uploaded  
#define SESSION_TOKEN 			// Set to 1 to use Security Credentials
#define S3_KEY_ID 
#define S3_KEY_SECRET 
#define S3_SESSION_TOKEN
#define ADD_IN_FORM_FIELD		// Set to 1 to add "x-amz-security-token" in HTML form
#define ADD_IN_POLICY			// Set to 1 to add "x-amz-security-token" in POST policy
#define ADD_IN_REQUEST_HEADER	// Set to 1 to add "x-amz-security-token" in request header
#define S3_BUCKET
#define S3_REGION 
#define S3_POLICY_EXPIRATION