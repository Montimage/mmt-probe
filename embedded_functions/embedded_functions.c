//Linux (one of the follows)
//gcc -g -fPIC -I/usr/local/include/mmt -shared -nostartfiles embedded_functions/embedded_functions.c -o embedded_functions/libembedded_functions.so 
//gcc -g -fPIC -I../../../mmt-sdk/sdk/include -shared -nostartfiles embedded_functions.c -o libembedded_functions.so
//gcc -g -fPIC -I/opt/mmt/dpi/include -shared -nostartfiles embedded_functions/embedded_functions.c -o embedded_functions/libembedded_functions.so
//Then:
//sudo su
// export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./embedded_functions 
// export LD_LIBRARY_PATH=<your directory>/embedded_functions

// Windows don't forget to replace the include directory with the right one on your machine ;)
// gcc    -c -g -DWIN -I../MMT_SecurityLib/external/include/libmmtext  -MMD -MP -MF embedded_functions.o.d -o embedded_functions.o embedded_functions.c
// gcc     -shared -o embedded_functions.dll embedded_functions.o  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types_defs.h"
#include "data_defs.h"
#include <inttypes.h>
#include "hiredis/hiredis.h"
#include <sys/time.h>

//#include "ocilib.h"
//#define MAX_LEN 1000


//        CLEP_DATA_NOTYPE,     /**< no type constant value */
//        MMT_U8_DATA,          /**< unsigned 1-byte constant value */
//        MMT_U16_DATA,         /**< unsigned 2-bytes constant value */
//        MMT_U32_DATA,         /**< unsigned 4-bytes constant value */
//        MMT_U64_DATA,         /**< unsigned 8-bytes constant value */
//        MMT_DATA_POINTER,     /**< pointer constant value (size is CPU dependant) */
//        MMT_STRING_DATA,      /**< string constant value */
//        MMT_DATA_IP_NET,      /**< ip network address constant value */
//        MMT_DATA_MAC_ADDR,    /**< ethernet mac address constant value */
//        MMT_DATA_IP_ADDR,     /**< ip network address and mask constant value */
//        MMT_DATA_PATH,        /**< protocol path constant value */
//        MMT_DATA_TIMEVAL,     /**< number of seconds and microseconds constant value */
//        MMT_BINARY_DATA,      /**< binary constant value */
//        CLEP_DATA_BUFFER,     /**< binary buffer content */
//        MMT_DATA_CHAR,        /**< 1 character constant value */
//        MMT_DATA_IP6_ADDR,    /**< ip6 address constant value */
//        MMT_DATA_rPORT,        /**< tcp/udp port constant value */
//        MMT_DATA_POINT,       /**< point constant value */
//        MMT_DATA_PORT_RANGE,  /**< tcp/udp port range constant value */
//        MMT_DATA_DATE,        /**< date constant value */
//        MMT_DATA_TIMEARG,     /**< time argument constant value */
//        MMT_STRING_DATA_INDEX,/**< string index constant value (an association between a string and an integer) */
//        MMT_DATA_FLOAT,       /**< float constant value */
//        MMT_DATA_LAYERID,     /**< Layer ID value */
//        MMT_DATA_FILTER_STATE,/**< (filter_id, filter_state) */
//        MMT_oninary constant value */

int *get_data_type_of_funct_return_value(char * funct_name, int * size){
  int *handle;
  handle = malloc(sizeof(int));
  *size = 4;
  *handle = MMT_U16_DATA;
  //For other values do the following:
  //if(strcmp(funct_name,"name_of_the_function")==0){
  //  *size = 4;
  //  *handle = MMT_U16_DATA;
  //}
  return handle; 
}


int *check_ip_options(void *op2,void *op1){
  int *handle;
  handle = malloc(sizeof(int));
  *handle = 0;
  int i2 = *((int*)op2);
  int i1 = *((int*)op1);
  // int bit2 = (i2 >> 1) & 1;
  // int bit1 = (i1 >> 1) & 1;
//  if(bit2 == 1 || bit1 == 1){
      if(i2 != i1) *handle = 1;
//  }
  return handle;
}

int *check_port(void *port){
  int *handle;
  handle = malloc(sizeof(int));
  *handle = 0;
  if(port==NULL) {
	  //printf("Port NULL\n");
	  *handle =1;
	  return handle;
		}
  int i = *((int*)port);
  //printf("Port:%d\n", i);
  //according to: 
  //https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
  //and
  //https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt

  if(i<1023){return handle;}
  if(i>49151 && i< 65536){return handle;}
  if(i>65535){*handle = 1;return handle;}

  if(i>2193 && i<2197){*handle = 1;return handle;}
  if(i>4488 && i<4500){*handle = 1;return handle;}
  if(i>4953 && i<4969){*handle = 1;return handle;}
  if(i>5569 && i<5573){*handle = 1;return handle;}
  if(i>5646 && i<5670){*handle = 1;return handle;}
  if(i>6657 && i<6665){*handle = 1;return handle;}
  if(i>7491 && i<7500){*handle = 1;return handle;}
  if(i>7784 && i<7790){*handle = 1;return handle;}
  if(i>27999 && i<28119){*handle = 1;return handle;}
  if(i>5554 && i<5558){*handle = 1;return handle;}
  if(i>5999 && i<6064){*handle = 1;return handle;}
  if(i>8615 && i<8665){*handle = 1;return handle;}
  if(i>8801 && i<8804){*handle = 1;return handle;}
  if(i>8887 && i<8891){*handle = 1;return handle;}
  if(i>11430 && i<11489){*handle = 1;return handle;}
  if(i>11623 && i<11720){*handle = 1;return handle;}
  if(i>27009 && i<27345){*handle = 1;return handle;}
  if(i>41797 && i<42508){*handle = 1;return handle;}
  if(i>44444 && i<44544){*handle = 1;return handle;}
  switch (i) {
    case 78:
    case 79:
    case 100:
    case 106:
    case 787:
    case 1053:
    case 1491:
    case 2662:
    case 3060:
    case 3131:
    case 3145:
    case 3300:
    case 3301:
    case 4045:
    case 4315:
    case 4443:
    case 4967:
    case 5151:
    case 5152:
    case 5162:
    case 5444:
    case 5555:
    case 5556:
    case 6100:
    case 6200:
    case 6501:
    case 8882:
    case 9001:
    case 6632:
    case 7001:
    case 7002:
    case 7005:
    case 7011:
    case 7012:
    case 7501:
    case 7777:
    case 8001:
    case 16000:
    case 49151:
      *handle = 1;
      return handle;  
      break;
    default:
      return handle;
  }
  return handle;
}


int *check_URI(void *URI){
  //URI is a C string
  //#check_URI(http.uri) == 1 means invalid URI
  //0: ok
  //1: invalid
  //2: NULL
  int *handle;
  handle = malloc(sizeof(int));
  *handle = 0;
  if(URI == NULL){
    *handle = 2;
    return handle;
  }
  mmt_header_line_t * uri = (mmt_header_line_t *)URI;
  int len = uri->len;
  char * uri_str = malloc(len+1);
  strncpy(uri_str, uri->ptr, len);
  uri_str[len] = '\0';
  //printf("\nuri: %s", uri_str);
  char *x = uri_str;
  
  //fprintf(stderr, "%s\n",x);
  while (*x != '\0'){
      //octets 0-32 (0-20 hex) | "\" | """ | "&" | "<" | ">" | "[" | "]" | "^" | "`" | "{" | "|" | "}" | "~" | octets 127-255 (7F-FF hex)
      if(*x < 32 || *x == 92 || *x == '"' || *x == '<' || *x == '>' || *x == '[' || *x == ']' || *x == '^' || *x == '`' || *x == '{' || 
         *x == '|' || *x == '}' || *x == '%' || *x > 126) {
              *handle = 1;
              break;
      }
      x = x+1;
  }
  //detect directory traversal attack
  char *s0, *s1, *s2, *s3;
  s0 = strstr(uri_str, ".."); //find the first occurrence of string ".." in string
  s1 = strstr(uri_str, "./"); //find the first occurrence of string "./" in string
  s2 = strstr(uri_str, "//"); //find the first occurrence of string "//" in string
  s3 = strstr(uri_str, "/."); //find the first occurrence of string "//" in string
  if ((s0 !=NULL) || (s1 !=NULL) || (s2 !=NULL) || (s3 !=NULL))  *handle = 1;
#ifdef DEBUG
  fprintf(stderr, "executing check_URI with parameters:h=%d:nb=%u:a1=%o:a2=%o\n", 
                                           *handle, *(char*)(BLOC3+6),*(char*)(BLOC3+9),*(char*)(BLOC3+12));
#endif
  if (uri_str != NULL) free(uri_str);
  return handle;
}

/*
 * Nikto 
 */
int *check_UA( void *v){
  int *handle;
  handle = malloc(sizeof(int));
  *handle = 0; //False per default
  
  if( v == NULL ){
    *handle = 1;
    return handle;
  }
  
  mmt_header_line_t *hl;
  hl = v;
  
  char *user_agent = malloc( hl->len + 1 );
  strncpy(user_agent, hl->ptr, hl->len);
  user_agent[ hl->len ] = '\0';
  
  char *s;
  s = strstr(user_agent, "Nikto"); //find the first occurrence of string "Nikto" in string    
  if (s !=NULL)  {
   *handle = 1;   
  }
  free(user_agent);
  return handle;
}

int *check_sql_injection(void *p, void *pl){
  int *handle;
  handle = malloc(sizeof(int));
  *handle = 0;
 
  if( (p == NULL) || (pl == NULL) ){
    *handle = 2;
    return handle;
  }
  uint16_t len = *((uint16_t *)pl);
  //printf("Payload length: %"PRIu16"\n", len);
  char *str = malloc(len+1);
  memcpy(str, p, len);
  str[len] = '\0';
  //printf("String to be checked: %s\n", str);
  
    //Signature based dection begin here. 
  //(using  pattern matching techniques against signatures and 
  //keyword-based stores to identify potentially malicious requests)   
  char *s1, *s2, *s3, *s4, *s5, *s6;
  s1 = strstr(str, "DROP");  //find the first occurrence of string "DROP" in string
  s2 = strstr(str, "UNION"); //find the first occurrence of string "UNION" in string
  s3 = strstr(str, "SELECT"); //find the first occurrence of string "SELECT" in string
  s4 = strstr(str, "CHAR"); //find the first occurrence of string "CHAR" in string  
  s5 = strstr(str, "DELETE");
  s6 = strstr(str, "INSERT");
     
  if ((s1 !=NULL)  || (s2 !=NULL)   || (s3 !=NULL) || (s4 !=NULL) || (s5 !=NULL) || (s6 !=NULL))  {
    //printf ("SQL injection detected\n");
    *handle = 1;   
  }
  
  free(str);
  return handle;
 
}

int *check_http_response(void *p){
  int *handle;
  handle = malloc(sizeof(int));
  *handle = 0;
  if(p == NULL){
    *handle = 1;
    return handle;
  }
  return handle;
}

int *check_ip_add(void *src, void *dst, void *src1, void *dst1){
  int *handle;
  handle = malloc(sizeof(int));
  *handle = 0;
  if((src == NULL) || (dst == NULL) || (src1 == NULL) || (dst1 == NULL)){
    *handle = 1;
    return handle;
  }
  if (((src = src1) && (dst = dst1)) || ((src = dst1) && (dst = src1))){
	  *handle = 1;
	  //printf("In the same session\n");
	  return handle;
  }
  return handle;
}

int *check_nfs_upload(void *file_name, void *file_opcode, void *p_payload, void *payload_len){
  int *handle;
  handle = malloc(sizeof(int));
  *handle = 0;
  if((file_name == NULL) || (file_opcode == NULL) || (p_payload == NULL) || (payload_len == NULL)){
    return handle;
  }
  
  //take the file name
  uint16_t leng = *((uint16_t*)file_opcode);
  char * fn_str = malloc(leng+1);
  strncpy(fn_str, file_name, leng);
  fn_str[leng] = '\0';
  //printf("File name: %s. Leng: %d\n", fn_str, leng);
  
  //take the payload
  uint16_t len = *((uint16_t *)payload_len);
  //printf("Payload length: %"PRIu16"\n", len);
  char *tcp_payload = malloc(len+1);
  memcpy(tcp_payload, p_payload, len);
  tcp_payload[len] = '\0';
  //printf("TCP payload: %s\n", tcp_payload);
  
  if (strstr(tcp_payload, fn_str) != NULL){
	  //printf ("Detected\n");
	  *handle = 1;
		}
  free(fn_str);
  free(tcp_payload);
  return handle;
}

int *check_nfs_redis(void *p_payload, void *payload_len){
  int *handle;
  handle = malloc(sizeof(int));
  *handle = 0;
  if((p_payload == NULL) || (payload_len == NULL)){
    return handle;
  }
  
  redisContext *c, *command;
  redisReply *reply;
  
  const char *hostname = "127.0.0.1";
  //const char *hostname = "192.168.0.37";
  int port = 6379;
  
  //take the payload
  uint16_t len = *((uint16_t *)payload_len);
  //printf("Payload length: %"PRIu16"\n", len);
  char *tcp_payload = malloc(len+1);
  memcpy(tcp_payload, p_payload, len);
  tcp_payload[len] = '\0';
  //printf("TCP payload: %s\n", tcp_payload);
  
  struct timeval timeout = { 1, 500000 }; // 1.5 seconds
  c = redisConnectWithTimeout(hostname, port, timeout);
  if (c == NULL || c->err) {
        if (c) {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection error: Impossible to allocate redis context\n");
        }
        exit(1);
    }
  
    /* Let's check what we have inside the list */
    reply = redisCommand(c,"LRANGE multisession.report 0 -1");
    if (reply->type == REDIS_REPLY_ARRAY) {
 		int j=0;
        for (j = 0; j < reply->elements; j++) {
			//printf("report: %s\n", reply->element[j]->str);
            char probe_report[256];
            char *token;
            strcpy(probe_report, reply->element[j]->str);
            token = strtok(reply->element[j]->str, ",");
            int i = 0;
			while (token != NULL) {
				//printf("Token:%s\n", token);
				if (i==1) {
					//check the validity of the report
					struct timeval now;
					gettimeofday(&now, NULL);
					double element_ts = atof(token);
					//printf("Timestamp: %4.4f\n", element_ts);
					if (now.tv_sec - element_ts > 300) {
							redisCommand(c,"LREM multisession.report 1 %s", probe_report);
							//printf("Delete the outdated report %s\n", probe_report);
							i++;
							break;
							}
					}
				if (i==2){
					if (token[0] == ' '){
					//printf("NULL report\n");
					break;
					}
					//printf("Filename: %s\n", token);
					if (strstr(p_payload, token) != NULL){
					//printf ("Detected\n");
					redisFree(c);
					return 1;
					}        
					}
				token = strtok(NULL, ",");
				i++;
				}
			    
        }
    }
  redisFree(c);
  free(tcp_payload);
  return handle;
}
