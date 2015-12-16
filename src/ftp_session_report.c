#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
//#include "mmt/tcpip/mmt_tcpip_protocols.h"
#include "mmt/tcpip/mmt_tcpip.h"
#include "processing.h"


#define MAX_MESS 2000

char * str_replace_all_char(const char *str,int c1, int c2){
    char *new_str;
    new_str = (char*)malloc(strlen(str)+1);
    memcpy(new_str,str,strlen(str));
    new_str[strlen(str)] = '\0';
    int i;
    for(i=0;i<strlen(str);i++){
        if((int)new_str[i]==c1){
            new_str[i]=(char)c2;
        }
    }
    return new_str;
}

void write_data_to_file (const ipacket_t * ipacket,const char * path, const char * content, int len, uint32_t * file_size) {
    int fd = 0,MAX=200;
    char filename[len];

    static uint32_t total_len=0;
    static time_t download_start_time_sec =0, download_start_time_usec=0;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    total_len+=len;

    if (download_start_time_sec ==0 && download_start_time_usec==0){
        download_start_time_sec = ipacket->p_hdr->ts.tv_sec;
        download_start_time_usec = ipacket->p_hdr->ts.tv_usec;

    }

    path = str_replace_all_char(path,'/','_');
    snprintf(filename,MAX, "%s%lu.%lu_%s",probe_context->ftp_reconstruct_output_location,download_start_time_sec,download_start_time_usec,path);
    filename[MAX]='\0';


    if ( (fd = open ( filename , O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO )) < 0 ){
        fprintf ( stderr , "\n Error %d writting data to \"%s\": %s" , errno , path , strerror( errno ) );
        return;
    }

    if(len>0){
        printf("Going to write to file: %s\n",filename);
        printf("Data len: %d\n",len);
        write ( fd , content , len );
    }

    if (total_len >= * file_size){
        download_start_time_sec =0,
                download_start_time_usec=0;
        total_len=0;
    }


    close ( fd );
}

void reconstruct_data(const ipacket_t * ipacket ){

    uint8_t * data_type = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_DATA_TYPE);
    int d_type = -1;
    if(data_type){
        d_type = *data_type;
    }

    char * file_name = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_FILE_NAME);

    uint32_t * data_len = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_DATA_LEN);

    uint32_t * file_size = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_FILE_SIZE);



    int len = 0;
    if(data_len){
        len = *data_len;
    }

    char * data_payload = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,PROTO_PAYLOAD);

    if(len>0 && file_name && data_payload && d_type==1){
        printf("filename=%s\n",file_name);
        printf("Going to write data of packet %lu\n",ipacket->packet_id);
        write_data_to_file(ipacket,file_name,data_payload,len,file_size);
    }
}


void ftp_packet_events(const ipacket_t * ipacket){
    char message[MAX_MESS + 1];
    //FILE * out_file = (probe_context->data_out_file != NULL) ? probe_context->data_out_file : stdout;
    mmt_probe_context_t * probe_context = get_probe_context_config();
    ftp_packet_attr_t * packet_attr = (ftp_packet_attr_t * )malloc(sizeof(ftp_packet_attr_t));

    if (packet_attr != NULL) {
        memset(packet_attr, '\0', sizeof (ftp_packet_attr_t));
    }

    uint8_t * packet_type = (uint8_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_TYPE);

    if(packet_type!=NULL){
        packet_attr->packet_type = * packet_type;
    }


    packet_attr->request = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_REQUEST);
    packet_attr->request_parameter = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_REQUEST_PARAMETER);

    uint16_t * response_code=(uint16_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_RESPONSE_CODE);

    if(response_code!=NULL){
        packet_attr->response = * response_code;
    }

    //printf("value=%d, packet_id =%lu\n",value,ipacket->packet_id);

    packet_attr->response_value = (char *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_RESPONSE_VALUE);

    uint32_t * data_len = (uint32_t *) get_attribute_extracted_data(ipacket,PROTO_FTP,FTP_PACKET_DATA_LEN);

    if(data_len!=NULL){
        packet_attr->data_len = * data_len;
    }

    snprintf(message, MAX_MESS,
            "%u,%u,\"%s\",%lu.%lu,%"PRIu8",%s,%s,%"PRIu16",%s,%"PRIu32"",
            MMT_FTP_PACKET_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, ipacket->p_hdr->ts.tv_sec,ipacket->p_hdr->ts.tv_usec,packet_attr->packet_type,packet_attr->request,packet_attr->request_parameter,packet_attr->response,packet_attr->response_value,packet_attr->data_len);
    //snprintf(message, MAX_MESS,"%s,%u,%u",file_name,data_type,data_len);

    message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
    //send_message_to_file ("ftp.flow.report", message);
    if (probe_context->output_to_file_enable==1)send_message_to_file (message);
    if (probe_context->redis_enable==1)send_message_to_redis ("ftp.flow.report", message);


}


void reset_ftp_parameters(const ipacket_t * ipacket,session_struct_t *temp_session ){

    ((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_sec=0;
    ((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_usec=0;
    ((ftp_session_attr_t*) temp_session->app_data)->file_download_finishtime_sec=0;
    ((ftp_session_attr_t*) temp_session->app_data)->file_download_finishtime_usec=0;
    ((ftp_session_attr_t*) temp_session->app_data)->response_value=NULL;
    ((ftp_session_attr_t*) temp_session->app_data)->file_size=0;
    ((ftp_session_attr_t*) temp_session->app_data)->filename=NULL;
    ((ftp_session_attr_t*) temp_session->app_data)->response_code=0;
    ((ftp_session_attr_t*) temp_session->app_data)->session_password=NULL;
    ((ftp_session_attr_t*) temp_session->app_data)->packet_request=NULL;


}

void ftp_session_connection_type_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    mmt_probe_context_t * probe_context = get_probe_context_config();
    if (temp_session != NULL) {
        if (temp_session->app_data == NULL) {
            ftp_session_attr_t * ftp_data = (ftp_session_attr_t *) malloc(sizeof (ftp_session_attr_t));
            if (ftp_data != NULL) {
                memset(ftp_data, '\0', sizeof (ftp_session_attr_t));
                temp_session->app_format_id = MMT_FTP_DOWNLOAD_REPORT_FORMAT;
                temp_session->app_data = (void *) ftp_data;
            } else {
                mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating SSL reporting context");
                //fprintf(stderr, "Out of memory error when creating SSL specific data structure!\n");
                return;
            }
        }
    }

    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint8_t * conn_type = (uint8_t *) attribute->data;
        if (conn_type != NULL && temp_session->app_format_id == MMT_FTP_DOWNLOAD_REPORT_FORMAT) {
            ((ftp_session_attr_t*) temp_session->app_data)->session_conn_type = *conn_type;
        }
    }

}

void ftp_data_direction_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint8_t * direction = (uint8_t *) attribute->data;
        if (direction != NULL && temp_session->app_format_id == MMT_FTP_DOWNLOAD_REPORT_FORMAT) {
            ((ftp_session_attr_t*) temp_session->app_data)->direction = *direction;
        }
    }

}

void ftp_user_name_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        char * username = (char *) attribute->data;
        if (username != NULL && temp_session->app_format_id == MMT_FTP_DOWNLOAD_REPORT_FORMAT) {
            ((ftp_session_attr_t*) temp_session->app_data)->session_username =  username;
        }
    }
}

void ftp_password_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        char * password = (char *) attribute->data;
        if (password != NULL && temp_session->app_format_id == MMT_FTP_DOWNLOAD_REPORT_FORMAT) {
            ((ftp_session_attr_t*) temp_session->app_data)->session_password =  password;
        }
    }
}

void ftp_packet_request_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        char * packet_request= (char *)attribute->data;
        if (packet_request != NULL && temp_session->app_format_id == MMT_FTP_DOWNLOAD_REPORT_FORMAT) {
            ((ftp_session_attr_t*) temp_session->app_data)->packet_request =  packet_request;
        }
    }
}

void ftp_response_value_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        char * response_value = (char *) attribute->data;
        if (response_value != NULL && temp_session->app_format_id == MMT_FTP_DOWNLOAD_REPORT_FORMAT) {
            ((ftp_session_attr_t*) temp_session->app_data)->response_value =  response_value;
        }

    }
    mmt_probe_context_t * probe_context = get_probe_context_config();
    char message[MAX_MESS + 1];
    //char * location;
    int i;
    char ip_src_str[46];
    char ip_dst_str[46];

    //FILE * out_file = (probe_context->data_out_file != NULL) ? probe_context->data_out_file : stdout;
    mmt_session_t * ftp_session = get_session_from_packet(ipacket);
    if(ftp_session == NULL) return;

    uint64_t session_id = get_session_id(ftp_session);


    if (temp_session->ipversion == 4) {
        inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
    }

    for(i = 0; i < probe_context->condition_reports_nb; i++) {
        mmt_condition_report_t * condition_report = &probe_context->condition_reports[i];
        if (strcmp(((ftp_session_attr_t*) temp_session->app_data)->response_value,"Transfer complete.")==0 && strcmp(condition_report->condition.condition,"FTP")==0){
            //location=condition_report->condition.location;

            ((ftp_session_attr_t*) temp_session->app_data)->file_download_finishtime_sec= ipacket->p_hdr->ts.tv_sec;
            ((ftp_session_attr_t*) temp_session->app_data)->file_download_finishtime_usec=ipacket->p_hdr->ts.tv_usec;
            snprintf(message, MAX_MESS,
                    "%u,\"%s\",\"%s\",%hu,%hu,%"PRIu64",%"PRIu8",%"PRIu8",%s,%s,%"PRIu32",%s,%lu.%lu,%lu.%lu",
                    temp_session->app_format_id,
                    ip_dst_str, ip_src_str,
                    temp_session->serverport, temp_session->clientport,session_id,
                    ((ftp_session_attr_t*) temp_session->app_data)->session_conn_type,
                    ((ftp_session_attr_t*) temp_session->app_data)->direction,
                    ((ftp_session_attr_t*) temp_session->app_data)->session_username,
                    ((ftp_session_attr_t*) temp_session->app_data)->session_password,
                    ((ftp_session_attr_t*) temp_session->app_data)->file_size,
                    ((ftp_session_attr_t*) temp_session->app_data)->filename,
                    ((ftp_session_attr_t*) temp_session->app_data)->file_download_finishtime_sec,
                    ((ftp_session_attr_t*) temp_session->app_data)->file_download_finishtime_usec,
                    ((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_sec,
                    ((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_usec
            );
            message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
            //send_message_to_file ("ftp.download.report", message);
            if (probe_context->output_to_file_enable==1)send_message_to_file (message);
            if (probe_context->redis_enable==1)send_message_to_redis ("ftp.download.report", message);
            reset_ftp_parameters(ipacket,temp_session);
        }
    }
}
void ftp_file_size_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint32_t * file_size = (uint32_t *) attribute->data;
        if (file_size != NULL && temp_session->app_format_id == MMT_FTP_DOWNLOAD_REPORT_FORMAT ) {
            ((ftp_session_attr_t*) temp_session->app_data)->file_size = * file_size;
        }
    }
}
void ftp_file_name_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    //int valid;
    //char * name;
    //name= (char*)malloc(sizeof(char)*200);


    if (temp_session != NULL && temp_session->app_data != NULL) {
        char * file_name = (char *) attribute->data;
        //file_name=str_replace_all_char(file_name,'/','_');

        //valid=snprintf(name,MAX, "%lu.%lu_%s",((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_sec,((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_usec,file_name);
        //name[valid]='\0';

        if (file_name != NULL && temp_session->app_format_id == MMT_FTP_DOWNLOAD_REPORT_FORMAT) {
            ((ftp_session_attr_t*) temp_session->app_data)->filename=file_name;
        }
    }
}

void ftp_response_code_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint16_t * response_code = (uint16_t *) attribute->data;
        if (response_code != NULL && temp_session->app_format_id == MMT_FTP_DOWNLOAD_REPORT_FORMAT) {
            ((ftp_session_attr_t*) temp_session->app_data)->response_code= * response_code;
        }
        if(*response_code==150){
            ((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_sec = ipacket->p_hdr->ts.tv_sec;
            ((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_usec= ipacket->p_hdr->ts.tv_usec;
        }

    }
}

void * get_handler_by_name(char * func_name){

    if (strcmp(func_name,"ftp_file_name_handle")==0){
        return ftp_file_name_handle;
    }
    if (strcmp(func_name,"ftp_session_connection_type_handle")==0){
        return ftp_session_connection_type_handle;
    }
    if (strcmp(func_name,"ftp_user_name_handle")==0){
        return ftp_user_name_handle;
    }
    if (strcmp(func_name,"ftp_password_handle")==0){
        return ftp_password_handle;
    }
    if (strcmp(func_name,"ftp_response_value_handle")==0){
        return ftp_response_value_handle;
    }
    if (strcmp(func_name,"ftp_file_size_handle")==0){
        return ftp_file_size_handle;
    }
    if (strcmp(func_name,"ftp_packet_request_handle")==0){
        return ftp_packet_request_handle;
    }
    if (strcmp(func_name,"ftp_data_direction_handle")==0){
        return ftp_data_direction_handle;
    }
    if (strcmp(func_name,"ftp_response_code_handle")==0){
        return ftp_response_code_handle;
    }
    return 0;
}

int register_conditional_report_handle(void * handler, mmt_condition_report_t * condition_report) {
    int i = 1,j;
    if (strcmp(condition_report->condition.condition,"FTP")==0){
        for(j = 0; j < condition_report->attributes_nb; j++) {
            mmt_condition_attribute_t * condition_attribute = &condition_report->attributes[j];
            mmt_condition_attribute_t * handler_attribute = &condition_report->handlers[j];
            if (strcmp(handler_attribute->handler,"NULL")==0){
                i &= register_extraction_attribute_by_name(handler, condition_attribute->proto, condition_attribute->attribute);

            }else{
                i &= register_attribute_handler_by_name(handler, condition_attribute->proto,condition_attribute->attribute, get_handler_by_name (handler_attribute->handler), NULL, NULL);
            }
        }

    }
    return i;
}

void conditional_reports_init(void * handler) {
    int i;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    for(i = 0; i < probe_context->condition_reports_nb; i++) {
        mmt_condition_report_t * condition_report = &probe_context->condition_reports[i];
        if(register_conditional_report_handle(handler, condition_report) == 0) {
            fprintf(stderr, "Error while initializing condition report number %i!\n", condition_report->id);
            printf( "Error while initializing condition report number %i!\n", condition_report->id);
        }
    }
}


void register_ftp_attributes(void * handler){
    int i=1;
    i &=register_extraction_attribute(handler,PROTO_FTP,PROTO_PAYLOAD);
    i &=register_extraction_attribute(handler,PROTO_FTP,FTP_FILE_SIZE);
    i &=register_extraction_attribute(handler,PROTO_FTP,FTP_DATA_TYPE);
    i &=register_extraction_attribute(handler,PROTO_FTP,FTP_FILE_NAME);
    i &=register_extraction_attribute(handler,PROTO_FTP,FTP_PACKET_DATA_LEN);
    if(!i) {
        //TODO: we need a sound error handling mechanism! Anyway, we should never get here :)
        fprintf(stderr, "Error while initializing MMT handlers and extractions!\n");
    }


}

/*
void print_ftp_app_format(const mmt_session_t * expired_session,probe_internal_t * iprobe) {
    int keep_direction = 1;
    session_struct_t * temp_session = get_user_session_context(expired_session);
    char message[MAX_MESS + 1];
    char path[128];
    char * location;
	int i;
    mmt_probe_context_t * probe_context = get_probe_context_config();
    //proto_hierarchy_to_str(&expired_session->proto_path, path);
    uint64_t session_id = get_session_id(expired_session);



    if (probe_context->thread_nb > 1) {
        session_id <<= probe_context->thread_nb_2_power;
        session_id |= iprobe->instance_id;
    }
    //IP strings
    char ip_src_str[46];
    char ip_dst_str[46];
    if (temp_session->ipversion == 4) {
        inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
        keep_direction = is_local_net(temp_session->ipclient.ipv4);
        is_local_net(temp_session->ipserver.ipv4);
    } else {
        inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
    }

    proto_hierarchy_ids_to_str(get_session_protocol_hierarchy(expired_session), path);

    struct timeval init_time = get_session_init_time(expired_session);
    struct timeval end_time = get_session_last_activity_time(expired_session);
    const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(expired_session);
    for(i = 0; i < probe_context->condition_reports_nb; i++) {
        mmt_condition_report_t * condition_report = &probe_context->condition_reports[i];
        if (strcmp(condition_report->condition.condition,"FTP")==0 && ((ftp_session_attr_t*) temp_session->app_data)->file_size >1){
        	location=condition_report->condition.location;
        	snprintf(message, MAX_MESS,
        	        "%u,%u,\"%s\",%lu.%lu,%"PRIu64",%lu.%lu,%u,\"%s\",\"%s\",%hu,%hu,%"PRIu8",%s,%s,%"PRIu32",%s,%s",
        			MMT_FTP_APP_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, end_time.tv_sec, end_time.tv_usec,
        	        session_id,
        	        init_time.tv_sec, init_time.tv_usec,
        	        (int) temp_session->ipversion,
        	        ip_dst_str, ip_src_str,
        	        temp_session->serverport, temp_session->clientport,
					((ftp_session_attr_t*) temp_session->app_data)->session_conn_type,
        			((ftp_session_attr_t*) temp_session->app_data)->session_username,
        	        ((ftp_session_attr_t*) temp_session->app_data)->session_password,
        			((ftp_session_attr_t*) temp_session->app_data)->file_size,
        			((ftp_session_attr_t*) temp_session->app_data)->filename, location
        	    );
        	    message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
        	    send_message_to_file ("ftp.flow.report", message);

        }
    }
}
 */
