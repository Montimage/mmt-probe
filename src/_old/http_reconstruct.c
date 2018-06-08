/** Dependencies
 *  HTML parser
 *    git clone https://github.com/luongnv89/htmlstreamparser.git
 *    cd htmlstreamparser/
 *    ./configure
 *    make
 *    sudo make install
 *
 *  zlib
 *    sudo apt-get install zlib1g zlib1g-dev
 */


//TODOs: content reconstruction
// - add user data at session detection - OK
// - check it content encoding is gzip, and initialize gzip decoder if yes - OK
// - initialize (including creating the file) reconstruction at headers end event - OK
// - reconstruct into the initialized file handler at http.data events - OK
// - close file handler and gzip decoder (if any) at message end event, and cleanup reconstruction - OK
// - cleanup and free user data at session expiry - OK


//TODOs: html parsing
// - add user data at session detection - OK
// - check if content type is text/html and initialize html parser - OK
// - check it content encoding is gzip, and initialize gzip decoder if yes - OK
// - initialize processing at headers end event - OK
// - process data chunk at http.data events - OK
// - close html parser and gzip decoder (if any) and cleanup at message end event - OK
// - cleanup and free user data at session expiry - OK


#include <stdio.h>
#include <string.h>
#include <time.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "html_integration.h"

/**
 * copies into @fname the file name given session identifier and interaction count
 */
char* get_file_name(int session_id, int count) {
  char *filename = (char*)malloc(MAX_FILE_NAME*sizeof(char));
  snprintf(filename, MAX_FILE_NAME, "file_%i_%i", session_id, count);
  int real_len = strlen(filename) + 1;
  char *fname = (char*)malloc(real_len*sizeof(char));
  memcpy(fname,filename,real_len-1);
  fname[real_len-1]='\0';
  free(filename);
  return fname;
}


/**
 * Writes @len bytes from @content to the filename @path.
 */
void http_write_data_to_file ( char * path, const char * content, size_t len) {

    mmt_probe_context_t * probe_context = get_probe_context_config();

    char filename[MAX_FILE_NAME];
    snprintf(filename, MAX_FILE_NAME, "%s/%s", probe_context->HTTP_RECONSTRUCT_MODULE_output_location, path);
    filename[MAX_FILE_NAME-1] = '\0';
    // printf("[debug] Going to write to file: %s\n",filename);
    // printf("%s\n",content);
    int fd = 0;
    if ( (fd = open ( filename , O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO )) < 0 ){
        fprintf ( stderr , "\n[error] %d writting data to \"%s\": %s" , errno , filename , strerror( errno ) );
    }
    int nb_bytes = write ( fd , content , len );
    if(nb_bytes==0){
        fprintf(stderr, "[error] Write 0 bytes\n");
    }
    close ( fd );
}

/**
 * Get http_content_processor from ipacket
 * @param  ipacket [description]
 * @return         [description]
 */
http_content_processor_t * get_http_content_processor_from_packet(const ipacket_t * ipacket){
    session_struct_t *temp_session = (session_struct_t *)get_user_session_context_from_packet(ipacket);
    if(temp_session == NULL) return NULL;
    return temp_session->http_content_processor;
}


/**
 * Replace a character by another character in all string
 * @param  str string
 * @param  c1  ascii code number of character will be replaced
 * @param  c2  ascii code number of replacing character
 * @return     new string after replacing
 */
char * str_replace_all_char(char *str, int c1, int c2) {
    if(str == NULL) return NULL;
    char *new_str;
    new_str = (char*)malloc(strlen(str) + 1);
    memcpy(new_str, str, strlen(str));
    new_str[strlen(str)] = '\0';
    int i;
    for (i = 0; i < strlen(str); i++) {
        if ((int)new_str[i] == c1) {
            new_str[i] = (char)c2;
        }
    }
    // free(str);
    return new_str;
}

http_session_data_t * new_http_session_data() {
    http_session_data_t * new_http_data = (http_session_data_t * )malloc(sizeof(http_session_data_t));
    if (new_http_data) {
        new_http_data->session_id = -1;
        new_http_data->filename = NULL;
        new_http_data->content_type = NULL;
        new_http_data->next = NULL;
        new_http_data->http_session_status = 0;
        new_http_data->file_has_extension = 0;
        new_http_data->current_len = 0;
        new_http_data->total_len = 0;
        int i = 0;
        for ( i = 0; i < MAX_NB_DATA_PACKETS; ++i)
        {
            new_http_data->data_packets[i] = 0;
        }
    }
    return new_http_data;
}


void free_http_session_data(http_session_data_t* http_data) {
    if (http_data) {
        if (http_data->filename) {
            free(http_data->filename);
            http_data->filename = NULL;
        }

        if (http_data->content_type) {
            free(http_data->content_type);
            http_data->content_type = NULL;
        }

        http_data->session_id = -1;
        http_data->current_len = 0;
        http_data->http_session_status = 0;
        http_data->total_len = 0;
        http_data->file_has_extension = 0;
        int i = 0;
        for ( i = 0; i < MAX_NB_DATA_PACKETS; ++i)
        {
            http_data->data_packets[i] = 0;
        }
        free(http_data);
        http_data = NULL;
    }
}

void reset_http_session_data(http_session_data_t* http_data) {
    if (http_data) {
        if (http_data->filename) {
            free(http_data->filename);
            http_data->filename = NULL;
        }

        if (http_data->content_type) {
            free(http_data->content_type);
            http_data->content_type = NULL;
        }

        http_data->current_len = 0;
        http_data->http_session_status = HSDS_START;
        http_data->total_len = 0;
        http_data->file_has_extension = 0;
        int i = 0;
        for ( i = 0; i < MAX_NB_DATA_PACKETS; ++i)
        {
            http_data->data_packets[i] = 0;
        }
    }
}

/**
 * Add a packet ID into the list of data_packets
 * @param  http_data [description]
 * @param  packet_id [description]
 * @return           [description]
 */
int http_add_data_packet(http_session_data_t *  http_data, uint64_t packet_id){
    int i = 0;
    while(http_data->data_packets[i]!=0){
        if(http_data->data_packets[i] == packet_id) return 0;
        i++;
    }
    http_data->data_packets[i] = packet_id;
    return 1;
}

/**
 * Check if a packet is in a list of data_packets
 * @param  http_data [description]
 * @param  packet_id [description]
 * @return           [description]
 */
int http_check_data_packet(http_session_data_t * http_data, uint64_t packet_id){
    int i = 0;
    while(http_data->data_packets[i]!=0){
        if(http_data->data_packets[i] == packet_id) return 1;
        i++;
    }
    return 0;
}

http_session_data_t * get_http_session_data_by_id(uint64_t session_id, http_session_data_t * current_http_data) {
    if (current_http_data == NULL) return NULL;
    if (current_http_data->session_id == session_id) return current_http_data;
    return get_http_session_data_by_id(session_id, current_http_data->next);
}

void add_http_session_data(http_session_data_t * current_http_data, struct smp_thread * th) {
    if (current_http_data == NULL) {
        fprintf(stderr, "[error] Could not add NULL session\n");
        return;
    }

    if (th->list_http_session_data == NULL) {
        th->list_http_session_data = current_http_data;
    } else {
        http_session_data_t * cur_head = th->list_http_session_data;
        current_http_data->next = cur_head;
        th->list_http_session_data = current_http_data;
    }
}

char * get_extension_from_content_type(char *content_type) {
    if (strstr(content_type, "html")) return "html";
    if (strstr(content_type, "png") || strstr(content_type, "PNG")) return "png";
    if (strstr(content_type, "jpg") || strstr(content_type, "JPG")) return "jpg";
    if (strstr(content_type, "jpeg") || strstr(content_type, "JPEG")) return "jpeg";
    if (strstr(content_type, "zip") || strstr(content_type, "ZIP")) return "zip";
    if (strstr(content_type, "mp3") || strstr(content_type, "MP3")) return "mp3";
    if (strstr(content_type, "mp4") || strstr(content_type, "MP4")) return "mp4";
    if (strstr(content_type, "gif") || strstr(content_type, "GIF")) return "gif";
    if (strstr(content_type, "javascript") || strstr(content_type, "JAVASCRIPT")) return "js";
    if (strstr(content_type, "text/plain") || strstr(content_type, "TEXT/PLAIN")) return "txt";
    if (strstr(content_type, "css") || strstr(content_type, "CSS")) return "css";
    if (strstr(content_type, "svg") || strstr(content_type, "SVG")) return "svg";
    return "";
}


void update_file_extension(http_session_data_t * http_data) {
    char *filename = malloc(MAX_FILE_NAME * sizeof(char));
    if (filename) {
        snprintf(filename, MAX_FILE_NAME, "%s.%s", http_data->filename, get_extension_from_content_type(http_data->content_type));
        free(http_data->filename);
        int real_len = strlen(filename) + 1;
        http_data->filename = (char*)malloc(real_len*sizeof(char));
        memcpy(http_data->filename,filename,real_len-1);
        http_data->filename[real_len-1]='\0';
        http_data->file_has_extension = 1;
        free(filename);
        // http_data->filename = filename;
    } else {
        fprintf(stderr, "Cannot allocate memory!\n");
    }
}

/**
 * Attribute handler that will be called every time an HTTP message start event is detected
 */
void http_message_start_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    // debug("%lu: http_message_start_handle - 1\n", ipacket->packet_id);
    if (ipacket->session == NULL) return;
    struct smp_thread *th = (struct smp_thread *) user_args;
    uint64_t session_id = get_session_id(ipacket->session);
    http_session_data_t * http_session_data = get_http_session_data_by_id(session_id, th->list_http_session_data);
    if (http_session_data == NULL) {
        http_session_data = new_http_session_data();
        if (http_session_data) {
            http_session_data->session_id = session_id;
            http_session_data->http_session_status = HSDS_TRANSFER;
            add_http_session_data(http_session_data,th);
        } else {
            fprintf(stderr, "[error] Cannot create http session data for session %lu - packet: %lu\n", session_id, ipacket->packet_id);
        }
    } else {
        http_session_data->http_session_status = HSDS_TRANSFER;
    }
    // debug("%lu: %s.%s: %i\n", ipacket->packet_id, get_protocol_name_by_id(attribute->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id), *((uint32_t *) attribute->data));
    // debug("%lu: http_message_start_handle - 2\n", ipacket->packet_id);
}

/**
 * Attribute handler that will be called every time an HTTP header is detected
 * Checks if the content encoding iz gzip to initialize the gzip pre processor
 * and checks if the content type is htmp to initialize the html parser
 */
void http_generic_header_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    // debug("%lu: generic_header_handle - 1\n", ipacket->packet_id);
    mmt_session_t * session = get_session_from_packet(ipacket);
    if (session == NULL) return;
    http_content_processor_t * sp = get_http_content_processor_from_packet(ipacket);
    if (sp == NULL) return;
    mmt_generic_header_line_t * header_data = (mmt_generic_header_line_t *) attribute->data;
    // debug("%lu: generic_header_handle - 2\n", ipacket->packet_id);
    if ( check_str_eq( "Content-Encoding", header_data->hfield) &&
            check_str_eq( "gzip", header_data->hvalue) ) {
        // printf("[debug] %lu content is compressed!\n", ipacket->packet_id);
        sp->content_encoding = 1; //Content encoding is gzip
    }
    // debug("%lu: generic_header_handle - 3\n", ipacket->packet_id);
    if ( check_str_eq( "Content-Type", header_data->hfield) &&
            check_str_eq( "text/html", header_data->hvalue)) {
        sp->content_type = 1; // Content type is html
    }
    struct smp_thread *th = (struct smp_thread *) user_args;
    http_session_data_t * http_session_data = get_http_session_data_by_id(get_session_id(ipacket->session), th->list_http_session_data);
    if (check_str_eq( "Content-Type", header_data->hfield)) {
        if (http_session_data) {
            int hlen = strlen(header_data->hvalue) + 1;
            http_session_data->content_type = (char*)malloc(hlen*sizeof(char));
            memcpy(http_session_data->content_type,header_data->hvalue,hlen-1);
            http_session_data->content_type[hlen-1]='\0';
            // printf("[debug] %lu generic_header_handle: content_type: %s\n", ipacket->packet_id, http_session_data->content_type);
            if (http_session_data->filename && !http_session_data->file_has_extension) {
                update_file_extension(http_session_data);
            }
        }
    }

    if (check_str_eq( "Content-Length", header_data->hfield)) {
        if (http_session_data) {
            http_session_data->total_len = atoi(header_data->hvalue);
        }
    }

    // debug("%lu: generic_header_handle - 4\n", ipacket->packet_id);
    // debug("%lu: %s.%s: %s: %s\n", ipacket->packet_id,get_protocol_name_by_id(attribute->proto_id),get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),((mmt_generic_header_line_t *) attribute->data)->hfield,((mmt_generic_header_line_t *) attribute->data)->hvalue);
    // debug("%lu: generic_header_handle - 5\n", ipacket->packet_id);
}

/**
 * Attribute handler that will be called every time HTTP en of headers is detected
 * Initializes the gzip pre processor and the html parser if content encoding is gzip
 * and content type is html respectively.
 */
void http_headers_end_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    // debug("%lu: http_headers_end_handle - 1\n", ipacket->packet_id);
    mmt_session_t * session = get_session_from_packet(ipacket);
    if (session == NULL) return;
    // debug("%lu: http_headers_end_handle - 2\n", ipacket->packet_id);
    http_content_processor_t * sp = get_http_content_processor_from_packet(ipacket);
    if (sp == NULL) return;
    // debug("%lu: http_headers_end_handle - 3\n", ipacket->packet_id);
    if ( sp->content_encoding == 1 ) sp->pre_processor = (void *) init_gzip_processor();
    // debug("%lu: http_headers_end_handle - 4\n", ipacket->packet_id);
    if ( sp->content_type == 1 ) sp->processor = (void *) init_html_parser();
    // debug("%lu: http_headers_end_handle - 5\n", ipacket->packet_id);
    // debug("%lu: %s.%s: %i\n", ipacket->packet_id,get_protocol_name_by_id(attribute->proto_id),get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),*((uint32_t *) attribute->data));
    // debug("%lu: http_headers_end_handle - 6\n", ipacket->packet_id);
}

/**
 * Attribute handle that will be called every time an HTTP message end is detected
 * Cleans up the HTTP content processing structure and prepares it to a new message eventually.
 */
void http_message_end_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    // debug("%lu: http_message_end_handle - 1\n", ipacket->packet_id);
    mmt_session_t * session = get_session_from_packet(ipacket);
    if (session == NULL) return;
    // debug("%lu: http_message_end_handle - 2\n", ipacket->packet_id);
    http_content_processor_t * sp = get_http_content_processor_from_packet(ipacket);
    if (sp == NULL) return;
    // debug("%lu: http_message_end_handle - 3\n", ipacket->packet_id);
    clean_http_content_processor(sp);
    // debug("%lu: http_message_end_handle - 4\n", ipacket->packet_id);
    struct smp_thread *th = (struct smp_thread *) user_args;
    http_session_data_t * http_session_data = get_http_session_data_by_id(get_session_id(session), th->list_http_session_data);
    if (http_session_data) {
        if (http_session_data->filename && http_session_data->content_type) {
            // printf("[debug] %lu Transferred completed %s content_type: %s\n",ipacket->packet_id, http_session_data->filename, http_session_data->content_type);
        }
        reset_http_session_data(http_session_data);
    }
    // debug("%lu: %s.%s: %i\n", ipacket->packet_id,get_protocol_name_by_id(attribute->proto_id),get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),*((uint32_t *) attribute->data));
    // debug("%lu: http_message_end_handle - 5\n", ipacket->packet_id);
}

/**
 * Attribute handle that will be called for every HTTP body data chunk
 * The chunk will be process to by the gzip pre processor if content encoding
 * is gzip, then it will be processed by the html parser.
 * In all cases, the chunk will be saved into a file whose name containes the session ID
 * and the interaction number in the session to take into account keep alive HTTP sessions
 */
void http_data_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    // printf("%lu: data_handle - 1\n", ipacket->packet_id);
    mmt_session_t * session = get_session_from_packet(ipacket);

    char fname[128];

    if (session == NULL) return;
    // debug("%lu: data_handle - 2\n", ipacket->packet_id);
    http_content_processor_t * sp = get_http_content_processor_from_packet(ipacket);
    // if (sp == NULL) return;
    struct smp_thread *th = (struct smp_thread *) user_args;
    http_session_data_t * http_session_data = get_http_session_data_by_id(get_session_id(session), th->list_http_session_data);
    if (http_session_data) {
        if (http_session_data->filename == NULL) {
            http_session_data->filename = get_file_name(get_session_id(session), sp->interaction_count);
        }
        if (http_session_data->content_type && !http_session_data->file_has_extension) {
            update_file_extension(http_session_data);
        }
        http_session_data->current_len += ((mmt_header_line_t *) attribute->data)->len;
    }

    // debug("%lu: data_handle - 3\n", ipacket->packet_id);
    //Process body
    if (sp && sp->content_encoding ) {
        // debug("%lu: data_handle - 4\n", ipacket->packet_id);
        if ( sp->pre_processor ) {
            // debug("%lu: data_handle - 5\n", ipacket->packet_id);
            gzip_processor_t * gzp = (gzip_processor_t *) sp->pre_processor;
            if (http_session_data->filename) {
                gzip_process(((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len, gzp, sp, http_session_data->filename);
            } else {
                gzip_process(((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len, gzp, sp, NULL);
            }

        }
    } else if ( sp && sp->content_type && sp->processor ) {
        // debug("%lu: data_handle - 6\n", ipacket->packet_id);
        html_parser_t * hp = (html_parser_t *) sp->processor;
        html_parse(((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len, hp, sp);
        // debug("%lu: data_handle - 7\n", ipacket->packet_id);
    }

    if(!sp || !sp->content_encoding){
        // printf("%lu: data_handle - 2\n", ipacket->packet_id);
        http_write_data_to_file (http_session_data->filename, ((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len);
        http_add_data_packet(http_session_data,ipacket->packet_id);
    }

    // debug("%lu: data_handle - 8\n", ipacket->packet_id);
    // debug("%lu: %s.%s: %i\n", ipacket->packet_id,get_protocol_name_by_id(attribute->proto_id),get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),((mmt_header_line_t *) attribute->data)->len);
    // debug("%lu: data_handle - 9\n", ipacket->packet_id);
}

int http_packet_handler(const ipacket_t * ipacket, void * user_args) {
    // printf("[debug] http_packet_handler 1 :%lu\n", ipacket->packet_id);

    if (ipacket->session == NULL) {
        // fprintf(stderr, "[error] %lu: Packet does not have session\n", ipacket->packet_id);
        return 0;
    }

    uint64_t session_id = get_session_id(ipacket->session);

    mmt_probe_context_t * probe_context = get_probe_context_config();

    if(probe_context == NULL){
        fprintf(stderr, "[error] %lu: Cannot get probe context\n", ipacket->packet_id);
        return 0;
    }

    if(probe_context->HTTP_RECONSTRUCT_MODULE_enable == 0){
        printf("[debug] %lu HTTP_RECONSTRUCT_MODULE is not enabled\n", ipacket->packet_id);
        return 0;
    }

    if(is_http_packet(ipacket)==0) return 0;
    // printf("[debug] http_packet_handler 2 :%lu\n", ipacket->packet_id);
    struct smp_thread *th = (struct smp_thread *) user_args;
    http_session_data_t * http_session_data = get_http_session_data_by_id(session_id, th->list_http_session_data);

    http_content_processor_t * sp = get_http_content_processor_from_packet(ipacket);
    if (http_session_data) {
        // printf("[debug] http_packet_handler 3 :%lu\n", ipacket->packet_id);
        if (http_session_data->filename == NULL) {
            if (sp == NULL) {
                http_session_data->filename = get_file_name(session_id, 0);
            } else {
                http_session_data->filename = get_file_name(session_id, sp->interaction_count);
            }
            if (http_session_data->content_type && !http_session_data->file_has_extension) {
                update_file_extension(http_session_data);
            }
        }

        // Update content type
        if (http_session_data->content_type == NULL) {
            mmt_header_line_t * content_type = (mmt_header_line_t *)get_attribute_extracted_data_by_name(ipacket, "http", "content_type");
            if (content_type) {
                char * data_type = (char*)malloc((content_type->len + 1) * sizeof(char));
                memcpy(data_type, content_type->ptr, content_type->len);
                data_type[content_type->len] = '\0';
                http_session_data->content_type = data_type;
            }
        }
        // Update uri name
        mmt_header_line_t * uri = (mmt_header_line_t *)get_attribute_extracted_data_by_name(ipacket, "http", "uri");
        if (uri) {
            char * pre_uri_data = malloc((uri->len + 1) * sizeof(char));
            char * uri_data = NULL;
            memcpy(pre_uri_data, uri->ptr, uri->len);
            pre_uri_data[uri->len] = '\0';
            if(pre_uri_data){
                uri_data = str_replace_all_char(pre_uri_data, '/', '_');
                free(pre_uri_data);
            }
            char* default_name = NULL;
            if (str_compare(uri_data, "_") == 1) {
                if (http_session_data->filename != NULL) {
                    int len = strlen(http_session_data->filename) + 7;
                    default_name = malloc(len * sizeof(char));
                    snprintf(default_name, len, "index_%s", http_session_data->filename);
                    default_name[len - 1] = '\0';
                    free(http_session_data->filename);
                    http_session_data->filename = NULL;
                } else {
                    int len = 7;
                    default_name = malloc(len * sizeof(char));
                    strcpy(default_name, "index_");
                    default_name[len - 1] = '\0';
                }
            } else {

                if(strstr(uri_data,"?")!=NULL){
                    default_name = str_subvalue(uri_data,NULL,"?");
                }else{
                    default_name = str_copy(uri_data);
                }

                if(default_name){
                    if(http_session_data->filename !=NULL){
                        free(http_session_data->filename );
                    }
                    http_session_data->filename = str_copy(default_name);
                    if(strstr(http_session_data->filename,".")){
                        http_session_data->file_has_extension = 1;
                    }
                }else{
                    int len = 7;
                    default_name = malloc(len * sizeof(char));
                    strcpy(default_name, "index_");
                    default_name[len - 1] = '\0';
                }
            }

            if(http_session_data->filename!=NULL){
                free(http_session_data->filename);
                // http_session_data->filename = NULL;
            }
            http_session_data->filename = default_name;

            if (http_session_data->content_type && !http_session_data->file_has_extension) {
                update_file_extension(http_session_data);
            }
            // printf("[debug] %lu packet_handler new file name: uri: %s\n", ipacket->packet_id, http_session_data->filename);
            free(uri_data);
        }
    }
    mmt_header_line_t * http_method = (mmt_header_line_t *)get_attribute_extracted_data_by_name(ipacket, "http", "method");
    mmt_header_line_t * http_response = (mmt_header_line_t *)get_attribute_extracted_data_by_name(ipacket, "http", "response");
    char * tcp_payload = (char*)get_attribute_extracted_data_by_name(ipacket, "tcp", "p_payload");
    uint32_t * payload_len = (uint32_t *)get_attribute_extracted_data_by_name(ipacket, "tcp", "payload_len");
    if (tcp_payload && payload_len && *payload_len > 0 && http_method == NULL && http_response == NULL) {
        if (http_session_data) {
            // debug("http_packet_handler of packet: %lu in session: %lu (http_data session: %lu)",ipacket->packet_id, get_session_id(ipacket->session), http_session_data->session_id);
            if (http_session_data->http_session_status == HSDS_TRANSFER) {
                if ( sp && sp->content_encoding ) {
                    // debug("%lu: packet_handler - 4\n", ipacket->packet_id);
                    if ( sp->pre_processor ) {
                        // debug("%lu: packet_handler - 5\n", ipacket->packet_id);
                        gzip_processor_t * gzp = (gzip_processor_t *) sp->pre_processor;
                        http_session_data->current_len += *payload_len;
                        gzip_process(tcp_payload, *payload_len, gzp, sp, http_session_data->filename);
                    }
                } else {
                    if( http_check_data_packet(http_session_data,ipacket->packet_id) == 0){
                        http_session_data->current_len += *payload_len;
                        // printf("[debug] http_packet_handler 2 :%lu\n", ipacket->packet_id);
                        http_write_data_to_file (http_session_data->filename, tcp_payload, *payload_len);
                        http_add_data_packet(http_session_data,ipacket->packet_id);
                    }
                }
            }
        }
    }
    return 0;
}

/**
 * Cleans and closes the HTTP content processing structure
 */
void * close_http_content_processor(http_content_processor_t * sp) {
  if( sp->processor ) sp->processor = clean_html_parser( (html_parser_t *) sp->processor );
  if( sp->pre_processor ) clean_gzip_processor( (gzip_processor_t *) sp->pre_processor);

  sp->content_type = 0;
  sp->content_encoding = 0;

  free( sp );
  return NULL;
}

void clean_http_session_data(uint64_t session_id, struct smp_thread * th){
    // debug("clean_http_session_data : %lu",session_id );
    // fprintf(stderr, "[debug] clean_http_session_data : %lu\n",session_id );
    if(th->list_http_session_data == NULL)  {
        // fprintf(stderr, "[error] Cannot find http_session_data with id: %lu\n",session_id);
        return;
    }

    http_session_data_t * current_http_data = th->list_http_session_data;
    if(current_http_data->session_id == session_id){
        th->list_http_session_data = current_http_data->next;
        free_http_session_data(current_http_data);
        return;
    }

    http_session_data_t *next_http_data = current_http_data->next;
    while(next_http_data!=NULL){
        if(next_http_data->session_id == session_id){
            current_http_data->next = next_http_data->next;
            free_http_session_data(next_http_data);
            return;
        }else{
            current_http_data = next_http_data;
            next_http_data = current_http_data->next;
        }
    }
    fprintf(stderr, "[error] Cannot find http_session_data with id: %lu\n",session_id);
}

void HTTP_RECONSTRUCT_MODULE_init(void *arg){
    struct smp_thread *th = (struct smp_thread *) arg;
    register_packet_handler(th->mmt_handler, 11, http_packet_handler, arg);
    // register_session_timeout_handler(th->mmt_handler, http_classification_expiry_session, NULL);
    // printf("[debug] HTTP_RECONSTRUCT_MODULE_init\n");
}

