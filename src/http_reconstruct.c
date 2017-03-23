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

/**
 * gcc -g -o http_reconstruct_body reconstruct_body.c html_integration.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap -lhtmlstreamparser -lz
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include "mmt_core.h"
#include "html_integration.h"
#include <assert.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define MTU_BIG (16 * 1024)
#define HSDS_START 1
#define HSDS_TRANSFER 2
#define HSDS_END 3

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


typedef struct http_session_data_struct {
    uint64_t session_id;
    uint64_t http_session_status;
    char * filename;
    char * content_type;
    uint64_t current_len;
    uint64_t total_len;
    uint8_t file_has_extension;
    struct http_session_data_struct *next;
} http_session_data_t;

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
    }
}

static http_session_data_t * list_http_session_data = NULL;

http_session_data_t * get_http_session_data_by_id(uint64_t session_id, http_session_data_t * current_http_data) {
    if (current_http_data == NULL) return NULL;
    if (current_http_data->session_id == session_id) return current_http_data;
    return get_http_session_data_by_id(session_id, current_http_data->next);
}

void add_http_session_data(http_session_data_t * current_http_data) {
    if (current_http_data == NULL) {
        fprintf(stderr, "[ERROR] Could not add NULL session\n");
        return;
    }

    if (list_http_session_data == NULL) {
        list_http_session_data = current_http_data;
    } else {
        http_session_data_t * cur_head = list_http_session_data;
        current_http_data->next = cur_head;
        list_http_session_data = current_http_data;
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
    char *filename = malloc(128 * sizeof(char));
    if (filename) {
        snprintf(filename, 128, "%s.%s", http_data->filename, get_extension_from_content_type(http_data->content_type));
        free(http_data->filename);
        http_data->filename = filename;
        http_data->file_has_extension = 1;
    } else {
        fprintf(stderr, "Cannot allocate memory!\n");
    }
}

/**
 * Prints the usage help instructions
 */
void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

/**
 * Parses command line options and performes pre-initialization
 */
void parseOptions(int argc, char ** argv, char * filename, int * type) {
    int opt, optcount = 0;
    while ((opt = getopt(argc, argv, "t:i:h")) != EOF) {
        switch (opt) {
        case 't':
            optcount++;
            if (optcount > 1) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = TRACE_FILE;
            break;
        case 'i':
            optcount++;
            if (optcount > 1) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = LIVE_INTERFACE;
            break;
        case 'h':
        default: usage(argv[0]);
        }
    }

    if (filename == NULL || strcmp(filename, "") == 0) {
        if (*type == TRACE_FILE) {
            fprintf(stderr, "Missing trace file name\n");
        }
        if (*type == LIVE_INTERFACE) {
            fprintf(stderr, "Missing network interface name\n");
        }
        usage(argv[0]);
    }
    return;
}

/**
 * Attribute handle for IP new sessions.
 * Will be called every time a new session is detected.
 * Initializes an HTTP content processing structure and attaches it
 * to the MMT session.
 */
void new_session_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    printf(" %lu: new_session_handle - 1\n", ipacket->packet_id);
    mmt_session_t * session = get_session_from_packet(ipacket);
    if (session == NULL) return;

    if (attribute->data == NULL) {
        return; //This should never happen! check it anyway
    }
    printf(" %lu: new_session_handle - 2\n", ipacket->packet_id);
    http_content_processor_t * temp_session = init_http_content_processor();

    if (temp_session == NULL) {
        return;
    }
    printf(" %lu: new_session_handle - 3\n", ipacket->packet_id);
    set_user_session_context(session, temp_session);
    printf(" %lu: new_session_handle - 4\n", ipacket->packet_id);
    http_session_data_t * http_session_data = get_http_session_data_by_id(get_session_id(session), list_http_session_data);
    if (http_session_data == NULL) {
        http_session_data = new_http_session_data();
        if (http_session_data) {
            http_session_data->session_id = get_session_id(session);
            http_session_data->http_session_status = HSDS_START;
            add_http_session_data(http_session_data);
        } else {
            fprintf(stderr, "[ERROR] Cannot create http session data for session %lu - packet: %lu\n", get_session_id(session), ipacket->packet_id);
        }
    }
}

/**
 * Attribute handler that will be called every time an HTTP message start event is detected
 */
void http_message_start_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    printf(" %lu: http_message_start_handle - 1\n", ipacket->packet_id);
    if (ipacket->session == NULL) return;

    uint64_t session_id = get_session_id(ipacket->session);
    http_session_data_t * http_session_data = get_http_session_data_by_id(session_id, list_http_session_data);
    if (http_session_data == NULL) {
        http_session_data = new_http_session_data();
        if (http_session_data) {
            http_session_data->session_id = session_id;
            http_session_data->http_session_status = HSDS_TRANSFER;
            add_http_session_data(http_session_data);
        } else {
            fprintf(stderr, "[ERROR] Cannot create http session data for session %lu - packet: %lu\n", session_id, ipacket->packet_id);
        }
    } else {
        http_session_data->http_session_status = HSDS_TRANSFER;
    }
    printf(" %lu: %s.%s: %i\n", ipacket->packet_id,
           get_protocol_name_by_id(attribute->proto_id),
           get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
           *((uint32_t *) attribute->data)
          );
    printf(" %lu: http_message_start_handle - 2\n", ipacket->packet_id);
}

/**
 * Attribute handler that will be called every time an HTTP header is detected
 * Checks if the content encoding iz gzip to initialize the gzip pre processor
 * and checks if the content type is htmp to initialize the html parser
 */
void generic_header_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    printf(" %lu: generic_header_handle - 1\n", ipacket->packet_id);
    mmt_session_t * session = get_session_from_packet(ipacket);
    if (session == NULL) return;
    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context_from_packet(ipacket);
    if (sp == NULL) return;
    printf(" %lu: generic_header_handle - 2\n", ipacket->packet_id);
    if ( check_str_eq( "Content-Encoding", ((mmt_generic_header_line_t *) attribute->data)->hfield) &&
            check_str_eq( "gzip", ((mmt_generic_header_line_t *) attribute->data)->hvalue) ) {
        printf("--> %lu content is compressed!\n", ipacket->packet_id);
        sp->content_encoding = 1; //Content encoding is gzip
    }
    printf(" %lu: generic_header_handle - 3\n", ipacket->packet_id);
    if ( check_str_eq( "Content-Type", ((mmt_generic_header_line_t *) attribute->data)->hfield) &&
            check_str_eq( "text/html", ((mmt_generic_header_line_t *) attribute->data)->hvalue)) {
        sp->content_type = 1; // Content type is html
    }
    http_session_data_t * http_session_data = get_http_session_data_by_id(get_session_id(ipacket->session), list_http_session_data);
    if (check_str_eq( "Content-Type", ((mmt_generic_header_line_t *) attribute->data)->hfield)) {
        if (http_session_data) {
            http_session_data->content_type = str_copy(((mmt_generic_header_line_t *) attribute->data)->hvalue);
            printf("--> generic_header_handle: %lu content_type: %s\n", ipacket->packet_id, http_session_data->content_type);
            if (http_session_data->filename && !http_session_data->file_has_extension) {
                update_file_extension(http_session_data);
            }
        }
    }

    if (check_str_eq( "Content-Length", ((mmt_generic_header_line_t *) attribute->data)->hfield)) {
        if (http_session_data) {
            http_session_data->total_len = atoi(((mmt_generic_header_line_t *) attribute->data)->hvalue);
        }
    }

    printf(" %lu: generic_header_handle - 4\n", ipacket->packet_id);
    printf(" %lu: %s.%s: %s: %s\n", ipacket->packet_id,
           get_protocol_name_by_id(attribute->proto_id),
           get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
           ((mmt_generic_header_line_t *) attribute->data)->hfield,
           ((mmt_generic_header_line_t *) attribute->data)->hvalue
          );
    printf(" %lu: generic_header_handle - 5\n", ipacket->packet_id);
}

/**
 * Attribute handler that will be called every time HTTP en of headers is detected
 * Initializes the gzip pre processor and the html parser if content encoding is gzip
 * and content type is html respectively.
 */
void http_headers_end_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    printf(" %lu: http_headers_end_handle - 1\n", ipacket->packet_id);
    mmt_session_t * session = get_session_from_packet(ipacket);
    if (session == NULL) return;
    printf(" %lu: http_headers_end_handle - 2\n", ipacket->packet_id);
    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context_from_packet(ipacket);
    if (sp == NULL) return;
    printf(" %lu: http_headers_end_handle - 3\n", ipacket->packet_id);
    if ( sp->content_encoding == 1 ) sp->pre_processor = (void *) init_gzip_processor();
    printf(" %lu: http_headers_end_handle - 4\n", ipacket->packet_id);
    if ( sp->content_type == 1 ) sp->processor = (void *) init_html_parser();
    printf(" %lu: http_headers_end_handle - 5\n", ipacket->packet_id);
    printf(" %lu: %s.%s: %i\n", ipacket->packet_id,
           get_protocol_name_by_id(attribute->proto_id),
           get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
           *((uint32_t *) attribute->data)
          );
    printf(" %lu: http_headers_end_handle - 6\n", ipacket->packet_id);
}

/**
 * Attribute handle that will be called every time an HTTP message end is detected
 * Cleans up the HTTP content processing structure and prepares it to a new message eventually.
 */
void http_message_end_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    printf(" %lu: http_message_end_handle - 1\n", ipacket->packet_id);
    mmt_session_t * session = get_session_from_packet(ipacket);
    if (session == NULL) return;
    printf(" %lu: http_message_end_handle - 2\n", ipacket->packet_id);
    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context_from_packet(ipacket);
    if (sp == NULL) return;
    printf(" %lu: http_message_end_handle - 3\n", ipacket->packet_id);
    clean_http_content_processor(sp);
    printf(" %lu: http_message_end_handle - 4\n", ipacket->packet_id);
    http_session_data_t * http_session_data = get_http_session_data_by_id(get_session_id(session), list_http_session_data);
    if (http_session_data) {
        if (http_session_data->filename && http_session_data->content_type) {
            printf("--> Transferred completed %s content_type: %s\n", http_session_data->filename, http_session_data->content_type);
        }
        reset_http_session_data(http_session_data);
    }
    printf(" %lu: %s.%s: %i\n", ipacket->packet_id,
           get_protocol_name_by_id(attribute->proto_id),
           get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
           *((uint32_t *) attribute->data)
          );
    printf(" %lu: http_message_end_handle - 5\n", ipacket->packet_id);
}

/**
 * Attribute handle that will be called for every HTTP body data chunk
 * The chunk will be process to by the gzip pre processor if content encoding
 * is gzip, then it will be processed by the html parser.
 * In all cases, the chunk will be saved into a file whose name containes the session ID
 * and the interaction number in the session to take into account keep alive HTTP sessions
 */
void data_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    printf(" %lu: data_handle - 1\n", ipacket->packet_id);
    mmt_session_t * session = get_session_from_packet(ipacket);

    char fname[128];

    if (session == NULL) return;
    printf(" %lu: data_handle - 2\n", ipacket->packet_id);
    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context_from_packet(ipacket);
    // if (sp == NULL) return;

    http_session_data_t * http_session_data = get_http_session_data_by_id(get_session_id(session), list_http_session_data);
    if (http_session_data) {
        if (http_session_data->filename == NULL) {
            get_file_name(fname, 128, get_session_id(session), sp->interaction_count);
            http_session_data->filename = str_copy(fname);
        }
        if (http_session_data->content_type && !http_session_data->file_has_extension) {
            update_file_extension(http_session_data);
        }
        http_session_data->current_len += ((mmt_header_line_t *) attribute->data)->len;
    }

    printf(" %lu: data_handle - 3\n", ipacket->packet_id);
    //Process body
    if (sp && sp->content_encoding ) {
        printf(" %lu: data_handle - 4\n", ipacket->packet_id);
        if ( sp->pre_processor ) {
            printf(" %lu: data_handle - 5\n", ipacket->packet_id);
            gzip_processor_t * gzp = (gzip_processor_t *) sp->pre_processor;
            if (http_session_data->filename) {
                gzip_process(((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len, gzp, sp, http_session_data->filename);
            } else {
                gzip_process(((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len, gzp, sp, NULL);
            }

        }
    } else if ( sp && sp->content_type && sp->processor ) {
        printf(" %lu: data_handle - 6\n", ipacket->packet_id);
        html_parser_t * hp = (html_parser_t *) sp->processor;
        html_parse(((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len, hp, sp);
        printf(" %lu: data_handle - 7\n", ipacket->packet_id);
    }

    if(!sp || !sp->content_encoding){
        write_data_to_file (http_session_data->filename, ((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len);
    }
    
    printf(" %lu: data_handle - 8\n", ipacket->packet_id);
    printf(" %lu: %s.%s: %i\n", ipacket->packet_id,
           get_protocol_name_by_id(attribute->proto_id),
           get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
           ((mmt_header_line_t *) attribute->data)->len
          );
    printf(" %lu: data_handle - 9\n", ipacket->packet_id);
}

int packet_handler(const ipacket_t * ipacket, void * user_args) {

    if (ipacket->session == NULL) return 0;

    http_session_data_t * http_session_data = get_http_session_data_by_id(get_session_id(ipacket->session), list_http_session_data);

    char * tcp_payload = (char*)get_attribute_extracted_data_by_name(ipacket, "tcp", "p_payload");
    uint32_t * payload_len = (uint32_t *)get_attribute_extracted_data_by_name(ipacket, "tcp", "payload_len");
    mmt_header_line_t * http_method = (mmt_header_line_t *)get_attribute_extracted_data_by_name(ipacket, "http", "method");
    mmt_header_line_t * http_response = (mmt_header_line_t *)get_attribute_extracted_data_by_name(ipacket, "http", "response");
    mmt_header_line_t * uri = (mmt_header_line_t *)get_attribute_extracted_data_by_name(ipacket, "http", "uri");
    mmt_header_line_t * content_type = (mmt_header_line_t *)get_attribute_extracted_data_by_name(ipacket, "http", "content_type");
    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context_from_packet(ipacket);
    if (http_session_data) {
        if (http_session_data->filename == NULL) {
            http_session_data->filename = malloc(128 * sizeof(char));
            if (sp == NULL) {
                get_file_name(http_session_data->filename, 128, get_session_id(ipacket->session), 0);
            } else {
                get_file_name(http_session_data->filename, 128, get_session_id(ipacket->session), sp->interaction_count);
            }
            if (http_session_data->content_type && !http_session_data->file_has_extension) {
                update_file_extension(http_session_data);
            }
        }
        if (content_type) {
            char * data_type = malloc((content_type->len + 1) * sizeof(char));
            memcpy(data_type, content_type->ptr, content_type->len);
            data_type[content_type->len] = '\0';
            if (http_session_data->content_type == NULL) {
                http_session_data->content_type = data_type;
                printf("--> packet_handler: %lu content_type: %s\n", ipacket->packet_id, http_session_data->content_type);
            }
        }
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
                
                if(strstr(default_name,"?")!=NULL){
                    default_name = str_subvalue(uri_data,NULL,"?");
                }else{
                    default_name = str_copy(uri_data);
                }

                if(default_name){
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
            
            http_session_data->filename = default_name;

            if (http_session_data->content_type && !http_session_data->file_has_extension) {
                update_file_extension(http_session_data);
            }
            printf("--> packet_handler new file name: %lu uri: %s\n", ipacket->packet_id, http_session_data->filename);
            free(uri_data);
        }
    }

    // printf("%lu: http_method %p and http_response %p\n", ipacket->packet_id, http_method, http_response);
    if (tcp_payload && payload_len && *payload_len > 0 && http_method == NULL && http_response == NULL) {
        if (http_session_data) {
            if (http_session_data->http_session_status == HSDS_TRANSFER) {
                if ( sp && sp->content_encoding ) {
                    printf(" %lu: packet_handler - 4\n", ipacket->packet_id);
                    if ( sp->pre_processor ) {
                        printf(" %lu: packet_handler - 5\n", ipacket->packet_id);
                        gzip_processor_t * gzp = (gzip_processor_t *) sp->pre_processor;
                        http_session_data->current_len += *payload_len;
                        gzip_process(tcp_payload, *payload_len, gzp, sp, http_session_data->filename);
                    }
                } else {
                    http_session_data->current_len += *payload_len;
                    write_data_to_file (http_session_data->filename, tcp_payload, *payload_len);
                }
            }
        }
    }
    return 0;
}

/**
 * Session expiry handler that will be called every time MMT core detects a session expiry
 * Close the HTTP content processing structure
 */
void classification_expiry_session(const mmt_session_t * expired_session, void * args) {
    //fprintf(stdout, "Test from expiry session\n");
    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context(expired_session);
    if (sp == NULL) return;

    sp = close_http_content_processor(sp);
}

/**
 * Pcap live capture callback
 */
void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
    mmt_handler_t *mmt = (mmt_handler_t*)user;
    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;
    if (!packet_process( mmt, &header, data )) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}

int main(int argc, char** argv) {
    mmt_handler_t *mmt_handler;
    char mmt_errbuf[1024];

    pcap_t *pcap;
    const unsigned char *data;
    struct pcap_pkthdr p_pkthdr;
    char errbuf[1024];
    char filename[MAX_FILENAME_SIZE + 1];
    int type;

    struct pkthdr header;

    parseOptions(argc, argv, filename, &type);

    init_extraction();

    //Initialize an MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) { /* pcap error ? */
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
        return EXIT_FAILURE;
    }

    // Register attribute handlers
    register_attribute_handler_by_name(mmt_handler, "http", "msg_start", http_message_start_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "http", "header", generic_header_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "http", "headers_end", http_headers_end_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "http", "data", data_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "http", "msg_end", http_message_end_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "ip", "session", new_session_handle, NULL, NULL);
    register_extraction_attribute_by_name(mmt_handler, "tcp", "payload_len"); //Request TCP sequence number
    register_extraction_attribute_by_name(mmt_handler, "http", "method");
    register_extraction_attribute_by_name(mmt_handler, "http", "response");
    register_extraction_attribute_by_name(mmt_handler, "http", "content_type");
    register_extraction_attribute_by_name(mmt_handler, "http", "uri");
    register_packet_handler(mmt_handler, 1, packet_handler, NULL);
    register_extraction_attribute_by_name(mmt_handler, "tcp", "p_payload"); //Request TCP sequence number
    // register session expiry handler
    register_session_timeout_handler(mmt_handler, classification_expiry_session, NULL);

    if (type == TRACE_FILE) {
        pcap = pcap_open_offline(filename, errbuf); // open offline trace
        if (!pcap) { /* pcap error ? */
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }

        while ((data = pcap_next(pcap, &p_pkthdr))) {
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            if (!packet_process(mmt_handler, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
        }
    } else {
        pcap = pcap_open_live(filename, MTU_BIG, 1, 1000, errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        (void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
    }

    // We're done, close and cleanup
    mmt_close_handler(mmt_handler);

    close_extraction();

    pcap_close(pcap);

    return EXIT_SUCCESS;
}

