#include <stdio.h>
#include <stdlib.h>

#include <libjson/libjson.h>

#include "attribute_json.h"

#define MMT_U8_STRLEN           5
#define MMT_U16_STRLEN          7
#define MMT_U32_STRLEN          12
#define MMT_U64_STRLEN          22
#define MMT_CHAR_STRLEN         2
#define MMT_POINTER_STRLEN      22
#define MMT_MAC_STRLEN          20
#define MMT_IP_STRLEN           16
#define MMT_IP6_STRLEN          46
#define MMT_PATH_STRLEN         512
#define MMT_TIMEVAL_STRLEN      24
#define MMT_BINARY_STRLEN       BINARY_64DATA_LEN*2 + 1
#define MMT_BINARYVAR_STRLEN    BINARY_1024DATA_LEN*2 + 1
#define MMT_STRING_STRLEN       BINARY_64DATA_LEN
#define MMT_STRINGLONG_STRLEN   STRING_DATA_TYPE_LEN
/*
typedef struct olsr_hello_event_struct {
    uint32_t orig;
    uint32_t neighbor;
    uint16_t seqnb;
    uint8_t  type;
    uint8_t  lq;
    uint8_t  nlq;
    uint8_t  ttl;
    uint8_t  hopcount;
}olsr_hello_event_t;
*/

typedef struct olsr_hello_event_struct {
    uint32_t orig;
    uint32_t neighbor;
    uint16_t seqnb;
    uint8_t  type;
    uint8_t  fwd_signal;
    uint8_t  rcv_signal;
    uint8_t  interface;
    uint8_t  reserve;
    uint8_t ttl;
    uint8_t hopcount;
}olsr_hello_event_t;

json_t * mmt_char_json(attribute_t * attr, char * name) {
    char buff[2];
    snprintf(buff, 1, "%c", *(char *) attr->data);
    return (json_t *) json_new_a(name, buff);
}
json_t * mmt_uint8_json(attribute_t * attr, char * name) {
    return (json_t *) json_new_f(name, (double) *(uint8_t *) attr->data);
}
json_t * mmt_uint16_json(attribute_t * attr, char * name) {
    return (json_t *) json_new_f(name, (double) *(uint16_t *) attr->data);
}
json_t * mmt_uint32_json(attribute_t * attr, char * name) {
    return (json_t *) json_new_f(name, (double) *(uint32_t *) attr->data);
}
json_t * mmt_uint64_json(attribute_t * attr, char * name) {
    return (json_t *) json_new_f(name, (double) *(uint64_t *) attr->data);
}

json_t * mmt_pointer_json(attribute_t * attr, char * name) {
    if( strcmp("hello", get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id)) == 0) {
        olsr_hello_event_t * link = (olsr_hello_event_t *) attr->data;
        JSONNODE *n = NULL;
        
        char buff_orig[MMT_IP_STRLEN];
        mmt_inet_ntop(AF_INET, (void *) &link->orig, buff_orig, INET_ADDRSTRLEN);
        char buff_neighbor[MMT_IP_STRLEN];
        mmt_inet_ntop(AF_INET, (void *) &link->neighbor, buff_neighbor, INET_ADDRSTRLEN);

        n = json_new(JSON_NODE);
        mmt_json_set_name(n, "value");
        json_push_back(n, json_new_a("orig", buff_orig));
        json_push_back(n, json_new_a("neighbor", buff_neighbor));
        json_push_back(n, json_new_f("seqnb", (double) link->seqnb));
        json_push_back(n, json_new_i("type", (double) link->type));
        json_push_back(n, json_new_i("fwd_signal", (double) link->fwd_signal));
        json_push_back(n, json_new_i("rcv_signal", (double) link->rcv_signal));
        json_push_back(n, json_new_i("interface", (double) link->interface));
        json_push_back(n, json_new_i("reserve", (double) link->reserve));
        json_push_back(n, json_new_i("ttl", (double) link->ttl));
        json_push_back(n, json_new_i("hopcount", (double) link->hopcount));
        return (json_t *) n;
    } else {
      char buff[17];
      snprintf(buff, 16, "%p", (void *) attr->data);
      return (json_t *) json_new_a(name, buff);
    }
}
json_t * mmt_mac_json(attribute_t * attr, char * name) {
    char buff[MMT_MAC_STRLEN];
    const uint8_t *ea = attr->data;
    snprintf( buff, MMT_MAC_STRLEN, "%02x:%02x:%02x:%02x:%02x:%02x", ea[0], ea[1], ea[2], ea[3], ea[4], ea[5] );
    return (json_t *) json_new_a(name, buff);
}
json_t * mmt_ip_json(attribute_t * attr, char * name) {
    char buff[MMT_IP_STRLEN];
    mmt_inet_ntop(AF_INET, (void *) attr->data, buff, INET_ADDRSTRLEN);
    return (json_t *) json_new_a(name, buff);
}
json_t * mmt_ip6_json(attribute_t * attr, char * name){
    char buff[MMT_IP6_STRLEN];
    mmt_inet_ntop(AF_INET6, (void *) attr->data, buff, INET6_ADDRSTRLEN);
    return (json_t *) json_new_a(name, buff);
}
json_t * mmt_path_json(attribute_t * attr, char * name) {
    char buff[1024];
    int index = 1, len = 1023;
    int offset = 0;
    proto_hierarchy_t * p = (proto_hierarchy_t *) attr->data;

    offset += snprintf(buff, len - offset, "%u", p->proto_path[index]);
    index++;
    for (; (index < p->len) && (index < 16) && offset < len; index++) {
        offset += snprintf(&buff[offset], len - offset, ".%u", p->proto_path[index]);
    }

    return (json_t *) json_new_a(name, buff);
}
json_t * mmt_timeval_json(attribute_t * attr, char * name){
    struct timeval * tv = (struct timeval *) attr->data;
    return (json_t *) json_new_f(name, tv->tv_sec + tv->tv_usec/1000000);
}
json_t * mmt_binary_json(attribute_t * attr, char * name){
    char buff[MMT_BINARYVAR_STRLEN];
    
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    //if (len < (b->len * 2 + 1)) return -1;
    int index = 0, offset = 0;
    for (; index < (b->len) && offset < MMT_BINARYVAR_STRLEN; index++) {
        offset += snprintf((char *) &buff[offset], MMT_BINARYVAR_STRLEN - offset, "%02x", b->data[index]);
    }

    return (json_t *) json_new_a(name, buff);
}
json_t * mmt_string_json(attribute_t * attr, char * name){
    mmt_binary_var_data_t * b = (mmt_binary_var_data_t *) attr->data;
    return (json_t *) json_new_a(name, (char *) &b->data);
}
json_t * mmt_string_pointer_json(attribute_t * attr, char * name){
    return (json_t *) json_new_a(name, (char *) attr->data);
}
json_t * mmt_stats_json(attribute_t * attr, char * name) {
    return (json_t *) json_new_a(name, "TODO");
}
json_t * mmt_header_line_json(attribute_t * attr, char * name){
    char buff[MMT_BINARYVAR_STRLEN];
    mmt_header_line_t * h = (mmt_header_line_t *) attr->data;
    int len = (h->len >= MMT_BINARYVAR_STRLEN)? MMT_BINARYVAR_STRLEN : h->len + 1;
    snprintf(buff, len, "%s", h->ptr);

    return (json_t *) json_new_a(name, buff);
}
json_t * mmt_attr_json(attribute_t * attr, int human_readable) {
    JSONNODE *n = NULL;
    char val_name[128];
    int embed = 1;
    if(human_readable == 0) {
        embed = 0;
        snprintf(val_name, 127, "value"); 
    } else if(human_readable == 1) {
        n = json_new(JSON_NODE);
        json_push_back(n, json_new_i("proto", attr->proto_id));
        json_push_back(n, json_new_i("attr", attr->field_id));
        snprintf(val_name, 127, "value"); 
    } else if(human_readable == 2) {
        embed = 0;
        snprintf(val_name, 127, "%s.%s", get_protocol_name_by_id(attr->proto_id), get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id)); 
    }else if(human_readable == 3) {
        n = json_new(JSON_NODE);
        json_push_back(n, json_new_a("proto", get_protocol_name_by_id(attr->proto_id)));
        json_push_back(n, json_new_a("attr", get_attribute_name_by_protocol_and_attribute_ids(attr->proto_id, attr->field_id)));
        snprintf(val_name, 127, "value"); 
    }else {
        return NULL;
    }
    
    switch(attr->data_type) {
        case MMT_U8_DATA:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_uint8_json(attr, val_name));
            else
                return mmt_uint8_json(attr, val_name);
            break;
        case MMT_U16_DATA:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_uint16_json(attr, val_name));
            else
                return mmt_uint16_json(attr, val_name);
            break;
        case MMT_U32_DATA:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_uint32_json(attr, val_name));
            else
                return mmt_uint32_json(attr, val_name);
            break;
        case MMT_U64_DATA:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_uint64_json(attr, val_name));
            else
                return mmt_uint64_json(attr, val_name);
            break;
        case MMT_DATA_CHAR:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_char_json(attr, val_name));
            else
                return mmt_char_json(attr, val_name);
            break;
        case MMT_DATA_POINTER:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_pointer_json(attr, val_name));
            else
                return mmt_pointer_json(attr, val_name);
            break;
        case MMT_DATA_MAC_ADDR:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_mac_json(attr, val_name));
            else
                return mmt_mac_json(attr, val_name);
            break;
        case MMT_DATA_IP_ADDR:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_ip_json(attr, val_name));
            else
                return mmt_ip_json(attr, val_name);
            break;
        case MMT_DATA_IP6_ADDR:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_ip6_json(attr, val_name));
            else
                return mmt_ip6_json(attr, val_name);
            break;
        case MMT_DATA_PATH:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_path_json(attr, val_name));
            else
                return mmt_path_json(attr, val_name);
            break;
        case MMT_DATA_TIMEVAL:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_timeval_json(attr, val_name));
            else
                return mmt_timeval_json(attr, val_name);
            break;
        case MMT_BINARY_DATA:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_binary_json(attr, val_name));
            else
                return mmt_binary_json(attr, val_name);
            break;
        case MMT_BINARY_VAR_DATA:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_binary_json(attr, val_name));
            else
                return mmt_binary_json(attr, val_name);
            break;
        case MMT_STRING_DATA:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_string_json(attr, val_name));
            else
                return mmt_string_json(attr, val_name);
            break;
        case MMT_STRING_LONG_DATA:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_string_json(attr, val_name));
            else
                return mmt_string_json(attr, val_name);
            break;
        case MMT_STRING_DATA_POINTER:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_string_pointer_json(attr, val_name));
            else
                return mmt_string_pointer_json(attr, val_name);
            break;
        case MMT_HEADER_LINE:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_header_line_json(attr, val_name));
            else
                return mmt_header_line_json(attr, val_name);
            break;
        case MMT_STATS:
            if(embed)
                json_push_back(n, (JSONNODE *) mmt_stats_json(attr, val_name));
            else
                return mmt_stats_json(attr, val_name);
            break;
        default:
            if(embed)
                json_push_back(n, (JSONNODE *) json_new_a(val_name, ""));
            else
                return (json_t *) json_new_a(val_name, "");
            break;
    }
    return (json_t *) n;
}

json_t * mmt_json_new_node() {
    return (json_t *) json_new(JSON_NODE);
}

json_t * mmt_json_new_array() {
    return (json_t *) json_new(JSON_ARRAY);
}

void mmt_json_set_name(json_t * node, char * name) {
    JSONNODE * n = (JSONNODE *) node;
    json_set_name(n, name);
}

json_t * mmt_json_new_i(char * key, int val) {
    return (json_t *) json_new_i(key, val);
}

json_t * mmt_json_new_f(char * key, double val) {
    return (json_t *) json_new_f(key, val);
}

json_t * mmt_json_new_a(char * key, char * val) {
    return (json_t *) json_new_a(key, val);
}

void mmt_json_push(json_t * node, json_t * elem) {
    JSONNODE * n = (JSONNODE *) node;
    JSONNODE * e = (JSONNODE *) elem;
    
    json_push_back(n, e);
}

char * mmt_json_format(json_t * node) {
    JSONNODE * n = (JSONNODE *) node;
    return (char *) json_write_formatted(n);
}

void mmt_json_destroy(json_t * node) {
    JSONNODE * n = (JSONNODE *) node;
    json_delete(n);
}

void mmt_format_free(char * f) {
    json_char * jc = (json_char *) f;
    json_free(jc);
}

