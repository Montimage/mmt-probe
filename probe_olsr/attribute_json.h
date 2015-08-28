#include <mmt_core.h>

typedef json_t;

struct attr_id {
    char * proto;
    char * attr;
};

struct bus_event {
    char * event_id;
    struct attr_id event;
    int session_nb;
    int attr_nb;
    struct attr_id * session_src;
    struct attr_id * attributes;
};


json_t * mmt_json_new_node();

json_t * mmt_json_new_array();

void mmt_json_set_name(json_t * node, char * name);

json_t * mmt_json_new_i(char * key, int val);

json_t * mmt_json_new_f(char * key, double val);

json_t * mmt_json_new_a(char * key, char * val);

void mmt_json_push(json_t * node, json_t * elem);

/**
 * Serializes an mmt attribute into JSON
 * @param attr pointer to the attribute structure
 * @param format format identifier, MUST be one of 0, 1, 2, and, 3.<br>
 * 0: {val: xxx}<br>
 * 1: {proto: proto_id, attr: attr_id, val: xxx}<br>
 * 2: {proto_name.attr_name: xxx}<br>
 * 3: {proto: proto_name, attr: attr_name, val: xxx}<br>
 * @return Returns a pointer to the json serialized attribute 
 */
json_t * mmt_attr_json(attribute_t * attr, int human_readable);

char * mmt_json_format(json_t * node);

void mmt_json_destroy(json_t * node);

void mmt_format_free(char * f);
