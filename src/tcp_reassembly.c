#include "processing.h"
int reassembly_callback(const ipacket_t *ipacket, void *user_args)
{
    if (ipacket->session == NULL)
    {
        debug("[reassembly_callback: %lu] Cannot find IP session\n", ipacket->packet_id);
        return 0;
    }

    mmt_probe_context_t *probe_context = get_probe_context_config();

    if (probe_context == NULL)
    {
        debug("[reassembly_callback: %lu] Cannot get probe context\n", ipacket->packet_id);
        return 0;
    }
#ifdef TCP_PAYLOAD_DUMP
    if (probe_context->tcp_payload_dump_enable == 1)
    {
        session_struct_t *temp_session = (session_struct_t *)get_user_session_context_from_packet(ipacket);

        if (temp_session == NULL)
        {
            debug("[reassembly_callback: %lu] Cannot get temp_session\n", ipacket->packet_id);
            return 0;
        }

        uint32_t *payload_len = (uint32_t *)get_attribute_extracted_data(ipacket, PROTO_TCP, TCP_PAYLOAD_LEN);
        char *tcp_payload = (char *)get_attribute_extracted_data(ipacket, PROTO_TCP, PROTO_PAYLOAD);
        if (payload_len != NULL && tcp_payload != NULL)
        {
            char ip_src_str[46];
            char ip_dst_str[46];
            int direction = 0;
            if (temp_session->ipversion == 4)
            {
                inet_ntop(AF_INET, (void *)&temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, (void *)&temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
                uint32_t *ip_src = (uint32_t *)get_attribute_extracted_data(ipacket, PROTO_IP, IP_SRC);
                if (*ip_src == temp_session->ipclient.ipv4)
                {
                    direction = 1;
                }
            }
            else
            {
                inet_ntop(AF_INET6, (void *)&temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, (void *)&temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
                void *ipv6_src = (void *)get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SRC);
                if (memcmp(ipv6_src, &temp_session->ipclient.ipv6, sizeof(&ipv6_src)) == 0)
                {
                    direction = 1;
                }
            }
            char *path;
            path = (char *)malloc(sizeof(char) * 1024);
            int len = 0;
            if (direction == 0)
            {
                sprintf(path, "%s/%s:%d-%s:%d", probe_context->tcp_payload_dump_location, ip_src_str, temp_session->clientport, ip_dst_str, temp_session->serverport);
            }
            else
            {
                sprintf(path, "%s/%s:%d-%s:%d", probe_context->tcp_payload_dump_location, ip_dst_str, temp_session->serverport, ip_src_str, temp_session->clientport);
            }
            write_data_to_file(path, tcp_payload, *payload_len);
            free(path);
        }
    }
#endif
    return 0;
}
