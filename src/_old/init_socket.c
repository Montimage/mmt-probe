/*
 * init_socket.c
 *
 *  Created on: Mar 29, 2017
 *      Author: montimage
 */

#include "processing.h"
#include <netinet/in.h>
#include <netdb.h>

void error(const char *msg)
{
	perror(msg);
	exit(1);
}

/* This function creates socket, UNIX or Internet domain */
void create_socket(mmt_probe_context_t * mmt_conf, void *args){
	/*.....socket */
	struct sockaddr_in in_serv_addr;
	struct sockaddr_un un_serv_addr;
	int len;
	struct hostent *server;
	char socket_name[256];
	char common_socket_name[256] = "mysocket\0";
	int valid = 0;
	struct smp_thread *th = (struct smp_thread *) args;
	int i = 0, on;
	on = 1;

	/*...UNIX socket..*/
	if (mmt_conf->socket_domain == 0 || mmt_conf->socket_domain == 2){
		un_serv_addr.sun_family = AF_UNIX;
		th->sockfd_unix = socket(AF_UNIX, SOCK_STREAM, 0);
		if (th->sockfd_unix < 0)
			error("ERROR opening socket");
		//printf ("socket_id =%u\n",th->sockfd_unix);

		if (mmt_conf->one_socket_server ==1){
			valid = snprintf(socket_name, 256,"%s%s",
					mmt_conf->unix_socket_descriptor,common_socket_name);
			socket_name[ valid] = '\0';
		}else{
			valid = snprintf(socket_name, 256,"%s%s%u",
					mmt_conf->unix_socket_descriptor,common_socket_name,th->thread_index);
			socket_name[ valid] = '\0';
		}
		strcpy(un_serv_addr.sun_path, socket_name);
		len = strlen(un_serv_addr.sun_path) + sizeof(un_serv_addr.sun_family);
		if (connect(th->sockfd_unix, (struct sockaddr *)&un_serv_addr, len) == -1) {
			perror("ERROR connecting socket");
			//exit(0);

		}

	}

	/*Internet socket*/
	if (mmt_conf->socket_domain == 1|| mmt_conf->socket_domain == 2){
		th->sockfd_internet = calloc(sizeof(uint32_t), mmt_conf->server_ip_nb);

		for (i = 0; i < mmt_conf->server_ip_nb; i++){
			th->sockfd_internet[i] = socket(AF_INET, SOCK_STREAM, 0);
			if (th->sockfd_internet[i] < 0)
				error("ERROR opening socket");
			if (setsockopt(th->sockfd_internet[i] , SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) == -1) {
				perror("setsockopt(SO_REUSEADDR)");
				exit(1);
			}
			//setsockopt( th->sockfd_internet[i], IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on)); // need to experiment
			server = gethostbyname(mmt_conf->server_adresses[i].server_ip_address);
			if (server == NULL) {
				fprintf(stderr,"ERROR, no such host\n");
				//exit(0);
			}
			bzero((char *) &in_serv_addr, sizeof(in_serv_addr));
			in_serv_addr.sin_family = AF_INET;
			bcopy((char *)server->h_addr,
					(char *)&in_serv_addr.sin_addr.s_addr,
					server->h_length);

			if (mmt_conf->one_socket_server == 1){

				in_serv_addr.sin_port = htons(mmt_conf->server_adresses[i].server_portnb[0]);
				//printf("th_nb=%u,ip = %s,port = %u \n",th->thread_number,mmt_conf->server_adresses[i].server_ip_address,mmt_conf->server_adresses[i].server_portnb[0]);

			}else{

				in_serv_addr.sin_port = htons(mmt_conf->server_adresses[i].server_portnb[th->thread_index]);
				//printf("th_nb=%u,ip = %s,port = %u \n",th->thread_number,mmt_conf->server_adresses[i].server_ip_address,mmt_conf->server_adresses[i].server_portnb[th->thread_number]);
			}

			if (connect(th->sockfd_internet[i], (struct sockaddr *) &in_serv_addr, sizeof(in_serv_addr)) < 0)
				fprintf(stderr,"ERROR cannot connect to a socket(check availability of server):%s\n", strerror(errno));
			//error("ERROR connecting");
		}
	}
}
