/* A simple server in the internet/Unix domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
static int count = 0;
pthread_spinlock_t lock;
struct sockaddr_un {
	unsigned short sun_family;  /* AF_UNIX */
	char sun_path[108];
};
void error(const char *msg)
{
	perror(msg);
	exit(1);
}

typedef struct terminal_input_struct{
	int argc;
	int domain;
	int portnb;
	char socket_name[256];
	int thread_num;
	int count;
	pthread_t th_handler;


}terminal_input_t;

void * create_socket(void *arg){

	int sockfd,portno;
	int newsockfd;
	socklen_t in_clilen;
	struct sockaddr_in in_serv_addr, in_cli_addr;
	struct sockaddr_un un_saddr,un_cli_addr;
	terminal_input_t *input = (terminal_input_t *)arg;

	int n,on;
	int i=0,j=0,l=0;
	int length=0;
	int total_length=0;
	unsigned char buffer[256];
	unsigned char length_buffer[5];
	int proto_id =0;
	int field_length =0;
	int field_id =0;
	unsigned char data_ex[256];
	struct timeval time_attr ;
	int length_of_packet =0;
	input->count =1;
	int len;
	pthread_t threadA[3];

	/*Enable address reuse*/
	on = 1;
	if (input->domain==1){
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

		if (sockfd < 0)
			error("ERROR opening socket");

		if (setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) )<0)
			error("setsockopt(SO_REUSEADDR) failed");

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
			perror("setsockopt(SO_REUSEPORT) failed");

		bzero((char *) &in_serv_addr, sizeof(in_serv_addr));
		//portno = atoi(argv[2]);
		in_serv_addr.sin_family = AF_INET;
		in_serv_addr.sin_addr.s_addr = INADDR_ANY;
		in_serv_addr.sin_port = htons(input->portnb);

		if (bind(sockfd, (struct sockaddr *) &in_serv_addr,
				sizeof(in_serv_addr)) < 0)
			error("ERROR on binding");

		listen(sockfd,5);
		in_clilen = sizeof(in_cli_addr);

		newsockfd = accept(sockfd,
				(struct sockaddr *) &in_cli_addr,
				&in_clilen);

	}else if (input->domain==0){
		//printf ("here\n");

		char common_socket_name[256] = "/opt/mmt/probe/bin/mysocket\0";
		int valid =0;

		valid = snprintf(input->socket_name, 256,"%s%u",
				common_socket_name, input->thread_num);
		input->socket_name[ valid] = '\0';
		//printf("thread_num = %u,socket_name = %s\n",input->thread_num,input->socket_name);

		fopen(input->socket_name,"w");
		sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sockfd < 0)
			error("ERROR opening socket");

		if (setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) )<0)
			error("setsockopt(SO_REUSEADDR) failed");

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
			perror("setsockopt(SO_REUSEPORT) failed");



		un_saddr.sun_family = AF_UNIX;   /*saddr is declared before socket() ^*/
		strcpy(un_saddr.sun_path, input->socket_name);
		unlink(un_saddr.sun_path);
		len = strlen(un_saddr.sun_path) + sizeof(un_saddr.sun_family);

		if (bind(sockfd, (struct sockaddr *)&un_saddr, len) == -1)error("ERROR on binding");

		listen(sockfd,5);
		len = sizeof(un_cli_addr);

		newsockfd = accept(sockfd,(struct sockaddr *) &un_cli_addr, &len);
		if (newsockfd < 0)
			error("ERROR on accept");

	}
	while(1){
		bzero(buffer,256);
		bzero(length_buffer,5);
		n=read(newsockfd, length_buffer, 4);///

		if (n < 0) {
			error("ERROR reading from socket");
		}

		memcpy(&length_of_packet,&length_buffer,4);
		n = read(newsockfd,buffer,length_of_packet-4);

		buffer[n]='\0';
		length =0;
		proto_id =0;
		field_id=0;
		field_length =0;
		data_ex[0] = '\0';
		if (n > 10){
			input->count++;
	//printf("packet received count_multithread=%d,length=%u,id=%u \n",input->count++,n,input->thread_num);
			/*memcpy(&time_attr,&buffer[length],sizeof(struct timeval));
			length = sizeof (struct timeval);
			while (n-length > 0){
				memcpy(&proto_id,&buffer[length],4);
				length += 4;
				memcpy(&field_id,&buffer[length],4);
				length += 4;
				memcpy(&field_length,&buffer[length],2);
				length += 2;
				memcpy(&data_ex[0],&buffer[length],field_length);
				length += field_length;
				data_ex[field_length]='\0';
				//printf("proto_id = %u, attribute_id =%u, length =%u, data= %s\n",proto_id,field_id,field_length, (unsigned char *)buffer);
			}*/

		}

	}
	if (n < 0) error("ERROR reading from socket");
	close(newsockfd);
	close(sockfd);

}
void *task1 (void *sock_des)
{
	int threadsockfd = *(int *)sock_des;
    char test[300];
	int length=0;
	int total_length=0;
	unsigned char buffer[256];
	unsigned char length_buffer[5];
	int proto_id =0;
	int field_length =0;
	int field_id =0;
	unsigned char data_ex[256];
	struct timeval time_attr ;
	int length_of_packet =0;
	int len,n;


    while(1)
    {
             	bzero(buffer,256);
        		bzero(length_buffer,5);
        		n=read(threadsockfd, length_buffer, 4);///

        		if (n < 0) {
        			error("ERROR reading from socket");
        		}

        		memcpy(&length_of_packet,&length_buffer,4);
        		n = read(threadsockfd,buffer,length_of_packet-4);

        		buffer[n]='\0';
        		length =0;
        		proto_id =0;
        		field_id=0;
        		field_length =0;
        		data_ex[0] = '\0';
        		if (n > 10){
        			pthread_spin_lock(&lock);
        			count++;
        			pthread_spin_unlock(&lock);
        			//printf("packet received_single_thread_length=%u, count= %u\n",n,count);
     /*   			memcpy(&time_attr,&buffer[length],sizeof(struct timeval));
        			length = sizeof (struct timeval);
        			while (n-length > 0){
        				memcpy(&proto_id,&buffer[length],4);
        				length += 4;
        				memcpy(&field_id,&buffer[length],4);
        				length += 4;
        				memcpy(&field_length,&buffer[length],2);
        				length += 2;
        				memcpy(&data_ex[0],&buffer[length],field_length);
        				length += field_length;
        				data_ex[field_length]='\0';
        				//printf("proto_id = %u, attribute_id =%u, length =%u, data= %s\n",proto_id,field_id,field_length, (unsigned char *)buffer);
        			}*/

        		}





    }
    //close(sockfd);


   close(threadsockfd);
}
void socket_single_thread(void *arg){

	int sockfd,portno;
	socklen_t in_clilen;
	struct sockaddr_in in_serv_addr, in_cli_addr;
	struct sockaddr_un un_saddr,un_cli_addr;
	terminal_input_t *input = (terminal_input_t *)arg;
	int * threadsockfd;
	int client_sock;


	int n,on;
	int i=0,j=0,l=0;
	int len;
	pthread_t threadA[3];

	/*Enable address reuse*/
	on = 1;

	if (input->domain==1){

		sockfd = socket(AF_INET, SOCK_STREAM, 0);

		if (sockfd < 0)
			error("ERROR opening socket");

		if (setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) )<0)
			error("setsockopt(SO_REUSEADDR) failed");

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
			perror("setsockopt(SO_REUSEPORT) failed");

		bzero((char *) &in_serv_addr, sizeof(in_serv_addr));
		//portno = atoi(argv[2]);
		in_serv_addr.sin_family = AF_INET;
		in_serv_addr.sin_addr.s_addr = INADDR_ANY;
		in_serv_addr.sin_port = htons(input->portnb);

		if (bind(sockfd, (struct sockaddr *) &in_serv_addr,
				sizeof(in_serv_addr)) < 0)
			error("ERROR on binding");

		listen(sockfd,5);


	}else if (input->domain==0){
		//printf ("here\n");

		char common_socket_name[256] = "/opt/mmt/probe/bin/mysocket\0";
		int valid =0;

		valid = snprintf(input->socket_name, 256,"%s",
				common_socket_name);
		input->socket_name[ valid] = '\0';
		//printf("thread_num = %u,socket_name = %s\n",input->thread_num,input->socket_name);

		fopen(input->socket_name,"w");
		sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sockfd < 0)
			error("ERROR opening socket");

		if (setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) )<0)
			error("setsockopt(SO_REUSEADDR) failed");

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
			perror("setsockopt(SO_REUSEPORT) failed");



		un_saddr.sun_family = AF_UNIX;   /*saddr is declared before socket() ^*/
		strcpy(un_saddr.sun_path, input->socket_name);
		unlink(un_saddr.sun_path);
		len = strlen(un_saddr.sun_path) + sizeof(un_saddr.sun_family);

		if (bind(sockfd, (struct sockaddr *)&un_saddr, len) == -1)error("ERROR on binding");

		listen(sockfd,5);
	}

    int noThread =0;
    while (noThread < 3)
    {
    	if (input->domain == 0){

    		len = sizeof(un_cli_addr);

    		client_sock = accept(sockfd, (struct sockaddr *)&un_cli_addr, &len);
    		printf ("client_sock = %d \n",client_sock);

    	}
    	else {
    		in_clilen = sizeof(in_cli_addr);
    		printf ("here\n");

    		client_sock = accept(sockfd,
    				(struct sockaddr *) &in_cli_addr,
    				&in_clilen);
    		printf ("client_sock = %d \n",client_sock);

    	}
    	if (client_sock < 0)
    	    error("ERROR on accept");
    	threadsockfd = malloc(1);
    	* threadsockfd = client_sock;
        //this is where client connects. svr will hang in this mode until client conn

        pthread_create(&threadA[noThread], NULL, task1, (void *)threadsockfd);

        noThread++;
    }
    sleep (30);
    i=0;
    int s;

	for( i = 0; i < noThread; i++)
	{
		s = pthread_cancel(threadA[i]);
		if (s != 0) {
			exit(1);
		}
	}
	printf("\npacket received count=%d \n",count);
	exit(1);

}
int main(int argc, char *argv[])
{
	int err;
	int i =0,s;
	terminal_input_t *input_unix;
	terminal_input_t *input_internet;
	int num_of_input = argc;
	int num_thread = atoi(argv[2]);

	if (argc < (num_thread +3) ) {
		fprintf(stderr,"Arguments missing: For internet doman run as  <./server 1 thread_num port_nb1 probe_nb2> each thread will have unique port nb\n\t\t"
				"For Unix doman doman provide <./server 0 thread_num 0 0> each thread will have unique port nb\n");
		exit(1);
	}

	if (num_thread < 1){
		input_unix = (terminal_input_t *)calloc (1,sizeof (terminal_input_t));
		pthread_spin_init(&lock, 0);
		input_unix->thread_num = atoi(argv[2]);
		input_unix->argc = argc;
		input_unix->domain = atoi(argv[1]);
		input_unix->portnb = atoi(argv[3]);
		printf("port_nb=%u\n",input_unix->portnb);

		socket_single_thread((void *)input_unix);

	}else{
		input_internet = (terminal_input_t *)calloc (4,sizeof (terminal_input_t));

		for (i=0;i<num_thread;i++){
			input_internet[i].thread_num = i;
			input_internet[i].argc = argc;
			input_internet[i].domain = atoi(argv[1]);
			input_internet[i].portnb = atoi(argv[3 + i]);
			err =pthread_create (&input_internet[i].th_handler,NULL,&create_socket,&input_internet[i]);
			if (err != 0)printf("\ncan't create thread :[%s]", strerror(err));

		}
		printf("main() is running...\n");
		sleep (60);
		for( i = 0; i < num_thread; i++)
		{
			s = pthread_cancel(input_internet[i].th_handler);
			if (s != 0) {
				exit(1);
			}
			//pthread_join(input[i].th_handler, NULL);
			printf("th_nb = %u,packet received count=%d \n",input_internet[i].thread_num,input_internet[i].count++);


		}
	}
	return 0;
}
