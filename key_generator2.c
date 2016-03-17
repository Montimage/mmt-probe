/*
	 gcc -o license_key_generator key_generator2.c

	 Information that needs to be changed in the code for generating new license
	 Provide expiry date of the license in year (4-digits),month(2-digits) and date(2-digits)
	 Provide number of mac address (3 digits) and 12 digit MAC addresses (12 digits) separated by "-" of the machine for the license

 * */


#include<stdio.h>
#include<string.h>
#include <stdlib.h>
#include <unistd.h>

void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Provide all these parameters:\n");
    fprintf(stderr, "\t-m <MAC addresses>  : Provide MAC addresses separated by - if more than 1\"for example: 2a:3z:45:6c:12:34-45:67:34:t5:78:fG \" \n");
    fprintf(stderr, "\t-d <Date>           : Provide expiry date in format YYYY/MM/DD \n");
    fprintf(stderr, "\t-h                  : Prints this help.\n");
    exit(1);
}

int no_of_mac_address = 1;
char * write_mac_address = NULL;
char * expiry_date = NULL;

void parseOptions(int argc, char ** argv) {
    int opt, optcount = 0;
    int num_mac =0;
    int length =0;

    while ((opt = getopt(argc, argv, "m:d:h")) != EOF) {
        switch (opt) {
        case 'm':
            optcount++;
            length = strlen(optarg);
            //printf("length=%d\n",length);
            write_mac_address = malloc (sizeof(char)* (length));
            write_mac_address = optarg;
            //printf("write_mac_address= %s\n",write_mac_address);
            break;
        case 'd':
            optcount++;
            expiry_date = malloc (sizeof(char)*11);
            expiry_date = optarg;
           // printf("expiry_date = %s\n",expiry_date);
            break;
        case 'h':
        default: usage(argv[0]);
        }
    }

    if (optcount > 2 || optcount < 2 ) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    int count = 0;
    if (length == 0){
    	usage(argv[0]);
    	exit(EXIT_FAILURE);
    }

    for (count = 0; count < length; count++)
    {
    	if (write_mac_address[count] == '-')

    	{
    		no_of_mac_address++;
    	}

    }



    int mac_address_length = (no_of_mac_address *17 + no_of_mac_address-1);
    if(!write_mac_address || length < mac_address_length || length > mac_address_length) {
    	printf("Error: Specify 12 digit MAC addressess separated by - \"for example: 2A:3Z:45:6T:12:34-45:67:34:T5:78:FG also check number of mac address\" \n");
    	exit(EXIT_FAILURE);
    }

    if(strlen(expiry_date)<10 ||strlen(expiry_date)>10) {
    	printf("Error: Specify expiry date in format YYYY/MM/DD \n");
    	exit(EXIT_FAILURE);
    }

    return;
}
void main(int argc, char **argv){
    FILE * license_key;
    int MAX=50;
    char message[50];
    int valid=0;
    /*
     * Provide expiry date of the license in year,month and date
     * */
    parseOptions(argc,argv);
    char mac_number_string[4];
    char year[5];//4-digits
    char month[3];//2-digits
    char day[3];//2-digits

    int offset=0;
    /*
     * This blocks contains no information but are used to make the license key difficult to read
     */
    char block1[10]="627f639fb5";
    char block2[10]="70258tya60";
    char block3[10]="2Sd574g689";
    char block4[10]="24689k5b79";
    static char file [256+1]={0};

    strcpy(file,"License_key.key");

    license_key= fopen(file, "w");
    offset+=fwrite(block1,1,10,license_key);

    strncpy(year,expiry_date,4);
    year[4]='\0';

    offset+=fwrite(year,1,4,license_key);
    int len_yr=strlen(year);

    strncpy(month,&expiry_date[5],2);
    month[2]='\0';

    offset+=fwrite(month,1,2,license_key);

    strncpy(day,&expiry_date[8],2);
    day[2]='\0';

    offset+=fwrite(day,1,2,license_key);


    long int date = atoi(year)*atoi(month)*atoi(day);

    valid=snprintf(message,MAX,"%li",date);
    message[valid]='\0';

    offset+=fwrite(block2,1,10,license_key);

    offset+=fwrite(message,1,valid,license_key);

    offset+=fwrite(block3,1,10,license_key);

    snprintf(mac_number_string,4,"%03d",no_of_mac_address);
    mac_number_string[3]='\0';
   // printf("mac_number_string=%s\n",mac_number_string);


    offset+=fwrite(mac_number_string,1,3,license_key);

    int j=0;
    int offset_mac_read=0;
    int offset_mac_write=0;
    int length_of_mac_addresses = no_of_mac_address*12 +1;
    char * mac_address;
    mac_address=malloc(sizeof(char)*length_of_mac_addresses);

    for (j=0;j<no_of_mac_address *6;j++){
        strncpy(&mac_address[offset_mac_write],&write_mac_address[offset_mac_read],12);
        offset_mac_write+=2;
        offset_mac_read+=3;
    }
    mac_address[no_of_mac_address*12]='\0';

    offset+=fwrite(mac_address,1,no_of_mac_address*12,license_key);
    int count_mac_len= strlen(mac_address);

    if (count_mac_len!=(no_of_mac_address*12)){
        printf ("ERROR: length of MAC address do not match \n");
        exit(0);

    }

    offset+=fwrite(block4,1,10,license_key);

    long int  sum_mac=0;
    int i;

    for (i=0;i<(no_of_mac_address*12);i++){
        sum_mac+=mac_address[i];
    }
    //printf("sum_mac=%lu\n", sum_mac);

    char * sum_mac_str;

    sum_mac_str= malloc(sizeof(char)*10);

    memset(sum_mac_str,'\0',10);
    valid=snprintf(sum_mac_str,10,"%lu",sum_mac);

    sum_mac_str[valid]='\0';

    //printf ("mac_sum_str=%s\n",sum_mac_str);
    offset+=fwrite(sum_mac_str,1,valid,license_key);

    int k=0;
    unsigned long int  sum_of_blocks=0;

    for (k=0;k<10;k++){

        sum_of_blocks+=block1[k]+block2[k]+block3[k]+block4[k];

    }
    //printf("sum_of_blocks=%lu\n",sum_of_blocks);

    char * sum_of_blocks_str;

    sum_of_blocks_str= malloc(sizeof(char)*10);

    memset(sum_of_blocks_str,'\0',10);
    valid=snprintf(sum_of_blocks_str,10,"%lu",sum_of_blocks);
    sum_of_blocks_str[valid]='\0';
    //printf ("block_sum=%s\n",sum_of_blocks_str);


    offset+=fwrite(sum_of_blocks_str,1,valid,license_key);

    free(sum_of_blocks_str);
    free(sum_mac_str);
    free(mac_address);
    //free(no_of_mac_address);
    //free(write_mac_address);
    //free(expiry_date);
    fclose(license_key);
}

