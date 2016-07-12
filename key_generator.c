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

int encrypt(){      
	char ch;
	FILE * fp1;
	FILE * fp2;
	fp1=fopen("license_key_donot_cpy.key","r");
	if(fp1==NULL){
		printf("Source File Could Not Be Found\n");
	}
	fp2=fopen("license.key","w");
	if(fp2==NULL){
		printf("Target File Could Not Be Found\n");
	}
	while(1)
	{
		ch=fgetc(fp1);
		if(ch==EOF){
			//printf("\nEnd Of File\n");
			break;
		}
		else{
			ch=ch-(8*4-3);
			fputc(ch,fp2);
		}
	}
	fclose(fp2);
	return 0;
}
void main(int argc, char **argv){
	int MAX=50;
	char message[50];
	int valid=0;
	FILE * license_key;
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

	static char file [256+1]={0};

	strcpy(file,"license_key_donot_cpy.key");
	license_key= fopen(file, "w");

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

	long int date_sum = atoi(year)*atoi(month)*atoi(day);

	long int  sum_mac=0;
	int i;

	for (i=0;i<(no_of_mac_address*12);i++){
		sum_mac+=mac_address[i];
	}

	long int sum_license = date_sum + sum_mac + no_of_mac_address;

	char * sum_license_str;

	sum_license_str= malloc(sizeof(char)*20);

	memset(sum_license_str,'\0',20);
	valid=snprintf(sum_license_str,10,"%lu",sum_license);
	sum_license_str[valid]='\0';

	offset+=fwrite(sum_license_str,1,valid,license_key);
	free(mac_address);
	//free(write_mac_address);
	//free(expiry_date);
	fclose(license_key);
	encrypt();


}

