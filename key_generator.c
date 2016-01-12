/*
	 gcc -o license_key_generator key_generator.c

	 Information that needs to be changed in the code for generating new license
	 Provide expiry date of the license in year (4-digits),month(2-digits) and date(2-digits)
	 Provide number of mac address (3 digits) and 12 digit MAC addresses (12 digits) separated by "-" of the machine for the license

 * */


#include<stdio.h>
#include<string.h>
#include <stdlib.h>

unsigned long hex2dec(char *str){

    int i;
    for(i = 0; i < strlen(str); i++ ){
        int nb = str[i];
        if (!( (nb >=48 && nb <= 57) || (nb >= 97 && nb<=102) || (nb >= 65 && nb<=70) )){
            return -1;
        }
    }

    unsigned long ul;
    ul = strtoul (str, NULL, 16);
    if(ul == 0){
        int i;
        for(i = 0; i < strlen(str); i++){
            if(str[i] != '0') return -1;
        }
    }
    return ul;
}

void main(){
    FILE * license_key;
    int MAX=50;
    char message[50];
    int valid=0;
    /*
     * Provide expiry date of the license in year,month and date
     * */
    char year[4]="2016";//4-digits
    char month[2]="01";//2-digits
    char day[2]="30";//2-digits
    /*
     * Provide number of mac address (3 digits) and 12 digit MAC addresses separated by "-" of the machine for the license
     */
    char no_of_mac_address[3]= "004";//3-digits
    char * write_mac_address ="080027749053-0800271C04a5-9C2A70246CDB-B8CA3ACD58D9";//12 digit MAC addresses separated by "-"
    int offset=0;
    /*
     * This blocks contains no information but are used to make the license key difficult to read
     */
    char block1[10]="627G639FB5";
    char block2[10]="70258TYG60";
    char block3[10]="2SD574G689";
    char block4[10]="24689G5K79";
    static char file [256+1]={0};

    strcpy(file,"License_key.txt");

    license_key= fopen(file, "w");
    offset+=fwrite(block1,1,10,license_key);

    offset+=fwrite(year,1,4,license_key);
    int len_yr=strlen(year);
    if (len_yr!=4){
        printf("ERROR:year must have 4 digits i.e. 2014\n");
        exit(0);
    }

    offset+=fwrite(month,1,2,license_key);
    int len_mn=strlen(month);
    if (len_mn!=2){
        printf("ERROR:month must have 2 digits i.e. 01 for January\n");
        exit(0);
    }

    offset+=fwrite(day,1,2,license_key);
    int len_dy=strlen(month);
    if (len_dy!=2){
        printf("ERROR:day must have 2 digits i.e. 01 for day 1\n");
        exit(0);
    }

    long int date = atoi(year)*atoi(month)*atoi(day);

    valid=snprintf(message,MAX,"%li",date);
    message[valid]='\0';

    offset+=fwrite(block2,1,10,license_key);

    offset+=fwrite(message,1,valid,license_key);

    offset+=fwrite(block3,1,10,license_key);

    offset+=fwrite(no_of_mac_address,1,3,license_key);

    int no_of_mac;

    no_of_mac=atoi(no_of_mac_address);
    //printf("no_of_mac=%d\n",no_of_mac);
    int j=0;
    int offset_mac_read=0;
    int offset_mac_write=0;

    char * mac_address;
    mac_address=malloc(sizeof(char)*no_of_mac*12);

    for (j=0;j<no_of_mac;j++){
        strncpy(&mac_address[offset_mac_write],&write_mac_address[offset_mac_read],12);
        offset_mac_write+=12;
        offset_mac_read+=13;
    }
    mac_address[no_of_mac*12]='\0';
    offset+=fwrite(mac_address,1,no_of_mac*12,license_key);
    int count_mac_len= strlen(mac_address);
    //printf("count_mac_len=%d\n",count_mac_len);

    if (count_mac_len!=(no_of_mac*12)){
        printf ("ERROR: length of MAC address do not match \n");
        exit(0);

    }

    offset+=fwrite(block4,1,10,license_key);

    long int  sum_mac=0;
    int i;

    for (i=0;i<(no_of_mac*12);i++){

        sum_mac+=mac_address[i];


    }
    //printf("sum_mac=%lu\n", sum_mac);

    char * sum_mac_str;

    sum_mac_str= malloc(sizeof(char)*10);

    memset(sum_mac_str,'\0',10);
    valid=snprintf(sum_mac_str,10,"%lu",sum_mac);
    sum_mac_str[valid]='\0';

    //printf ("block_sum=%s\n",sum_mac_str);

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


    offset+=fwrite(sum_mac_str,1,valid,license_key);
    offset+=fwrite(sum_of_blocks_str,1,valid,license_key);

    fclose(license_key);
}

