#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>

int gethostMACaddress(char *read_mac_address,int no_of_mac){

    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int j=0;
    unsigned char * mac_address;
    char * message;

    message=malloc(sizeof(char)*12);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock == -1) {  /*handle error*/ };
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;

    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {  /*handle error*/ }
    struct ifreq* it = ifc.ifc_req;

    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    //int i=0;
    int offset=0;
    int valid=0;
    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        mac_address= (unsigned char*)malloc(7);
        memset(mac_address,'0',7);

        //printf("%s\n",it->ifr_name);

        char licensed_MAC[12];

        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {

            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
                    mac_address[6]='\0';
                    valid=snprintf(message,13,"%.2X%.2X%.2X%.2X%.2X%.2X", mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);
                    message[valid]='\0';
                    for (j=0;j<no_of_mac;j++){
                        memcpy(licensed_MAC,&read_mac_address[offset],12);
                        licensed_MAC[12]='\0';
                        //printf("licensed_MAC=%s\n",licensed_MAC);
                        if(strncmp(message,licensed_MAC,12)==0) return 1;
                        offset+=12;
                    }

                    offset=0;
                }
            }
        }
        else {  /*handle error*/  }
    }
    return 0;
}

int license_expiry_check(){
    struct tm *tm;
    time_t now;
    now=time(0);
    FILE * license_key;
    int MAX=50;
    char message[MAX];
    int valid=0;
    char year[5];
    char month[3];
    char day[3];
    char no_of_mac_address[3];
    char *read_mac_address;
    int no_of_mac;
    int offset=0;
    char block1[10];
    char block2[10];
    char block3[10];
    char block4[10];


    tm=localtime(&now);

    static char file [256+1]={0};
    strcpy(file,"License_key.txt");

    if((fopen("License_key.txt","r"))!=NULL) {
        license_key= fopen(file, "r");

        fseek(license_key,offset,SEEK_SET);
        offset+=fread(block1,1,10,license_key);
        block1[10]='\0';

        fseek(license_key,offset,SEEK_SET);
        offset+=fread(year,1,4,license_key);
        year[4]='\0';

        fseek(license_key,offset,SEEK_SET);
        offset+=fread(month,1,2,license_key);
        month[2]='\0';

        fseek(license_key,offset,SEEK_SET);
        offset+=fread(day,1,2,license_key);
        day[2]='\0';

        long int date = atoi(year)*atoi(month)*atoi(day);

        valid=snprintf(message,MAX,"%lu",date);
        message[MAX]='\0';

        char * key;
        key=malloc(valid*sizeof(char));

        fseek(license_key,offset,SEEK_SET);
        offset+=fread(block2,1,10,license_key);
        block2[10]='\0';

        fseek(license_key,offset,SEEK_SET);
        offset+=fread(key,1,valid,license_key);
        key[valid]='\0';

        int mn_dy=atoi(month)* atoi (day);
        int yr_dy=atoi(year) * atoi(day);
        int mn_yr=atoi (month) * atoi (year);

        int yr =  atoi(key)/mn_dy;
        int mn= atoi(key)/yr_dy;
        int dy= atoi(key)/mn_yr;

        fseek(license_key,offset,SEEK_SET);
        offset+=fread(block3,1,10,license_key);
        block3[10]='\0';

        fseek(license_key,offset,SEEK_SET);
        offset+=fread(no_of_mac_address,1,3,license_key);
        no_of_mac_address[3]='\0';
        no_of_mac=atoi(no_of_mac_address);

        read_mac_address=malloc(sizeof(char)* no_of_mac*12);
        memset(read_mac_address,'\0',no_of_mac*12);
        fseek(license_key,offset,SEEK_SET);
        offset+=fread(read_mac_address,1,no_of_mac*12,license_key);
        read_mac_address[no_of_mac*12]='\0';

        fseek(license_key,offset,SEEK_SET);
        offset+=fread(block4,1,10,license_key);
        block4[10]='\0';

        long int  sum_mac=0;
        int i;
        int valid1=0;

        for (i=0;i<(no_of_mac*12);i++){

            sum_mac+=read_mac_address[i];

        }

        char * sum_mac_str;

        sum_mac_str= malloc(sizeof(char)*10);

        memset(sum_mac_str,'\0',10);
        valid1=snprintf(sum_mac_str,10,"%lu",sum_mac);
        sum_mac_str[valid1]='\0';

        char * read_sum_mac;
        read_sum_mac=malloc(sizeof(char)* valid1);
        fseek(license_key,offset,SEEK_SET);
        offset+=fread(read_sum_mac,1,valid1,license_key);
        read_sum_mac[valid1]='\0';

        int valid2=0;
        int k=0;
        unsigned long int  sum_of_blocks=0;

        for (k=0;k<10;k++){

            sum_of_blocks+=block1[k]+block2[k]+block3[k]+block4[k];

        }

        char * sum_block_str;

        sum_block_str= malloc(sizeof(char)*10);

        memset(sum_block_str,'\0',10);
        valid2=snprintf(sum_block_str,10,"%lu",sum_of_blocks);
        sum_block_str[valid2]='\0';

        //printf("sum__blocks_str=%s\n",sum_block_str);

        char * read_sum_block;
        read_sum_block=malloc(sizeof(char)* valid2);
        fseek(license_key,offset,SEEK_SET);
        fread(read_sum_block,1,valid2,license_key);
        read_sum_block[valid2]='\0';

        //printf("sum_of_blocks_read=%s\n",read_sum_block);



        fclose (license_key);

        if (strncmp(key,message,valid)==0 && yr==atoi(year) && mn==atoi(month) && dy==atoi(day) && strncmp(read_sum_mac,sum_mac_str,valid1)==0 && strncmp(read_sum_block,sum_block_str,valid2)==0){
            if (tm->tm_year+1900>=yr && tm->tm_mon+1>=mn && tm->tm_mday>=dy){

                printf("\n\t*************************************\n"
                        "\t* MMT LICENSE EXPIRED ON %04d-%02d-%02d *\n"
                        "\t*          BUY MMT LICENSE          *\n"
                        "\t*   Website: http://montimage.com   *\n"
                        "\t*   Contact: contact@montimage.com  *\n"
                        "\t**************************************\n\n",yr,mn,dy);
                return 1;
            }
            if ( dy-tm->tm_mday<=7 && dy-tm->tm_mday>0){

                printf("\n\t***********************************************\n"
                        "\t*  MMT LICENSE WILL BE EXPIRED ON %04d-%02d-%02d  *\n"
                        "\t*              BUY MMT LICENSE                *\n"
                        "\t*        Website: http://montimage.com        *\n"
                        "\t*        Contact: contact@montimage.com       *\n"
                        "\t************************************************\n\n",yr,mn,dy);
            }

        }else{

            printf("\n\t*************************************\n"
                    "\t*        MMT LICENSE MODIFIED       *\n"
                    "\t*          BUY MMT LICENSE          *\n"
                    "\t*   Website: http://montimage.com   *\n"
                    "\t*   Contact: contact@montimage.com  *\n"
                    "\t**************************************\n\n");
            return 1;
        }

    }else{
        printf("\n\t*************************************\n"
                "\t*  MMT LICENSE KEY DOES-NOT EXIST   *\n"
                "\t*          BUY MMT LICENSE          *\n"
                "\t*   Website: http://montimage.com   *\n"
                "\t*   Contact: contact@montimage.com  *\n"
                "\t**************************************\n\n");
        return 1;

    }


    int valid_mac = gethostMACaddress(read_mac_address,no_of_mac);

    if (valid_mac==0){
        printf("\n\t*************************************\n"
                "\t*          BUY MMT LICENSE          *\n"
                "\t*   Website: http://montimage.com   *\n"
                "\t*   Contact: contact@montimage.com  *\n"
                "\t**************************************\n\n");
        return 1;
    }

    return 0;
}

