#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "wifi-scanner.h"

int scan_interval = DEFAULT_INT;
char *interface;
char scan_log[] = "/var/log/wifi-scan.log";
char conf_dir[] = "/usr/local/etc/airodump-ng/conf";
char mon_interface[] = "wlan1mon";

void show_help(void){
    printf("Usage:\n wifi-scanner [options] <wireless interface>\n \
    Options:\n \
	-i : monitor interface, default wlan1mon \n \
	-c : config path, default /usr/local/etc/airodump-ng/conf \n \
	-t : checking time, default 30s\n \
	-w : output file, default /var/log/wifi-scan.log\n \
	-h : show help\n ");
    exit(0);
}

void check_daemon(void){
    char output[MAX_STR];
    char cmd[MAX_STR] = "\0";
    FILE *fp;

    fp = popen("ps -a | grep airodump-ng", "r");
    while(fgets(output, sizeof(output)-1, fp) != 0){
        sprintf(cmd, "killall airodump-ng > /dev/null 2>&1");
        system(cmd);
        break;
    }
    pclose(fp);
}

void pre_scan(char *interface){
    char cmd[MAX_STR] = "\0";
    sprintf(cmd, "airmon-ng start %s > /dev/null 2>&1", interface);
    system(cmd);
}

char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

void wifi_scan(){
    FILE *fp;
    char csv_file[MAX_STR];
    char line[1024];
    char **items;
    char temp_file[] = "/tmp/wifi-scanner";
    ap_t *ap_obj;
    int ap_objs_count = 0;
    ap_t *new_ap_obj;
    int new_ap_objs_count = 0;
    ap_t *rm_ap_obj;
    int rm_ap_objs_count = 0;
    wifi_t *wifi_obj;
    int wifi_objs_count = 0;
    wifi_t *new_wifi_obj;
    int new_wifi_objs_count = 0;
    wifi_t *rm_wifi_obj;
    int rm_wifi_objs_count = 0;
    int temp_count = 0;
    int i;
    time_t current_time, obj_last_seen;
    struct tm tm;
    char ap_list_file[MAX_STR];
    char wifi_list_file[MAX_STR];
    int new_flag = 0;
    double diff;
    int ap_removed = 0;
    int ap_updated = 0;
    int wifi_removed = 0;
    int wifi_updated = 0;
    int start_ap = 0;
    int start_wifi = 0;
    int line_num = 0;
 
    current_time = time(NULL);

    sprintf(csv_file, "%s-01.csv", temp_file);
    sprintf(ap_list_file, "%s/ap_list", conf_dir);
    sprintf(wifi_list_file, "%s/wifi_list", conf_dir);
    
    ap_obj = (ap_t *)malloc(MAX_OBJ * sizeof(*ap_obj));
    new_ap_obj = (ap_t *)malloc(MAX_OBJ * sizeof(*new_ap_obj));
    rm_ap_obj = (ap_t *)malloc(MAX_OBJ * sizeof(*rm_ap_obj));
    
    wifi_obj = (wifi_t *)malloc(MAX_OBJ * sizeof(*wifi_obj));
    new_wifi_obj = (wifi_t *)malloc(MAX_OBJ * sizeof(*new_wifi_obj));
    rm_wifi_obj = (wifi_t *)malloc(MAX_OBJ * sizeof(*rm_wifi_obj));
    
    fp = fopen(csv_file, "r");
    if(fp != NULL){
	line_num = 0;
	while( fgets(line, sizeof(line), fp) != NULL ){
            if(strlen(line) > 2){
		line_num++;
		items = str_split(line, ',');
		if(!strcmp(*items, "BSSID"))
		    start_ap = line_num;
		else if(!strcmp(*items, "Station MAC"))
		    start_wifi = line_num;
	    }
	}
	fclose(fp);
    }
    else{
        printf("Error of Reading csv_file\n");
        return;
    }
    fp = fopen(csv_file, "r");
    if(fp != NULL){
	line_num = 0;
        while( fgets(line, sizeof(line), fp) != NULL ){
            if(strlen(line) > 2){
		line_num++;
                //printf("result is %s\n", csv_line);
                items = str_split(line, ',');
                temp_count = 0;
                for(i = 0; *(items + i); i++){
                    *(items + i) = strtok(*(items + i), "\n");
		    *(items + i) = strtok(*(items + i), "\r");
		    *(items + i) = strtok(*(items + i), "\0");
		    *(items + i) = strtok(*(items + i), "\t");
                    temp_count++;
                }
                
		if(line_num > start_ap && line_num < start_wifi){
		    char manuf_buf[MAX_STR];
		    memset(manuf_buf, '\0', sizeof(manuf_buf));
		    for(i = 16; i < temp_count; i++){
			strcat(manuf_buf, *(items + i));
			if(i != temp_count - 1)
			    strcat(manuf_buf, ",");
		    }
		    strcpy(ap_obj[ap_objs_count].bssid, *items);
		    strcpy(ap_obj[ap_objs_count].first_time_seen, *(items + 1));
		    strcpy(ap_obj[ap_objs_count].last_time_seen, *(items + 2));
		    ap_obj[ap_objs_count].channel = atoi(*(items + 3));
		    ap_obj[ap_objs_count].speed = atoi(*(items + 4));
		    strcpy(ap_obj[ap_objs_count].privacy, *(items + 5));
		    strcpy(ap_obj[ap_objs_count].cipher, *(items + 6));
		    ap_obj[ap_objs_count].power = atoi(*(items + 8));
		    strcpy(ap_obj[ap_objs_count].essid, *(items + 13));
		    strcpy(ap_obj[ap_objs_count].wps, *(items + 15));
		    strcpy(ap_obj[ap_objs_count].manuf, manuf_buf);
		    ap_obj[ap_objs_count].active = 1;
		    ap_objs_count++;
		}
                else if(line_num > start_wifi){
		    char probed_buf[MAX_STR];
		    memset(probed_buf, '\0', sizeof(probed_buf));
		    for(i = 6; i < temp_count; i++){
			strcat(probed_buf, *(items + i));
			if(i != temp_count - 1)
			    strcat(probed_buf, ",");
		    }
		    strcpy(wifi_obj[wifi_objs_count].station_mac, *items);
		    strcpy(wifi_obj[wifi_objs_count].first_time_seen, *(items + 1));
		    strcpy(wifi_obj[wifi_objs_count].last_time_seen, *(items + 2));
		    wifi_obj[wifi_objs_count].power = atoi(*(items + 3));
		    strcpy(wifi_obj[wifi_objs_count].bssid, strtok(*(items + 5), " "));
		    strcpy(wifi_obj[wifi_objs_count].probed, probed_buf);
		    wifi_obj[wifi_objs_count].active = 1;
		    wifi_objs_count++;
		}
            }            
        }
        fclose(fp);
    }
    else{
        printf("Error of Reading csv_file\n");
        return;
    }
    
    for(i = 0; i < ap_objs_count; i++){
	new_flag = 1;
	fp = fopen(ap_list_file, "a+");
	if(fp != NULL){
	    while( fgets(line, sizeof(line), fp) != NULL ){
		items = str_split(line, ',');
		if(strcmp(*items, ap_obj[i].bssid)){
		    new_flag = 1;
		    continue;
		}
		else{
		    new_flag = 0;
		    if(atoi(*(items + 3)) == 0){
			memset(&tm, 0, sizeof(struct tm));
			strptime(ap_obj[i].last_time_seen, " %Y-%m-%d %H:%M:%S", &tm);
			obj_last_seen = mktime(&tm);
			
			diff = difftime(current_time-scan_interval, obj_last_seen);
			if(diff < 0){
			    ap_obj[i].active = 1;
			    new_ap_obj[new_ap_objs_count] = ap_obj[i];
			    new_ap_objs_count++;
			    ap_updated = 1;
			}
			else
			    ap_obj[i].active = 0;
		    }
		    break;
		}
	    }
	     
	    if(new_flag != 0){
		fprintf(fp, "%s,%s,%s, %d, %s\n", ap_obj[i].bssid, ap_obj[i].first_time_seen, ap_obj[i].last_time_seen ,ap_obj[i].active, ap_obj[i].wps);
		
		new_ap_obj[new_ap_objs_count] = ap_obj[i];
		new_ap_objs_count++;
	    }

	}
	fclose(fp);
    }
    
    for(i = 0; i < ap_objs_count; i++){
	if(ap_obj[i].active != 0){
	    memset(&tm, 0, sizeof(struct tm));
	    strptime(ap_obj[i].last_time_seen, " %Y-%m-%d %H:%M:%S", &tm);
	    obj_last_seen = mktime(&tm);
	    
	    diff = difftime(current_time-LEFT_TIME, obj_last_seen);
	    if(diff > 0){
		ap_obj[i].active = 0;
		rm_ap_obj[rm_ap_objs_count] = ap_obj[i];
		rm_ap_objs_count++;
		ap_removed = 1;
	    }
	}
    }
    if((ap_removed != 0) || (ap_updated != 0)){
	fp = fopen(ap_list_file, "w+");
	for(i = 0; i < ap_objs_count; i++)
	    fprintf(fp, "%s,%s,%s, %d, %s\n", ap_obj[i].bssid, ap_obj[i].first_time_seen, ap_obj[i].last_time_seen ,ap_obj[i].active, ap_obj[i].wps);
	fclose(fp);
    }
    
    
    for(i = 0; i < wifi_objs_count; i++){
	new_flag = 1;
	fp = fopen(wifi_list_file, "a+");
	if(fp != NULL){
	    while( fgets(line, sizeof(line), fp) != NULL ){
		items = str_split(line, ',');
		if(strcmp(*items, wifi_obj[i].station_mac)){
		    new_flag = 1;
		    continue;
		}
		else{
		    new_flag = 0;
		    if(atoi(*(items + 3)) == 0){
			memset(&tm, 0, sizeof(struct tm));
			strptime(wifi_obj[i].last_time_seen, " %Y-%m-%d %H:%M:%S", &tm);
			obj_last_seen = mktime(&tm);
			
			diff = difftime(current_time-scan_interval, obj_last_seen);
			if(diff < 0){
			    wifi_obj[i].active = 1;
			    new_wifi_obj[new_wifi_objs_count] = wifi_obj[i];
			    new_wifi_objs_count++;
			    wifi_updated = 1;
			}
			else
			    wifi_obj[i].active = 0;
		    }  
		    break;
		}
	    }
	     
	    if(new_flag != 0){
		fprintf(fp, "%s,%s,%s, %d, %s\n", wifi_obj[i].station_mac, wifi_obj[i].first_time_seen, wifi_obj[i].last_time_seen,wifi_obj[i].active, wifi_obj[i].probed);
		
		new_wifi_obj[new_wifi_objs_count] = wifi_obj[i];
		new_wifi_objs_count++;
	    }
	}
	fclose(fp);
    }    
    
    for(i = 0; i < wifi_objs_count; i++){
	if(wifi_obj[i].active != 0){
	    memset(&tm, 0, sizeof(struct tm));
	    strptime(wifi_obj[i].last_time_seen, " %Y-%m-%d %H:%M:%S", &tm);
	    obj_last_seen = mktime(&tm);
	    
	    diff = difftime(current_time-LEFT_TIME, obj_last_seen);
	    if(diff > 0){
		wifi_obj[i].active = 0;
		rm_wifi_obj[rm_wifi_objs_count] = wifi_obj[i];
		rm_wifi_objs_count++;
		wifi_removed = 1;
	    }
	}
    }
    if((wifi_removed != 0) || (wifi_updated != 0)){
	fp = fopen(wifi_list_file, "w+");
	for(i = 0; i < wifi_objs_count; i++)
	    fprintf(fp, "%s,%s,%s, %d, %s\n", wifi_obj[i].station_mac, wifi_obj[i].first_time_seen, wifi_obj[i].last_time_seen ,wifi_obj[i].active, wifi_obj[i].probed);
	fclose(fp);
    }

    fp = fopen(scan_log, "a+");
    fprintf(fp, "%s", ctime(&current_time));
    for(i = 0; i < new_ap_objs_count; i++){
        fprintf(fp, "Added New AP : BSSID: %s, first time: %s, Last time: %s, channel: %d, speed: %d, privacy: %s, cipher: %s, power: %d, essid: %s, WPS: %s, MANUFACTURER: %s\n", \
                                                        new_ap_obj[i].bssid,\
                                                        new_ap_obj[i].first_time_seen, \
                                                        new_ap_obj[i].last_time_seen, \
                                                        new_ap_obj[i].channel,\
                                                        new_ap_obj[i].speed, \
                                                        new_ap_obj[i].privacy, \
                                                        new_ap_obj[i].cipher, \
                                                        new_ap_obj[i].power, \
                                                        new_ap_obj[i].essid, \
							new_ap_obj[i].wps, \
							new_ap_obj[i].manuf);
    }
    for(i = 0; i < rm_ap_objs_count; i++){
	fprintf(fp, "Removed AP : BSSID: %s, first time: %s, Last time: %s, channel: %d, speed: %d, privacy: %s, cipher: %s, power: %d, essid: %s, WPS: %s, MANUFACTURER: %s\n", \
                                                        rm_ap_obj[i].bssid,\
                                                        rm_ap_obj[i].first_time_seen, \
                                                        rm_ap_obj[i].last_time_seen, \
                                                        rm_ap_obj[i].channel,\
                                                        rm_ap_obj[i].speed, \
                                                        rm_ap_obj[i].privacy, \
                                                        rm_ap_obj[i].cipher, \
                                                        rm_ap_obj[i].power, \
                                                        rm_ap_obj[i].essid, \
							rm_ap_obj[i].wps, \
							rm_ap_obj[i].manuf);
    }
    for(i = 0; i < new_wifi_objs_count; i++){
        fprintf(fp, "Added New Wifi device : Station Mac: %s, First time: %s, Last time: %s, power: %d, BSSID: %s, probed ESSID: %s\n", \
                                                        new_wifi_obj[i].station_mac, \
                                                        new_wifi_obj[i].first_time_seen, \
                                                        new_wifi_obj[i].last_time_seen, \
                                                        new_wifi_obj[i].power, \
                                                        new_wifi_obj[i].bssid, \
							new_wifi_obj[i].probed);
    }
    for(i = 0; i < rm_wifi_objs_count; i++){
	fprintf(fp, "Removed Wifi device : Station Mac: %s, First time: %s, Last time: %s, power: %d, BSSID: %s, probed ESSID: %s\n", \
                                                        rm_wifi_obj[i].station_mac, \
                                                        rm_wifi_obj[i].first_time_seen, \
                                                        rm_wifi_obj[i].last_time_seen, \
                                                        rm_wifi_obj[i].power, \
                                                        rm_wifi_obj[i].bssid, \
							rm_wifi_obj[i].probed);
    }
    if(new_ap_objs_count || rm_ap_objs_count || new_wifi_objs_count || rm_wifi_objs_count)
	fprintf(fp, "\n");
    fprintf(fp, "ACCESS POINT INFOMATIONS\n");
    for(i = 0; i < ap_objs_count; i++){
        fprintf(fp, "BSSID: %s, first time: %s, Last time: %s, channel: %d, speed: %d, privacy: %s, cipher: %s, power: %d, essid: %s, WPS: %s, MANUFACTURER: %s\n", \
                                                        ap_obj[i].bssid,\
                                                        ap_obj[i].first_time_seen, \
                                                        ap_obj[i].last_time_seen, \
                                                        ap_obj[i].channel,\
                                                        ap_obj[i].speed, \
                                                        ap_obj[i].privacy, \
                                                        ap_obj[i].cipher, \
                                                        ap_obj[i].power, \
                                                        ap_obj[i].essid, \
                                                        ap_obj[i].wps, \
                                                        ap_obj[i].manuf);
    }
    fprintf(fp, "\nWIFI DEVICE INFOMATIONS\n");
    for(i = 0; i < wifi_objs_count; i++){
        fprintf(fp, "Station Mac: %s, First time: %s, Last time: %s, power: %d, BSSID: %s, probed ESSID: %s\n", \
                                                        wifi_obj[i].station_mac, \
                                                        wifi_obj[i].first_time_seen, \
                                                        wifi_obj[i].last_time_seen, \
                                                        wifi_obj[i].power, \
                                                        wifi_obj[i].bssid, \
                                                        wifi_obj[i].probed);
    }
    fprintf(fp, "\n =====================================================================================================\n");
    fclose(fp);
    
    free(ap_obj);
    free(new_ap_obj);
    free(rm_ap_obj);
    free(wifi_obj);
    free(new_wifi_obj);
    free(rm_wifi_obj);
}

int main(int argc, char *argv[]) {
    int c;
    pid_t pid;
    pid_t dump_pid = -1;
    char temp_file[] = "/tmp/wifi-scanner";
    char cmd[MAX_STR] = "\0";

    if(argc < 2){
        show_help();
    }

    while((c = getopt(argc, argv, "i:c:t:w:h")) != -1){
        switch (c){
	    case 'i':
		strcpy(mon_interface, optarg);
		break;
            case 't':
                scan_interval = atoi(optarg);
                break;
	    case 'c':
		strcpy(conf_dir, optarg);
		break;
            case 'w':
                strcpy(scan_log, optarg);
                break;
            case 'h':
                show_help();
            case '?':
                show_help();
            default:
                show_help();
        }
    }

    if(argc - optind == 1){
        interface = argv[argc - 1];
    }
    if(!interface){
        printf("Select interface to monitor\n");
        show_help();
    }
    

    sprintf(cmd, "rm -rf %s-01.*", temp_file);
    system(cmd);
    
    sprintf(cmd, "rm -rf %s/*", conf_dir);
    system(cmd);
         
    check_daemon();
    pre_scan(interface);

    dump_pid = fork();
    switch (dump_pid){
        case -1:
            printf("fork() error.\n");
            exit(EXIT_FAILURE);
        case 0:
	    sprintf(cmd, "airodump-ng -w %s --wps --manufacturer --output-format csv --band abg %s > /dev/null 2>&1", temp_file, mon_interface);
            system(cmd);
            break;
        default:
            break;
    }

    //Fork the Parent Process
    pid = fork();

    if (pid < 0) { exit(EXIT_FAILURE); }

    //We got a good pid, Close the Parent Process
    if (pid > 0) { exit(EXIT_SUCCESS); }

    //Close Standard File Descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    //----------------
    //Main Process
    //----------------
    while(1){
        wifi_scan();    //Run wifi scan
        sleep(scan_interval);    //Sleep for 60 seconds
    }

}
