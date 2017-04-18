#define MAX_STR 2048
#define LEN_SSID 18
#define DEFAULT_INT 30
#define MAX_OBJ 1024
#define LEFT_TIME 120

struct ap_info{
    char bssid[LEN_SSID];
    char first_time_seen[MAX_STR];
    char last_time_seen[MAX_STR];
    unsigned int channel;
    unsigned int speed;
    int power;
    char privacy[MAX_STR];
    char cipher[MAX_STR];
    char essid[MAX_STR];
    char wps[MAX_STR];
    char manuf[MAX_STR];
    int active;
};
typedef struct ap_info ap_t;

struct wifi_info{
    char station_mac[LEN_SSID];
    char first_time_seen[MAX_STR];
    char last_time_seen[MAX_STR];
    int power;
    char bssid[LEN_SSID];
    char probed[MAX_STR];
    int active;
};
typedef struct wifi_info wifi_t;
