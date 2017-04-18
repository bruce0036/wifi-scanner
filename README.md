1) pre-install aircrack-ng
	sudo apt-get install aircrack-ng

2) build 
	- build binary with gcc
		make
	- install binary to /usr/local/bin
		make install
	- remove the binary that built
		make clean

3) Usage
	
Usage:
 wifi-scanner [options] <wireless interface>
Options:
    -t : checking time, default 30s
    -w : output file, default /var/log/wifi-scan.log
    -h : show help

example: 
	wifi-scanner wlan0

	- if you need to check every 60 second.
	wifi-scanner -t 60 wlan0

	- if you need to change log file path.
	wifi-scanner -w test.log wlan0

	- show help page
	wifi-scanner -h
