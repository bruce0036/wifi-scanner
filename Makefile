PROG = wifi-scanner

all:
	gcc -o $(PROG) wifi-scanner.c

clean:
	rm -f $(PROG)

install:
	cp $(PROG) /usr/local/bin/
	mkdir -p /usr/local/etc/airodump-ng/conf
