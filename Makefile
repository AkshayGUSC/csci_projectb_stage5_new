all: inputs running

inputs:
	gcc -c -Wall router_connection.c
	gcc -c -Wall proxy_connection.c
	gcc -c -Wall main_program_3.c
	gcc -c -Wall input_identification.c
	gcc -c -Wall circuit.c
	gcc -o proja input_identification.c router_connection.c proxy_connection.c circuit.c main_program_3.c

running:
	sudo ./proja file

clean:
	rm -rf proja *.o *.out

.PHONY: running clean
