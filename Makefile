fend: fend.c aliens.txt
	gcc -o fend fend.c
aliens.txt:
	touch aliens.txt
	chmod 000 aliens.txt
clean:
	rm fend aliens.txt
