fend: fend.c res rd rl
	gcc -o fend fend.c
rd:
	mkdir rd
	chmod 000 rd
res:
	touch res
	chmod 000 res
rl: rd
	ln -s rd rl
clean:
	rm -f fend res rl
	rmdir rd