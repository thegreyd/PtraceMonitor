/*
Author: Siddharth Sharma, NCSU
Unity ID: ssharm24
Class: CS501 2016
Instructor: Vincent Freeh
Assignment 1: Sandbox
*/
#include <sys/user.h> // for register user_regs_struct
#include <stdio.h> //fprintf, fscanf, printf, scanf, perror
#include <unistd.h> // fork exec
#include <sys/types.h> //pid_t
#include <stdlib.h> //for exit and EXIT, realpath
#include <sys/wait.h> //wait waitpid
#include <string.h> // strcmp, strcpy, strerror
#include <errno.h> //for errno
#include <sys/ptrace.h> //for ptrace
#include <err.h> //for err
#include <asm/unistd.h> // for __NR_read constants
#include <fcntl.h> // for O_RD constants
#include <fnmatch.h> // for matching wildcards
#include <sys/stat.h> // for checking if directory or file

typedef unsigned long long ull;
typedef struct user_regs_struct uregs;

typedef struct {
	pid_t child;
	int insyscall;
} sandbox;

typedef struct {
  int syscall;
  void (*callback)(sandbox *, uregs *,int);
  int fileindex;
} sandb_syscall;

int exec_once = 0;
char global_config_path[1000];
char *config_name = ".fendrc";
char *restricted_file = "/root/z";
const int word_length = 8; //for x86_64 , 4 for x86

void handle_exec(sandbox *, uregs *, int);
void handle_open(sandbox *, uregs *, int);
void handle_write(sandbox *, uregs *, int);
void handle_rename(sandbox *, uregs *, int);

void sandb_init(sandbox *, int, char**);
void sandb_run(sandbox *);
void sandb_kill(sandbox *);
void sandb_handle_syscall(sandbox *);

int parse_input(int, char **);
int find_config(char *);
int find_local_config();

void get_string(sandbox *, ull *, char *);
void set_string(sandbox *, ull *, char *);

int rw_perm(int);
ull get_addr(uregs *, int);
int block_file(char *, int);
int block_file_exec(char *);

sandb_syscall sandb_syscalls[] = {
  {__NR_creat,		handle_write,	0},
  {__NR_openat, 	handle_open,	1},
  {__NR_open,		handle_open,	0},
  {__NR_mkdir, 		handle_write,	0},
  {__NR_rmdir, 		handle_write,	0},
  {__NR_unlink, 	handle_write,	0},
  {__NR_unlinkat,	handle_write,	1},
  {__NR_execve, 	handle_exec,	0},
  {__NR_rename, 	handle_rename,	0},
  {__NR_renameat,	handle_rename,	1},
  {__NR_renameat2,	handle_rename,	1},
};

int rw_perm(int p){
	if(p==11) return 3;
	else if(p==10) return 0;
	else if(p==0) return -1;
	else if(p==1) return 1;
}

ull get_addr(uregs *regs, int index){
	switch(index){
		case(0):
			return regs->rdi;
		case(1):
			return regs->rsi;
		case(2):
			return regs->rdx;
		case(3):
			return regs->rcx;
		default:
			return 0;
	}
}

int block_file(char *path, int demand){
	int rwx,rw, block = 0;
	char pattern[1000];
	
	FILE *config = fopen(global_config_path,"r");
	while(fscanf(config, "%d %s", &rwx, pattern) != EOF) {
  		rw = rw_perm(rwx/10);
  		if(fnmatch(pattern, path, 0) == 0){
  			block = (rw != 3) && (rw != demand);
  		}
  	}
	fclose(config);
	return block;
}

int block_file_exec(char *path){
	int x, rwx,block = 0;
	char pattern[1000];
	
	FILE *config = fopen(global_config_path,"r");
	while(fscanf(config, "%d %s", &rwx, pattern) != EOF) {
  		x = rwx%10;
  		if(fnmatch(pattern, path, 0) == 0){
  			block = (x != 1);
  		}
  	}
	fclose(config);
	return block;
}

char filepathex[1000];
char realfilepathex[1000];
void handle_exec(sandbox *sandb, uregs *regs, int index){
	if(exec_once){
		return;
	}
	ull fileaddr = get_addr(regs, sandb_syscalls[index].fileindex);
	if(sandb->insyscall == 0){//syscall entry
		get_string(sandb, &fileaddr, filepathex);
		realpath(filepathex,realfilepathex);
		if(block_file_exec(realfilepathex)){
			set_string(sandb,&fileaddr,restricted_file);
			sandb->insyscall = 2;		
		}
		else{
			sandb->insyscall = 1;
		}
	}
	else{
		if(sandb->insyscall == 2){
			set_string(sandb, &fileaddr, filepathex);
		}
		sandb->insyscall = 0;
		exec_once = 1;
	}
}

char realfilepathrm1[1000];
char realfilepathrm2[1000];
char filepathrm1[1000];
char filepathrm2[1000];
void handle_rename(sandbox *sandb, uregs *regs, int index){
	int m1=0,m2=1;
	if(sandb_syscalls[index].fileindex == 1){
		m1 = 1;
		m2 = 3;
	}
	ull fileaddr1 = get_addr(regs, m1);
	ull fileaddr2 = get_addr(regs, m2);
	
	if(sandb->insyscall == 0){//syscall entry
		int mode = 1; //write permission
		get_string(sandb, &fileaddr1, filepathrm1);
		get_string(sandb, &fileaddr2, filepathrm2);
		realpath(filepathrm1,realfilepathrm1);
		realpath(filepathrm2,realfilepathrm2);
		if(block_file(realfilepathrm1,mode) || block_file(realfilepathrm2,mode)){
			set_string(sandb,&fileaddr1,restricted_file);
			sandb->insyscall = 2 ;
		}
		else{
			sandb->insyscall = 1;
		}
	}
	else{
		if(sandb->insyscall==2){
			set_string(sandb, &fileaddr1, filepathrm1);
		}
		sandb->insyscall = 0;
	}
}

char filepathwrite[1000];
char realfilepathwrite[1000];
void handle_write(sandbox *sandb, uregs *regs, int index){
	ull fileaddr = get_addr(regs, sandb_syscalls[index].fileindex);
	if(sandb->insyscall == 0){//syscall entry
		int mode = 1; //write permission
		get_string(sandb, &fileaddr, filepathwrite);
		realpath(filepathwrite,realfilepathwrite);
		if(block_file(realfilepathwrite,mode)){
			set_string(sandb,&fileaddr,restricted_file);
			sandb->insyscall = 2 ;
		}
		else{
			sandb->insyscall = 1;
		}
	}
	else{
		if(sandb->insyscall==2){
			set_string(sandb, &fileaddr, filepathwrite);
		}
		sandb->insyscall=0;
	}
}

char filepathop[1000];
char realfilepathop[1000];
void handle_open(sandbox *sandb, uregs *regs, int index){
	ull fileaddr = get_addr(regs, sandb_syscalls[index].fileindex);
	if(sandb->insyscall == 0){//syscall entry
		ull modeaddr = get_addr(regs, sandb_syscalls[index].fileindex+1);
		int creat = ((modeaddr & 67) > 3);
		int mode = modeaddr & O_ACCMODE;
		
		get_string(sandb, &fileaddr, filepathop);
		realpath(filepathop,realfilepathop);
		int filenotexist = (access(realfilepathop, F_OK ) == -1);
		
		if(creat && filenotexist && (mode == 0)){
			mode = 3;
		}
		if(block_file(realfilepathop,mode)){
			set_string(sandb,&fileaddr,restricted_file);
			sandb->insyscall = 2;	
		}
		else{
			sandb->insyscall = 1;
		}
	}	
	else{
		if(sandb->insyscall==2){
			set_string(sandb, &fileaddr, filepathop);
		}
		sandb->insyscall=0;
	}
}

int find_config(char *config_path){
	if(access(config_path, F_OK ) == -1){
		return(EXIT_FAILURE);
	}
	strcpy(global_config_path,config_path);
	return(EXIT_SUCCESS);
}
				
int find_local_config(){
	int status;
	char home_config_path[1000];
	 
	status = find_config(global_config_path);
	if(status == EXIT_FAILURE){
		strcpy(home_config_path, getenv("HOME"));
		strcat(home_config_path, "/");
		strcat(home_config_path, global_config_path);
		status = find_config(home_config_path);
		if(status==EXIT_FAILURE){
			err(EXIT_FAILURE, "Must provide a config file.");
		}
	}
	return(EXIT_SUCCESS);			
}

int parse_input(int argc, char **argv){
	int status;
	int config_local = 1;
	
	if(argc < 2){
		errx(EXIT_FAILURE, "Input error. Usage : %s [-c config] <command>", argv[0]);
	}
	
	if(strcmp(argv[1],"-c")==0){
		if(argc > 3){
			status = find_config(argv[2]);
			if(status == EXIT_FAILURE){
				err(EXIT_FAILURE, "Must provide a config file.");
			}
			config_local = 0;
		}
		else{
			errx(EXIT_FAILURE, "Input error. Usage : %s [-c config] <command>", argv[0]);
		}
	}
	else{
		find_local_config();
	}
	return config_local;
}

void get_string(sandbox *sandb, ull *addr, char *str){   
    char *laddr = str;
    int i = 0;
    union u {
        long val;
        char chars[sizeof(long)];
    }data;
    
    while(1){
        data.val = ptrace(PTRACE_PEEKDATA,sandb->child, *addr + (i*word_length),NULL);
        if(data.val < 0) {
			if(errno == ESRCH) {
				sandb_kill(sandb);
			}
			else{
				exit(EXIT_FAILURE);
			}
		}
        memcpy(laddr, data.chars, word_length);
        
        if(data.chars[word_length-1]=='\0'){
        	break;
        }
        if(i>100){
        	break;
        }
        i += 1;
        laddr += word_length;
    }
}

void set_string(sandbox *sandb, ull *addr, char *str){   
	char *laddr = str;
    int i = 0, status;
    union u {
        long val;
        char chars[sizeof(long)];
    }data;

    while(1) {
        memcpy(data.chars, laddr, word_length);
        status = ptrace(PTRACE_POKEDATA,sandb->child, *addr + (i*word_length), data.val);
        if(data.val < 0) {
			if(errno == ESRCH) {
				sandb_kill(sandb);
			}
			else{
				exit(EXIT_FAILURE);
			}
		}
        if(data.chars[word_length-1]=='\0'){
        	break;
        }
        if(i>100){
        	break;
        }
        i += 1;
        laddr += word_length;
    }
}

void sandb_handle_syscall(sandbox *sandb) {
  	int i, status;
	uregs regs;
	status = ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs);
	if(status < 0){
		exit(EXIT_FAILURE);
	}

	for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
		if(regs.orig_rax == sandb_syscalls[i].syscall) {
			if(sandb_syscalls[i].callback != NULL){
				sandb_syscalls[i].callback(sandb,&regs,i);
			}
			return;
		}
	}

	if(regs.orig_rax == -1){
		sandb_kill(sandb);
	}
	return;
}


void sandb_run(sandbox *sandb) {
	int status, pstatus, ch;
	pstatus = ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL);
	if(pstatus < 0) {
		if(errno == ESRCH) {
			waitpid(sandb->child, &status, __WALL | WNOHANG);
			sandb_kill(sandb);
		} 
		else{
			exit(EXIT_FAILURE);
		}
	}
		
	wait(&status);
	if(WIFEXITED(status)){
		exit(EXIT_SUCCESS);
	}
	if(WIFSTOPPED(status)){
		sandb_handle_syscall(sandb);
	}
}

void sandb_kill(sandbox *sandb) {
	kill(sandb->child, SIGKILL);
	wait(NULL);
	exit(EXIT_FAILURE);
}

void sandb_init(sandbox *sandb, int argc, char **argv) {
	int status;
	pid_t childpid;
	
	childpid = fork();
	switch(childpid){
		case(0):
			status = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
			if(status < 0){
				exit(EXIT_FAILURE);
			}

			status = execvp(argv[0], argv);
			if(status < 0){
				exit(EXIT_FAILURE);
			}
				
			break;
		
		case(-1):
			exit(EXIT_FAILURE);

		default:
			sandb->child = childpid;
    		sandb->insyscall = 0;
    		wait(NULL);
    }
}

int main(int argc, char **argv){	
	int config_local;
	pid_t childpid;
	
	strcpy(global_config_path,config_name);
	config_local = parse_input(argc, argv);
	sandbox sandb;
	if(config_local){
		sandb_init(&sandb, argc-1, argv+1);	
	}
	else{
		sandb_init(&sandb, argc-3, argv+3);	
	}
	
	while(1){
		sandb_run(&sandb);	
	}
	return EXIT_SUCCESS;
}