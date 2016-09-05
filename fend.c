//barebones sandbox
#include <sys/user.h> // for register user_regs_struct
#include <stdio.h> //fprintf, fscanf, printf, scanf, perror
#include <unistd.h> // fork exec
#include <sys/types.h> //for pid_t
#include <stdlib.h> //for exit and EXIT, realpath
#include <sys/wait.h> //wait waitpid
#include <string.h> // strcmp, strcpy, strerror
#include <errno.h> //for errno
#include <sys/ptrace.h> //for ptrace
#include <err.h> //for err
#include <asm/unistd.h> // for __NR_read etc constants
#include <fcntl.h> // for O_RD constants
#include <fnmatch.h> // for matching wildcards
#include <sys/stat.h> // for checking if directory or file

typedef unsigned long long ull;
typedef struct user_regs_struct uregs;

typedef struct {
	pid_t child;
	const char *progname;
	int insyscall;
} sandbox;

char global_config_path[1000];
char *config_name = ".fendrc";
char *restricted_file = "/root/r";
const int word_length = 8; //for x86_64 , 4 for x86
const int long_size = sizeof(ull);

typedef struct {
  int syscall;
  void (*callback)(sandbox *, uregs *,int);
  int fileindex;
} sandb_syscall;

void handle_open(sandbox *, uregs *, int);
void handle_write(sandbox *, uregs *, int);
int get_open_mode(ull *, char *);

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
int block_open(int,int);
int block_file(char *, int);

sandb_syscall sandb_syscalls[] = {
  {__NR_creat,	handle_write,	0},
  {__NR_openat, handle_open,	1},
  {__NR_open,	handle_open,	0},
  {__NR_access,	NULL,			0},
  {__NR_fstat,	NULL,			0},
  {__NR_mkdir, 	handle_write,	0},
  {__NR_rmdir, 	handle_write,	0},
  {__NR_unlink, handle_write,	0},
  {__NR_unlinkat,handle_write,	1},
  {__NR_execve, handle_exec,	0}
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
	int allowed, block=0;
	char pattern[1000];
	
	FILE *config = fopen(global_config_path,"r");
	while(fscanf(config, "%d %s", &allowed, pattern) != EOF) {
  		allowed = rw_perm(allowed/10);
  		if(fnmatch(pattern, path, 0) == 0)
  			block = (allowed != 3) && (allowed != demand);
  	}
	fclose(config);
	return block;
}

int block_file_exec(char *path){
	int allowed, block=0;
	char pattern[1000];
	
	FILE *config = fopen(global_config_path,"r");
	while(fscanf(config, "%d %s", &allowed, pattern) != EOF) {
  		allowed = allowed%10;
  		if(fnmatch(pattern, path, 0) == 0)
  			block = (allowed == 1);
  	}
	fclose(config);
	return block;
}

void handle_exec(sandbox *sandb, uregs *regs, int index){
	ull fileaddr = get_addr(regs, sandb_syscalls[index].fileindex);
	char filepath[1000];
	
	if(sandb->insyscall == 0){//syscall entry
		char realfilepath[1000];
		char newpath[1000];

		get_string(sandb, &fileaddr, filepath);
		realpath(filepath,realfilepath);
		//printf("Creat/Rm(\"%s\")", realfilepath);
		if(block_file_exec(realfilepath)){
			//printf(" --blocking %s",realfilepath);			
			set_string(sandb,&fileaddr,restricted_file);
			sandb->insyscall = 2 ;	
		}
		sandb->insyscall = 1;
	}
	else{
		if(sandb->insyscall==2)
			set_string(sandb, &fileaddr, filepath);
		//printf(" = %d\n",(int)regs->rax);
		sandb->insyscall=0;
	}
}

void handle_write(sandbox *sandb, uregs *regs, int index){
	ull fileaddr = get_addr(regs, sandb_syscalls[index].fileindex);
	char filepath[1000];
	
	if(sandb->insyscall == 0){//syscall entry
		int mode = 1, n; //write permission
		char realfilepath[1000];
		char newpath[1000];

		get_string(sandb, &fileaddr, filepath);
		realpath(filepath,realfilepath);
		//printf("Creat/Rm(\"%s\")", realfilepath);
		
		n = strlen(realfilepath)-strlen(strrchr(realfilepath, '/'));
		strncpy(newpath,realfilepath,n);
		strcpy(realfilepath, newpath);

		if(block_file(realfilepath,mode)){
			//printf(" --blocking %s",realfilepath);			
			set_string(sandb,&fileaddr,restricted_file);
			sandb->insyscall = 2 ;	
		}
		sandb->insyscall = 1;
	}
	else{
		if(sandb->insyscall==2)
			set_string(sandb, &fileaddr, filepath);
		//printf(" = %d\n",(int)regs->rax);
		sandb->insyscall=0;
	}
}

void handle_open(sandbox *sandb, uregs *regs, int index){
	char filepath[1000];
	ull fileaddr = get_addr(regs, sandb_syscalls[index].fileindex);
	
	if(sandb->insyscall == 0){//syscall entry
		ull modeaddr = get_addr(regs, sandb_syscalls[index].fileindex+1);
		int creat = ((modeaddr & 67) > 3);
		int mode = modeaddr & O_ACCMODE;
		char realfilepath[1000];
		
		get_string(sandb, &fileaddr, filepath);
		realpath(filepath,realfilepath);
		//printf("Open(\"%s\",%d,%d)", realfilepath, mode, creat);
		int filenotexist = (access(realfilepath, F_OK ) == -1);
		//printf(" --filenotexist %d ", filenotexist);
		
		if(creat && filenotexist){
			char newpath[1000];
			int n = strlen(realfilepath)-strlen(strrchr(realfilepath, '/'));
			strncpy(newpath,realfilepath,n);
			strcpy(realfilepath, newpath);
			mode = 1;
		}
		
		if(block_file(realfilepath,mode)){
			//printf("--Blocking %s ", realfilepath);
			set_string(sandb,&fileaddr,restricted_file);
			sandb->insyscall = 2;	
		}
		
		sandb->insyscall = 1;
	}
	else{
		if(sandb->insyscall==2)
			set_string(sandb, &fileaddr, filepath);
		//printf(" = %d\n",(int)regs->rax);
		sandb->insyscall=0;
	}
}

int find_config(char *config_path){
	if(access(config_path, F_OK ) == -1)
		return(EXIT_FAILURE);
	
	strcpy(global_config_path,config_path);
	return(EXIT_SUCCESS);
}
				
int find_local_config(){
	int status;
	char home_config_path[100];
	 
	status = find_config(global_config_path);
	if(status==EXIT_FAILURE){
		strcpy(home_config_path, getenv("HOME"));
		strcat(home_config_path, "/");
		strcat(home_config_path, global_config_path);
		status = find_config(home_config_path);
		if(status==EXIT_FAILURE)
			err(EXIT_FAILURE, "Must provide a config file.");
	}
	return(EXIT_SUCCESS);			
}

int parse_input(int argc, char **argv){
	int status;
	int config_local = 1;
	
	if(argc < 2)
		errx(EXIT_FAILURE, "Input error. Usage : %s [-c config] <command>", argv[0]);

	if(strcmp(argv[1],"-c")==0){
		if(argc > 3){
			status = find_config(argv[2]);
			if(status==EXIT_FAILURE)
				err(EXIT_FAILURE, "Config File Error");

			config_local = 0;
		}
		else 
			errx(EXIT_FAILURE, "Input error. Usage : %s [-c config] <command>", argv[0]);
	}
	else
		find_local_config();

	return config_local;
}

int main(int argc, char **argv){	
	int config_local;
	pid_t childpid;
	
	strcpy(global_config_path,config_name);

	config_local = parse_input(argc, argv);
	sandbox sandb;
	if(config_local)
		sandb_init(&sandb, argc-1, argv+1);	
	else
		sandb_init(&sandb, argc-3, argv+3);	

	while(1)
		sandb_run(&sandb);	
	return EXIT_SUCCESS;
}

void get_string(sandbox *sandb, ull *addr, char *str){   
    char *laddr;
    int i;
    union u {
        long long val;
        char chars[long_size];
    }data;
    
    i = 0;
    laddr = str;
    while(1) {
        data.val = ptrace(PTRACE_PEEKDATA,sandb->child, *addr + (i*word_length),NULL);
        memcpy(laddr, data.chars, long_size);
        if(data.chars[word_length-1]=='\0')
        	break;
		i += 1;
        laddr += long_size;
    }
}

void set_string(sandbox *sandb, ull *addr, char *str){   
	char *laddr;
    int i;
    union u {
        long long val;
        char chars[long_size];
    }data;
    
    i = 0;
    laddr = str;
    while(1) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA,sandb->child, *addr + (i*word_length), data.val);
        if(data.chars[word_length-1]=='\0')
        	break;
        i += 1;
        laddr += long_size;
    }
}

void sandb_handle_syscall(sandbox *sandb) {
  	int i, status;
	uregs regs;
	status = ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs);
	if(status < 0)
		err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

	for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
		if(regs.orig_rax == sandb_syscalls[i].syscall) {
			if(sandb_syscalls[i].callback != NULL){
				sandb_syscalls[i].callback(sandb,&regs,i);
			}
			return;
		}
	}
	//printf("System call %llu\n", regs.orig_rax);

	if(regs.orig_rax == -1){
		printf("[SANDBOX] Segfault ?! KILLING !!!\n");
		sandb_kill(sandb);
	}
	return;
}

void sandb_run(sandbox *sandb) {
	int status, pstatus;

	pstatus = ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL);
	if(pstatus < 0) {
		if(errno == ESRCH) {
			//waitpid(sandb->child, &status, __WALL | WNOHANG);
			sandb_kill(sandb);
		} 
		else 
			err(EXIT_FAILURE, "Ptrace Error");
	}

	wait(&status);
	if(WIFEXITED(status))
		exit(EXIT_SUCCESS);
	if(WIFSTOPPED(status))
		sandb_handle_syscall(sandb);
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
			if(status < 0)
				err(EXIT_FAILURE, "Ptrace error");

			status = execv(argv[0], argv);
			if(status < 0)
				err(EXIT_FAILURE, "Exec error: %s",argv[0]);
				
			break;
		
		case(-1):
			err(EXIT_FAILURE, "Fork error");

		default:
			sandb->child = childpid;
    		sandb->progname = argv[0];
    		sandb->insyscall = 0;
    		wait(NULL);
    }
}