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

char global_config_path[1000];
char *config_name = ".fendrc";
char *restricted_file = "res";
char *restricted_directory = "rd";
char *restricted_link = "rl";
char *restricted_name;
const int word_length = 8; //for x86_64 , 4 for x86
const int long_size = sizeof(unsigned long long);

typedef struct user_regs_struct uregs;

typedef struct {
	pid_t child;
	const char *progname;
	int insyscall;
} sandbox;

typedef struct {
  int syscall;
  void (*callback)(sandbox *, unsigned long long *, unsigned long long *, unsigned long long *);
  int pathpos;
} sandb_syscall;

void handle_open(sandbox *, unsigned long long *, unsigned long long *, unsigned long long *);
int get_open_mode(unsigned long long *, char *);
void sandb_init(sandbox *, int, char**);
void sandb_run(sandbox *);
void sandb_kill(sandbox *);
void sandb_handle_syscall(sandbox *);
void parse_config(FILE *);
int find_config(char *);
int parse_input(int, char **);
int find_local_config();
void get_string(sandbox *, unsigned long long *, char *);
void set_string(sandbox *, unsigned long long *, char *);
int block_file(char *, int mode);
int rw_perm(int);

sandb_syscall sandb_syscalls[] = {
  {__NR_creat,	NULL,	0},
  {__NR_openat, handle_open,	1},
  {__NR_open,	handle_open,	0},
  {__NR_access,	NULL,			0},
  {__NR_fstat,	NULL,			0},
};

int rw_perm(int p){
	if(p==11) return 3;
	else if(p==10) return 2;
	else return p;
}

int block_file(char *filepath, int demand){
	int match, allowed, status, block=0;
	char pattern[1000];
	char real_path[1000];
	struct stat sb;

	realpath(filepath,real_path);
	
	FILE *config = fopen(global_config_path,"r");
	status = fscanf(config, "%d %s", &allowed, pattern);
	allowed = rw_perm(allowed/10);
	while(status != EOF) {
  		match = fnmatch(pattern, real_path, 0);
  		if(match == 0){
  			if((allowed & demand) != demand)
  				block=1;
  			else
  				block=0;
  		}
  		status = fscanf(config, "%d %s", &allowed, pattern);
	}
	fclose(config);
	
	restricted_name = restricted_file;
	stat(filepath, &sb);
    if(S_ISDIR(sb.st_mode))
       restricted_name = restricted_directory;
    else if(S_ISLNK(sb.st_mode))
       restricted_name = restricted_link;
	
	return block;
}


void handle_open(sandbox *sandb, unsigned long long *fileaddr, unsigned long long *modeaddr, unsigned long long *returnaddr){
	char filepath[1000];
	char mode[10];
	int m;
	
	if(sandb->insyscall == 0){//syscall entry
		sandb->insyscall = 1;

		get_string(sandb, fileaddr, filepath);
		m=get_open_mode(modeaddr, mode);
		printf("Open(\"%s\",%s)", filepath, mode);
		
		if(block_file(filepath,m)){
			set_string(sandb,fileaddr,restricted_name);
			sandb->insyscall = 2 ;	
		}
	}
	
	else{
		if(sandb->insyscall==2){
			set_string(sandb, fileaddr, filepath);
		}
			
		if(*returnaddr < 0){
			printf(" = %d, %s\n",(int)*returnaddr,strerror(-1*(*returnaddr)));
		}
		else{
			printf(" = %d\n",(int)*returnaddr);
		}
	
		sandb->insyscall=0;
	}
}

int get_open_mode(unsigned long long *flags, char *mode){
	int accessMode = *flags & O_ACCMODE;

	strcpy(mode,"");
	if(accessMode==O_WRONLY){
		strcat(mode,"O_WRONLY");
		return 1;
	}
	else if(accessMode == O_RDWR){
		strcat(mode,"O_RDWR");
		return 3;
	}
	strcat(mode,"O_RDONLY");
	return 2;
}

int find_config(char *config_path){
	if(access(config_path, F_OK ) == -1)
		return(EXIT_FAILURE);
	
	strcpy(global_config_path,config_path);
	printf("Found config file at %s.\n",global_config_path);
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

void get_string(sandbox *sandb, unsigned long long *addr, char *str){   
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

void set_string(sandbox *sandb, unsigned long long *addr, char *str){   
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
				if(sandb_syscalls[i].pathpos==0)
					sandb_syscalls[i].callback(sandb,&regs.rdi,&regs.rsi,&regs.rax);
				else
					sandb_syscalls[i].callback(sandb,&regs.rsi,&regs.rdx,&regs.rax);
			}
			return;
		}
	}
	//if(!found)
	//	printf("System call %llu\n", regs.orig_rax);

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