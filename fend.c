//barebones sandbox
#include <sys/user.h> // for register user_regs_struct
#include <stdio.h> //fprintf, fscanf, printf, scanf, perror
#include <unistd.h> // fork exec
#include <sys/types.h> //for pid_t
#include <stdlib.h> //for exit and EXIT
#include <sys/wait.h> //wait waitpid
#include <string.h> // strcmp
#include <errno.h> //for errno
#include <sys/ptrace.h> //for ptrace
#include <err.h> //for err
#include <asm/unistd.h> // for __NR_read etc constants
#include <fcntl.h> // for O_RD constants

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
  const char * syscallname;
  void (*callback)(sandbox *, uregs *);
} sandb_syscall;

void handle_open(sandbox *, uregs *);
void get_open_mode(int, char *);
void sandb_init(sandbox *, int, char**);
void sandb_run(sandbox *);
void sandb_kill(sandbox *);
void sandb_handle_syscall(sandbox *);
void parse_config(FILE *);
int find_config(char *);
int parse_input(int, char **);
int find_local_config();
void get_string(sandbox *, unsigned long long, char *);
void set_string(sandbox *, unsigned long long, char *);

sandb_syscall sandb_syscalls[] = {
  {__NR_read,		"Read",		NULL},
  {__NR_write,		"Write",    NULL},
  {__NR_exit,		"Exit",     NULL},
  {__NR_brk,		"Break",    NULL},
  {__NR_mmap,		"Mmap",     NULL},
  {__NR_access,		"Access",   NULL},
  {__NR_open,		"Open",    	handle_open},
  {__NR_fstat,		"Fstat",    NULL},
  {__NR_close,		"Close",   	NULL},
  {__NR_mprotect,	"Mprotect", NULL},
  {__NR_munmap,		"Munmap",   NULL},
  {__NR_arch_prctl,	"Arch_pr",  NULL},
  {__NR_exit_group,	"Exit_grp", NULL},
  {__NR_getdents,	"Getdents", NULL},
};

void handle_open(sandbox *sandb, uregs *regs ){
	char filepath[1000];
	char filepath2[1000];
	char mode[10];
	char *aliens = "aliens.txt";
	
	if(sandb->insyscall == 0){//syscall entry
		sandb->insyscall = 1;

		get_string(sandb, regs->rdi, filepath);
		get_open_mode(regs->rsi, mode);
		printf("Open(\"%s\",%s)", filepath, mode);
		
		if(regs->rdi%3==0){
			set_string(sandb, regs->rdi, aliens);
			sandb->insyscall = 2 ;	
		}
	}
	
	else{
		if(sandb->insyscall==2)
			set_string(sandb, regs->rdi, filepath);
			
		if(regs->rax < 0)
			printf(" = %d, %s\n",(int)regs->rax,strerror(-1*(regs->rax)));
		else
			printf(" = %d\n",(int)regs->rax);
	
		sandb->insyscall=0;
	}
}



void get_open_mode(int flags, char *mode){
	int accessMode = flags & O_ACCMODE;

	strcpy(mode,"");
	if(accessMode==O_WRONLY)
		strcat(mode,"O_WRONLY");
	else if(accessMode == O_RDWR)
		strcat(mode,"O_RDWR");
	else
		strcat(mode,"O_RDONLY");
}



void parse_config(FILE *config){
	
}

int find_config(char *config_path){
	FILE *config_file;

	config_file = fopen(config_path,"r");
	if(!config_file)
		return(EXIT_FAILURE);
	
	printf("Found config file at %s.\n",config_path);
	//load_config(config_file);
	fclose(config_file);
	return(EXIT_SUCCESS);
}
				
int find_local_config(){
	int status;
	char home_config_path[100];
	char *local_config_name = ".fendrc"; 
	
	status = find_config(local_config_name);
	if(status==EXIT_FAILURE){
		strcpy(home_config_path, getenv("HOME"));
		strcat(home_config_path, "/.fendrc");
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

void get_string(sandbox *sandb, unsigned long long addr, char *str){   
    char *laddr;
    int i;
    union u {
        long long val;
        char chars[long_size];
    }data;
    
    i = 0;
    laddr = str;
    while(1) {
        data.val = ptrace(PTRACE_PEEKDATA,sandb->child, addr + (i*word_length),NULL);
        memcpy(laddr, data.chars, long_size);
        if(data.chars[word_length-1]=='\0')
        	break;
		i += 1;
        laddr += long_size;
    }
}

void set_string(sandbox *sandb, unsigned long long addr, char *str){   
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
        ptrace(PTRACE_POKEDATA,sandb->child, addr + (i*word_length), data.val);
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
			if(sandb_syscalls[i].callback != NULL)
				sandb_syscalls[i].callback(sandb, &regs);
			return;
		}
	}

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