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

const int long_size = sizeof(unsigned long long);

typedef struct {
	pid_t child;
	const char *progname;
	int insyscall;
} sandbox;

typedef struct {
  int syscall;
  const char * syscallname;
  void (*callback)(sandbox *, struct user_regs_struct *);
  int check;
} sandb_syscall;

sandb_syscall sandb_syscalls[] = {
  {__NR_read,		"Read",		NULL,	0},
  {__NR_write,		"Write",    NULL,	0},
  {__NR_exit,		"Exit",     NULL,	0},
  {__NR_brk,		"Break",    NULL,	0},
  {__NR_mmap,		"Mmap",     NULL,	0},
  {__NR_access,		"Access",   NULL,	1},
  {__NR_open,		"Open",    	NULL,	1},
  {__NR_fstat,		"Fstat",    NULL,	0},
  {__NR_close,		"Close",   	NULL,	0},
  {__NR_mprotect,	"Mprotect", NULL,	0},
  {__NR_munmap,		"Munmap",   NULL,	0},
  {__NR_arch_prctl,	"Arch_pr",  NULL,	0},
  {__NR_exit_group,	"Exit_grp", NULL,	0},
  {__NR_getdents,	"Getdents", NULL,	0},
};

void sandb_init(sandbox *, int, char**);
void sandb_run(sandbox *);
void sandb_kill(sandbox *);
void sandb_handle_syscall(sandbox *sandb);

void load_config(char *file_path){
	FILE *config_file;
}

int find_config(char *config_path){
	FILE *config_file;

	config_file = fopen(config_path,"r");
	if(!config_file)
		return(EXIT_FAILURE);
	
	printf("Found config file at %s.\n",config_path);
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



void getdata(pid_t child, unsigned long long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + (i*8),
                          NULL);
        //printf("Ptrace_peekdata %llu\n", data.val);

        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * 8,
                          NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
    //printf("Ptrace_peekdata %llu\n", data.val);
    //printf("errno %d %s\n",errno,strerror(errno));
}

void sandb_handle_syscall(sandbox *sandb) {
  	int i, pstatus,s;
	struct user_regs_struct regs;
	
	pstatus = ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs);
	if(pstatus < 0)
		err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

	for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
		if(regs.orig_rax == sandb_syscalls[i].syscall) {
			
			if(sandb->insyscall == 0){//syscall entry
				sandb->insyscall = 1;
				
				if(sandb_syscalls[i].check){
					char *str;
					str = (char *)calloc(1,(regs.rsi+1)* sizeof(char));
					getdata(sandb->child, regs.rdi, str,regs.rsi);
					printf("%s(\"%s\",%llu,%llu,%llu)", sandb_syscalls[i].syscallname, str, regs.rdi,regs.rsi, regs.rdx);
				}
				//else
					//printf("%s(%llu,%llu,%llu)", sandb_syscalls[i].syscallname, regs.rdi, regs.rsi, regs.rdx);
			}

			else{
				if(sandb_syscalls[i].check){
					if((long int)regs.rax<0){
						printf(" = %ld, %s\n",(long int)regs.rax,strerror(-1*regs.rax));
					}
					else
						printf(" = %ld\n",(long int)regs.rax);
				}
				sandb->insyscall=0;
			}

			/*
			
			if(sandb_syscalls[i].callback != NULL){
				printf("Callback function is not NULLl\n");
				sandb_syscalls[i].callback(sandb, &regs);
			}
			else{
				printf("In else\n" );
				s=ptrace(PTRACE_CONT, sandb->child, NULL, NULL);
				if(s==-1)
					err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_CONT:");
				wait(NULL);
				//s=ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL);

				//if(s==-1)
				//	err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
				
			}*/	
			return;
		}
	}

	if(regs.orig_rax == -1){
		printf("[SANDBOX] Segfault ?! KILLING !!!\n");
		sandb_kill(sandb);
	}
	//else
		//printf("[SANDBOX] Trying to use devil syscall (%llu) \n", regs.orig_rax);
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