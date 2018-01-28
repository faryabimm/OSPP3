#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>

//Macros
#define DEFAULT_COMMAND_SIZE (size_t) 20
#define DEFAULT_ARGUMENT_COUNT 10
#define LOGGER_INTERVAL 5


//Structures
struct time_manager_args {
    int time;
    FILE *fd;
};

//Global Variables
char *shell_name;
char *shell_version;
char **log_buffer;
int logging = 0;
FILE *log_file;

static int init_shell(char[], char[], char **, size_t **, char ***, char ***, int);
static int mem_cleanup(char *shell_name, char *shell_version, size_t *command_size, char **lineptr, char **argv);
static int shell_exit(void);
void *time_manager(void *arguments);
int cmd_lookup(char *program_name, char **arg_list);
void sigalarm_handler(int signal_number);
void initiate_logger(int time_interval) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &sigalarm_handler;
    sigaction(SIGALRM, &sa, NULL);


    pthread_t time_manager_thread;

    struct time_manager_args args;
    args.time = time_interval;
    args.fd = log_file;


    pthread_create(&time_manager_thread, NULL, time_manager, &args);
}
void scan_command(char **lineptr, size_t *command_size) {
    ssize_t ret_val;
    ret_val = getline(lineptr, command_size, stdin);
    (*lineptr)[ret_val - 1] = '\0';

    if (logging) {
        fprintf(log_file, "CMD: %s\n", *lineptr);
    }
}
void pars_command_args(char *argv[], char **lineptr, char *delimiter, int *argument_count_coeff) {
    int arg_counter = 0;
    for (argv[arg_counter] = strtok(*lineptr, delimiter);
         argv[arg_counter] != NULL; arg_counter++, argv[arg_counter] = strtok(NULL, delimiter)) {
        if (arg_counter == DEFAULT_ARGUMENT_COUNT - 1)
            argv = realloc(argv, (++(*argument_count_coeff)) * DEFAULT_ARGUMENT_COUNT * sizeof(char *));
    }
}
void print_prepend(char *user_name, char *host_name) {
    fprintf(stdout, "%s@%s ", user_name, host_name);
    fprintf(stdout, "$ ");
}
void get_args(int argc, char *argv[], const char **log_file_name, const char **user_name, const char **host_name,
              char **bin_path, int *other_bin_path, int *time_interval) {
    int next_option;

    const char *const short_options = "l:uhb:t:";

    const struct option long_options[] = {
            {"logput",   1, NULL, 'l'},
            {"user",     0, NULL, 'u'},
            {"hostname", 0, NULL, 'h'},
            {"binpath",  1, NULL, 'b'},
            {"time",     1, NULL, 't'},
            {NULL,       0, NULL, 0}
    };


    do {
        next_option = getopt_long(argc, argv, short_options, long_options, NULL);
        switch (next_option) {
            case 'l':
                *log_file_name = optarg;
                logging = 1;
                break;
            case 'u':
                *user_name = getenv("USER");
                break;

            case 'h':
                *host_name = getenv("DESKTOP_SESSION");
                break;
            case 'b':
                *bin_path = optarg;
                *other_bin_path = 1;
                setenv("PATH", *bin_path, 1);
                break;
            case 't':
                *time_interval = atoi(optarg);
                break;

            case '?':
                printf("Invalid Argument!\n");
                break;
            case -1:    /* no more args.*/
                break;
            default:
                abort();
        }
    } while (next_option != -1);
}

/*
 * Builtin shell functions declarations
 */

int dsh_kill(char **args);
int dsh_cd(char **args);
int dsh_exit(char **args);
int dsh_help(char **args);

char *builtin_str[] = {
        "kill",
        "cd",
        "exit",
        "help",
};

int (*builtin_func[])(char **) = {
        &dsh_kill,
        &dsh_cd,
        &dsh_exit,
        &dsh_help,
};
int dsh_num_builtins() {
    return sizeof(builtin_str) / sizeof(char *);
}
/*
 * Builtin shell functions implementations
 */
int dsh_cd(char **args) {
    if (args[1] == NULL) {
        fprintf(stderr, "dsh: expected argument to \"cd\"\n");
    } else {
        if (chdir(args[1]) != 0) {
            perror("dsh");
        }
    }
    return 1;
}
int dsh_kill(char **args) {
    return 1;
}
int dsh_exit(char **args) {
    fprintf(stdout, "Good Luck!\n");
    return 0;
}
int dsh_help(char **args) {
    fprintf(stdout, "dragon shell v0.2!\n");
    fprintf(stdout, "By   Mohammadmahdi Faryabi!\n");
    fprintf(stdout, "   & Mohammadhosein A'lami!\n");
    return 1;
}

int execute_commnad(char *argv[]) {
    int pid = cmd_lookup(argv[0], argv);
    int status;
    wait(&status);

    if (WIFEXITED(status)) {
        if (logging) {
            fprintf(log_file, "RETVAL: %d\n", WEXITSTATUS(status));
        }
    } else {
        if (logging) {
            fprintf(log_file, "The child process exited abnormaly!\n");
        }
    }
    return -1; // indicating error!
}
int run_command(char *argv[]) {
    int i;
    if (argv[0] == NULL) {
        // An empty command was entered.
        return 1;
    }

    for (i = 0; i < dsh_num_builtins(); i++) {
        if (strcmp(argv[0], builtin_str[i]) == 0) {
            return (*builtin_func[i])(argv);
        }
    }
    return execute_commnad(argv);
}

int main(int argc, char *argv[]) {

    char *log_file_name = NULL;
    char *user_name = NULL;
    char *host_name = NULL;
    char *bin_path = NULL;
    int other_bin_path = 0;
    int argument_count_coeff = 1;
    int time_interval = LOGGER_INTERVAL;

    get_args(argc, argv, (const char **) &log_file_name, (const char **) &user_name, (const char **) &host_name,
             &bin_path, &other_bin_path, &time_interval);
    log_file = fopen(log_file_name, "w");
    initiate_logger(time_interval);

    size_t *command_size;
    char *delimiter = " ";
    char *command_line;
    char **lineptr;

    init_shell("DragonShell", "0.2", &command_line, &command_size, &lineptr, &argv, argument_count_coeff);
    fprintf(stdout, "Welcome to \"%s-v%s\"\n", shell_name, shell_version);
    int status;
    do {
        print_prepend(user_name, host_name);
        scan_command(lineptr, command_size);
        pars_command_args(argv, lineptr, delimiter, &argument_count_coeff);
        status = run_command(argv);
    } while (status);
    mem_cleanup(shell_name, shell_version, command_size, lineptr, argv);

    return 0;
}

int cmd_lookup(char *program_name, char **arg_list) {
    pid_t child_pid;

    child_pid = fork();

    if (child_pid != 0) {
        return child_pid;
    } else {
        execvp(program_name, arg_list);

        /* The execvp will never return unless error occurs. */
        if (logging) {
            fprintf(stderr, "an error occured when invoking execvp.\n");
        }
        abort();
    }
}
void sigalarm_handler(int signal_number) {
    time_t curr_time;
    time(&curr_time);
    struct tm *tm_parts = localtime(&curr_time);

    if (logging) {
        fprintf(log_file, "*****[ALARM Received AT %d:%d:%d]*****\n",
                tm_parts->tm_hour, tm_parts->tm_min, tm_parts->tm_sec);
    }
}
void *time_manager(void *arguments) {
    struct time_manager_args *args = (struct time_manager_args *) arguments;
    time_t curr_time;
    while (1) {
        sleep(args->time);
        time(&curr_time);
        if (logging) {
            fprintf(args->fd, "-----[%s]-----\n", ctime(&curr_time));
        }
    }
    int retval = 0;
    return &retval;
}
int mem_cleanup(char *shell_name, char *shell_version, size_t *command_size, char **lineptr, char **argv) {

    free((void *) shell_name);
    free((void *) shell_version);

    free((void *) *lineptr);
    free((void *) command_size);

    free((void *) argv);

    free((void *) log_buffer);

    return 0;
}
int init_shell(char *name, char *version, char **command_line, size_t **command_size, char ***lineptr, char ***argv,
               int argument_count_coeff) {
    shell_name = (char *) malloc(strlen(name) * sizeof(char));
    shell_version = (char *) malloc(strlen(version) * sizeof(char));

    strcpy(shell_name, name);
    strcpy(shell_version, version);

    (*command_line) = (char *) malloc(DEFAULT_COMMAND_SIZE);
    (*lineptr) = command_line;

    (*command_size) = (size_t *) malloc(sizeof(int));
    (**command_size) = DEFAULT_COMMAND_SIZE;

    (*argv) = (char **) malloc((argument_count_coeff) * DEFAULT_ARGUMENT_COUNT * sizeof(char *));

    return 0;
}

