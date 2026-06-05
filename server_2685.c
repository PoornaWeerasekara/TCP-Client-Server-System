#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#define SERVERPORT 50685
#define MAX 4096
#define SID "1026"

typedef struct {
    char user[50];
    char hash[65];
    char salt[20];
} userrecord;

userrecord users[100];
int usercount = 0;
 
typedef struct {
    char user[50];
    char usertoken[64];
    time_t lastactive;
} usersession;

usersession activeusersession[100];
int sessioncount = 0;

void hash_password(const char *password, const char *salt, char *output) {
    char input[100];
    sprintf(input, "%s%s", password, salt);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input, strlen(input), hash);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
}

void createtoken(char *usertoken) {
    sprintf(usertoken, "%ld", random());
}

usersession* findsession(char *usertoken) {
    for(int i=0;i<sessioncount;i++) {
        if(strcmp(activeusersession[i].usertoken, usertoken)==0)
            return &activeusersession[i];
    }
    return NULL;
}

void logwrite(char *ip, int port, char *user, char *cmd, char *status) {
    FILE *f = fopen("server_IT24102685.log", "a");
    fprintf(f,"TIME:%ld PID:%d CLIENT:%s:%d USER:%s CMD:%s STATUS:%s\n",
        time(NULL), getpid(), ip, port, user, cmd, status);
    fclose(f);
}

void create_user_directory(char *user) {
    mkdir("/srv/ie2102", 0777);
    mkdir("/srv/ie2102/IT24102685", 0777);

    char path[200];
    sprintf(path, "/srv/ie2102/IT24102685/%s", user);
    mkdir(path, 0777);

    printf("Directory created for user: %s\n", user);
}

void handleclient(int clientconnsocke, char *ip, int port) {

    char databuffer[8192];
    int buffer_len = 0;

    int requestcount = 0;
    time_t start = time(NULL);

    printf("Client connected: %s:%d\n", ip, port);

    while(1) {

        int n = recv(clientconnsocke, databuffer + buffer_len,
                     sizeof(databuffer) - buffer_len - 1, 0);

        if(n <= 0) {
            printf("Client disconnected: %s:%d\n", ip, port);
            break;
        }

        buffer_len += n;
        databuffer[buffer_len] = '\0';

        if(time(NULL)-start < 1) {
            requestcount++;
            if(requestcount > 10) {
                char msg[] = "ERR 429 SID:1026 Too many requests\n";
                send(clientconnsocke, msg, strlen(msg), 0);
                break;
            }
        } else {
            requestcount = 0;
            start = time(NULL);
        }

        while(1) {

            char *nl = strchr(databuffer, '\n');
            if(!nl) break;

            int header_len = nl - databuffer + 1;

            if(strncmp(databuffer,"LEN:",4)!=0) {
                printf("Invalid format\n");
                break;
            }

            int messagelen = atoi(databuffer+4);

            if(buffer_len < header_len + messagelen)
                break;

            char message[4096];
            memcpy(message, databuffer+header_len, messagelen);
            message[messagelen] = '\0';

            printf("Message: %s\n", message);

            memmove(databuffer,
                    databuffer + header_len + messagelen,
                    buffer_len - (header_len + messagelen));

            buffer_len -= (header_len + messagelen);

            char cmd[20], user[50], password[50], usertoken[64];
            sscanf(message,"%s %s %s %s",cmd,user,password,usertoken);

            printf("Command: %s\n", cmd);

            if(!strcmp(cmd,"REGISTER")) {

                char salt[20];
                sprintf(salt,"%ld",random());

                char hash[65];
                hash_password(password,salt,hash);

                strcpy(users[usercount].user,user);
                strcpy(users[usercount].hash,hash);
                strcpy(users[usercount].salt,salt);
                usercount++;

                create_user_directory(user);

                printf("User registered: %s\n", user);

                char msg[] = "OK 200 SID:1026 User created\n";
                send(clientconnsocke, msg, strlen(msg), 0);

                logwrite(ip,port,user,cmd,"OK");
            }

            else if(!strcmp(cmd,"LOGIN")) {

                int found = 0;

                for(int i=0;i<usercount;i++) {
                    if(strcmp(users[i].user,user)==0) {

                        char hash[65];
                        hash_password(password,users[i].salt,hash);

                        if(strcmp(hash,users[i].hash)==0) {

                            char newtoken[64];
                            createtoken(newtoken);

                            strcpy(activeusersession[sessioncount].user,user);
                            strcpy(activeusersession[sessioncount].usertoken,newtoken);
                            activeusersession[sessioncount].lastactive=time(NULL);
                            sessioncount++;

                            char msg[128];
                            sprintf(msg,"OK 200 SID:1026 TOKEN:%s\n", newtoken);

                            printf("Login success: %s\n", user);

                            send(clientconnsocke, msg, strlen(msg), 0);
                            logwrite(ip,port,user,cmd,"OK");

                            found = 1;
                            break;
                        }
                    }
                }

                if(!found) {
                    printf("Login failed: %s\n", user);

                    char msg[] = "ERR 401 SID:1026 Invalid credentials\n";
                    send(clientconnsocke, msg, strlen(msg), 0);

                    logwrite(ip,port,user,cmd,"FAIL");
                }
            }

            else if(!strcmp(cmd,"LOGOUT")) {

                usersession *s = findsession(usertoken);

                if(!s) {
                    printf("Invalid token used\n");

                    char msg[] = "ERR 401 SID:1026 Invalid Token\n";
                    send(clientconnsocke, msg, strlen(msg), 0);
                    continue;
                }

                if(time(NULL)-s->lastactive > 300) {
                    printf("Session expired for %s\n", s->user);

                    char msg[] = "ERR 401 SID:1026 Session expired\n";
                    send(clientconnsocke, msg, strlen(msg), 0);
                    continue;
                }

                printf("User logged out: %s\n", s->user);

                char msg[] = "OK 200 SID:1026 Logged out\n";
                send(clientconnsocke, msg, strlen(msg), 0);

                logwrite(ip,port,user,cmd,"OK");
            }

            else {
                printf("Unknown command\n");

                char msg[] = "ERR 400 SID:1026 Unknown Command\n";
                send(clientconnsocke, msg, strlen(msg), 0);

                logwrite(ip,port,user,cmd,"ERR");
            }
        }
    }

    close(clientconnsocke);
    exit(0);
}

int main() {

    int serverlistensock, clientconnsocke;
    struct sockaddr_in serveraddr, clientaddr;
    socklen_t addrlen = sizeof(clientaddr);

    serverlistensock = socket(AF_INET, SOCK_STREAM, 0);

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_port = htons(SERVERPORT);

    bind(serverlistensock,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
    listen(serverlistensock,5);

    printf("\nServer running on port %d\n\n", SERVERPORT);

    while(1) {
        clientconnsocke = accept(serverlistensock,
        (struct sockaddr*)&clientaddr,&addrlen);

        char *ip = inet_ntoa(clientaddr.sin_addr);
        int port = ntohs(clientaddr.sin_port);

        if(fork()==0) {
            close(serverlistensock);
            handleclient(clientconnsocke,ip,port);
        } else {
            close(clientconnsocke);
            waitpid(-1,NULL,WNOHANG);
        }
    }
}
