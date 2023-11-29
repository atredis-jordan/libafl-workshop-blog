#include <poll.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define xstr(x) str(x)
#define str(x)  #x

#define USAGE       "./chat <address> [<port>]"
#define PORT        "8088"

#define MAXDATA     0xc000
#define MAXUSER     11
#define MAXUSTR     xstr(MAXUSER)
#define MAXTIMESZ   (32 + 4)

#define MSG_HI      0
#define MSG_HEY     1
#define MSG_TXT     2
#define MSG_RENAME  3
#define MSG_ART     4
#define MSG_ME      5
#define MSG_PING    6
#define MSG_PONG    7

#define CMD_ME      "/me "
#define CMD_RENAME  "/nick "
#define CMD_PING    "/ping"
#define CMD_ART     "/art"
#define CMD_QUIT    "/quit"
#define CMD_HELP    "/help"

#define HELP_MSG    "-- Commands available: /me <msg>, /nick <new nickname>, /ping, /art, /quit, /help --"

#pragma pack(push, 1)

struct chatmsghdr {
    uint32_t usrid;
    uint16_t msgtype;
    uint16_t datalen;
};

struct chatmsg_art {
    uint16_t h;
    uint16_t w;
    char data[0];
};

struct chatmsg {
    struct chatmsghdr hdr;
    union {
        char data[0];
        struct chatmsg_art art;
    };
};

#pragma pack(pop)

struct userinfo {
    uint32_t usrid;
    struct userinfo* nxt;
    char nick[MAXUSER+1];
};

uint32_t g_usrid;
struct userinfo* g_users = NULL;


int recv_msg(int s, struct chatmsg** msg) {
    // receive first the header, then the rest of the message
    ssize_t amt;
    size_t sz;
    struct chatmsghdr hdr;

    amt = recv(s, &hdr, sizeof(hdr), MSG_WAITALL);

    if (amt < 0) {
        printf("-- Error when recving message header: %s --\n", strerror(errno));
        return -1;
    }

    if (amt != sizeof(hdr)) {
        // bad bad not good
        printf("-- Received message fragment --\n");
        return -1;
    }

    sz = sizeof(hdr) + (size_t)hdr.datalen;

    *msg = (struct chatmsg*)realloc(*msg, sz);
    if (!msg) {
        printf("-- OOM --\n");
        return -1;
    }

    (*msg)->hdr = hdr;

    sz = 0;
    while (sz != hdr.datalen) {
        amt = recv(s, (*msg)->data, ((size_t)hdr.datalen) - sz, MSG_WAITALL);

        if (amt < 0) {
            printf("-- Error when recving message data: %s --", strerror(errno));
            return -1;
        }

        sz += amt;

        // here we could be in trouble or get off message alignment :(
    }

    return 0;
}

void printuser(uint32_t id) {
    struct userinfo* ui = NULL;
    // if the user id has a nickname, print that

    for (ui = g_users; ui != NULL; ui = ui->nxt) {
        if (ui->usrid == id) {
            if (ui->nick[0] == '\0') {
                break;
            }
            printf("%" MAXUSTR "s", ui->nick);
            return;
        }
    }

    // otherwise print the id
    printf("%" MAXUSTR "d", id);
}

void cleantxt(char* data, size_t datalen) {
    size_t i;

    if (data[datalen - 1] != '\0') {
        data[datalen - 1] = '\0';
    }
    
    i = 2;
    while (i > 0) {
        if (data[datalen - i] == '\n') {
            data[datalen - i] = '\0';
        } else {
            break;
        }
    }
}

int send_msg(int s, uint16_t msgtype, const void* data, size_t datalen) {
    size_t msgsz;
    ssize_t amt;
    struct chatmsg* msg = NULL;

    if (datalen > MAXDATA) {
        printf("-- Message too large --\n");
        return -1;
    }

    msgsz = datalen + sizeof(struct chatmsghdr);
    msg = (struct chatmsg*)malloc(msgsz);
    if (msg == NULL) {
        printf("-- OOM --\n");
        return -1;
    }

    msg->hdr.usrid = g_usrid;
    msg->hdr.msgtype = msgtype;
    msg->hdr.datalen = (uint16_t)datalen;

    if (datalen) {
        memcpy(msg->data, data, datalen);
    }

    amt = send(s, msg, msgsz, 0);

    free(msg);

    if (amt < 0) {
        printf("-- Error sending message: %s --\n", strerror(errno));
        return -1;
    }

    return 0;
}

int send_pong(int s, char* data, size_t datalen) {
    char* outdata;
    char* outdataf;
    time_t now;
    int amt;
    int i;

    outdataf = (char*)malloc(datalen + MAXTIMESZ);
    outdata = (char*)malloc(datalen + MAXTIMESZ);

    outdataf[0] = '\0';
    strcat(outdataf, "@ %s: ");
    strcat(outdataf, data);

    now = time(NULL);
    amt = sprintf(outdata, outdataf, ctime(&now));

    // remove the newline ctime gives
    for (i = 0; i < amt; i++) {
        if (outdata[i] == '\n') {
            outdata[i] = ' ';
        }
    }

    if (amt < 0) {
        printf("-- Error replying to a ping! --\n");
        i = -1;
        goto END;
    }

    i = send_msg(s, MSG_PONG, outdata, (size_t)amt + 1);

END:
    free(outdataf);
    free(outdata);

    return i;
}

int print_art(struct chatmsg_art* art) {
    int i;
    int leftpad;
    struct winsize w = {};
    leftpad = 3;

    if (!ioctl(STDIN_FILENO, TIOCGWINSZ, &w)) {
        leftpad = (w.ws_col - art->w) / 2;
    }

    for (i = 0; i < art->h; i++) {
        printf("%*s%.*s\n", leftpad, "", art->w, &art->data[(i * art->w)]);
    }

    return 0;
}

int get_send_art(int s) {
    // first collect all the art until they hit enter twice
    printf("-- Make your Art, press Enter twice to finish --\n");

    int i = 0;
    int w = 0;
    int h = 0;
    int lw = 0;

    char* line = NULL;
    size_t linesz = 0;
    
    int cap = 16;
    char** lines = malloc(sizeof(line) * cap);

    while (1) {
        lw = getline(&line, &linesz, stdin);

        if (lw <= 0 || line[0] == '\n') {
            break;
        }

        if (line[lw-1] == '\n') {
            line[lw-1] = '\0';
            lw -= 1;
        }

        if (lw > w) {
            w = lw;
        }

        h += 1;

        if (h > cap) {
            cap = cap * 2;
            lines = realloc(lines, sizeof(line) * cap);
        }

        lines[h - 1] = line;
        line = NULL;
        linesz = 0;
    }

    // okay now box it all up

    size_t datalen = (w*h) + sizeof(struct chatmsg_art);
    struct chatmsg_art* art = (struct chatmsg_art*)malloc(datalen);
    char* box = art->data;
    art->w = w;
    art->h = h;

    for (i = 0; i < h; i++) {
        line = lines[i];
        lw = strlen(line);

        memcpy(&box[(i*w)], line, lw);
        memset(&box[(i*w) + lw], ' ', w - lw);

        free(line);
    }
    free(lines);

    i = send_msg(s, MSG_ART, (void*)art, datalen);

    free(art);

    return i;
}

__attribute__ ((noinline))
int handle_msg(int s, struct chatmsg* msg) {
    struct userinfo* ui = NULL;
    size_t datalen = msg->hdr.datalen;

    switch (msg->hdr.msgtype) {
    case MSG_HI:
    case MSG_HEY:
        // record user, make entry if new
        if (g_users == NULL) {
            // first user
            g_users = (struct userinfo*)malloc(sizeof(*g_users));

            g_users->nxt = NULL;
            g_users->nick[0] = '\0';
            g_users->usrid = msg->hdr.usrid;
        } else {
            for (ui = g_users; ; ui = ui->nxt) {
                if (ui->usrid == msg->hdr.usrid) {
                    // already exists
                    return 0;
                }

                if (ui->nxt == NULL) {
                    // put new on the end
                    ui->nxt = (struct userinfo*)malloc(sizeof(*g_users));
                    ui = ui->nxt;

                    ui->nxt = NULL;
                    ui->nick[0] = '\0';
                    ui->usrid = msg->hdr.usrid;
                    break;
                }
            }
        }

        if (msg->hdr.msgtype == MSG_HI) {
            printf("-- User %d Joined --\n", msg->hdr.usrid);
            // send a HEY so they know about us
            send_msg(s, MSG_HEY, NULL, 0);
        } 
        break;
    case MSG_TXT:
        cleantxt(msg->data, datalen);
        printuser(msg->hdr.usrid);
        printf(" : %s\n", msg->data);
        break;
    case MSG_RENAME:
        // in the entry, rename the user
        cleantxt(msg->data, datalen);

        for (ui = g_users; ui != NULL; ui = ui->nxt) {
            if (ui->usrid == msg->hdr.usrid) {
                break;
            }
        }

        strncpy(ui->nick, msg->data, MAXUSER);

        printf("-- User %d is now %s --\n", ui->usrid, ui->nick);
        break;
    case MSG_ART:
        // center and print it nice
        printuser(msg->hdr.usrid);
        printf(" sent art :\n");
        print_art(&msg->art);
        break;
    case MSG_ME:
        cleantxt(msg->data, datalen);
        printuser(msg->hdr.usrid);
        printf("%s\n", msg->data);
        break;
    case MSG_PING:
        cleantxt(msg->data, datalen);
        printf("-- Ping from ");
        printuser(msg->hdr.usrid);
        if (datalen) {
            printf(": %s --\n", msg->data);
        } else {
            printf("--\n");
        }

        // respond with a pong with the time
        send_pong(s, msg->data, datalen);
        break;
    case MSG_PONG:
        cleantxt(msg->data, datalen);
        printf("-- Ping response from ");
        printuser(msg->hdr.usrid);
        printf(": %s --\n", msg->data);
        break;
    }

    return 0;
}

int handle_user_command(int s, const char* line) {
    uint16_t datalen;

    uint16_t msgtype = MSG_TXT;

    // handle special commands
    if (*line == '/') {
        if (!memcmp(CMD_ME, line, sizeof(CMD_ME) - 1)) {
            msgtype = MSG_ME;
            line = line + (sizeof(CMD_ME) - 1);
        }
        else if (!memcmp(CMD_RENAME, line, sizeof(CMD_RENAME) - 1)) {
            msgtype = MSG_RENAME;
            line = line + (sizeof(CMD_RENAME) - 1);
        }
        else if (!memcmp(CMD_PING, line, sizeof(CMD_PING) - 1)) {
            line = line + (sizeof(CMD_PING) -1);
            if (*line == ' ') {
                line++;
                // optional line data
                return send_msg(s, MSG_PING, line, strlen(line) + 1);
            } else {
                return send_msg(s, MSG_PING, NULL, 0);
            }
        }
        else if (!memcmp(CMD_ART, line, sizeof(CMD_ART) - 1)) {
            //TODO prompt user for art, double enter at the end
            // send data over as block with w/h info

            get_send_art(s);

            return 0;
        }
        else if (!memcmp(CMD_QUIT, line, sizeof(CMD_QUIT) - 1)) {
            return 1;
        }
        else if (!memcmp(CMD_HELP, line, sizeof(CMD_QUIT) - 1)) {
            puts(HELP_MSG);
            return 0;
        }
        else {
            // unknown command
            return -1;
        }
    }


    // handles fall through cases where data is null terminated str
    datalen = strlen(line) + 1;
    return send_msg(s, msgtype, line, datalen);
}

int init_chat() {
    srandom(time(NULL));
    g_usrid = (uint32_t)random();

    return 0;
}

int do_chat(int s) {
    int res = -1;
    struct pollfd fds[2] = {};
    char* line = NULL;
    size_t linesz = 0;
    struct chatmsg* msg = NULL;

    // init global state
    if (init_chat()) {
        printf("-- Error when Initializing --\n");
        goto END;
    }

    send_msg(s, MSG_HI, NULL, 0);

    printf("-- Connected --\n");


    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = s;
    fds[1].events = POLLIN;

    while (1) {
        res = poll(fds, 2, -1);

        if (res == -1) {
            printf("-- Error when polling: %s --", strerror(errno));
            goto END;
        }

        if (fds[0].revents & (POLLERR | POLLHUP)) {
            printf("-- Closing connection --\n");
            res = 0;
            goto END;
        }
        else if (fds[0].revents & POLLIN) {
            // read a user command
            getline(&line, &linesz, stdin);
            if (*line == '\n') {
                continue;
            }
            res = handle_user_command(s, line);
            if (res == 1) {
                printf("-- Quitting --\n");
                res = 0;
                goto END;
            }
        }

        if (fds[1].revents & (POLLERR | POLLHUP)) {
            printf("-- Connection to server closed --\n");
            res = 0;
            goto END;
        }
        else if (fds[1].revents & POLLIN) {
            // incoming message
            if (recv_msg(s, &msg)) {
                printf("-- Error receiving message --\n");
                res = -1;
                goto END;
            }
            handle_msg(s, msg);
        }
    }

END:
    free(msg);
    free(line);

    return res;
}

int main(int argc, char** argv) {
    struct addrinfo* addr_res;
    struct addrinfo* rc;
    struct addrinfo hints = {};

    const char* service = PORT;

    int res;
    int s = -1;

    if (argc < 2) {
        printf(USAGE);
        exit(-1);
    }

    if (argc > 2) {
        service = argv[2];
    }

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    res = getaddrinfo(argv[1], service, &hints, &addr_res);
    if (res) {
        printf("Error getting address for %s %s: %s\n", argv[1], service, gai_strerror(res));
        exit(-1);
    }

    for (rc = addr_res; rc != NULL; rc = rc->ai_next) {
        // try to connect to one of them
        s = socket(rc->ai_family, rc->ai_socktype, rc->ai_protocol);

        if (s == -1) {
            continue;
        }

        if (connect(s, rc->ai_addr, rc->ai_addrlen) != -1) {
            // success
            break;
        }

        close(s);
        s = -1;
    }

    freeaddrinfo(addr_res);

    if (s == -1) {
        // could not connect
        printf("Error connecting to %s %s\n", argv[1], service);
        exit(-1);
    }

    // handle chat session
    do_chat(s);

    close(s);

    printf("Done\n");

    return 0;
}