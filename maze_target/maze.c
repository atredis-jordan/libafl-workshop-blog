#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>

// generated maze
#ifdef MAZE1

#include "m1.c"

#elif defined MAZE2

#include "m2.c"

#else

#include "m3.c"

#endif

void render_maze() {
    int yi;
    
    for (yi = 0; ; yi++) {
        printf("%.*s\n", maze_w, &maze[yi * maze_w]);
        if (maze[(yi+1) * maze_w] == '\0') {
            break;
        }
    }
}

void render_maze_pretty() {
    int yi;
    int yoff;
    int xi;
    
    for (yi = 0; ; yi++) {
        yoff = yi * maze_w;

        for (xi = 0; xi < maze_w; xi++) {
            switch (maze[xi + yoff]) {
            case '#':
                fputs("\u2588", stdout);
                break;
            case '@':
                fputs("\u263a", stdout);
                break;
            case '.':
                fputs("\u2027", stdout);
                break;
            default:
                fputc(maze[xi + yoff], stdout);
                break;
            }
        }
        fputs("\n", stdout);

        if (maze[(yi+1) * maze_w] == '\0') {
            break;
        }
    }
}

void lose() {
    puts("You Lose.");
}

struct termios oldattrs;

void reset_terminal(int signal) {
    (void)signal;

    tcsetattr(STDIN_FILENO, TCSANOW, &oldattrs);

    if (signal == SIGINT) {
        lose();
        fflush(stdout);
        exit(0);
    }
}

int main(int argc, char** argv) {
    char c;
    int x;
    int y;
    int xpos = 1;
    int ypos = 1;
    int win = 0;

    struct sigaction sa = {};
    struct termios newattrs;

    int pretty_mode = 0;

    if (argc > 1 && !strcmp(argv[1], "-p")) {
        pretty_mode = !pretty_mode;
    }

    if (pretty_mode) {
        // set up terminal with tcsetattr
        // so we can not echo the typed char, and we can not wait for 'enter' to be pressed
        if (tcgetattr(STDIN_FILENO, &oldattrs)) {
            pretty_mode = 0;
        } else {
            newattrs = oldattrs;
            newattrs.c_lflag &= ~(ICANON | ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &newattrs);
            
            // clear terminal
            fputs("\x1b[2J", stdout);

            // handle signal to put terminal back how we found it
            sa.sa_handler = reset_terminal;
            sigaction(SIGINT, &sa, NULL);
        }
    }

    // game loop
    while (1) {
RENDER:
        // place character
        maze[xpos + (ypos * maze_w)] = '@';

        // display maze
        if (pretty_mode) {
            // reset terminal position
            fputs("\x1b[H", stdout);
            render_maze_pretty();
        } else {
            render_maze();
        }

        if (win) {
            // non-zero means game is over
            break;
        }

        // take input
        // handle w,a,s,d, or the arrow keys
        // ignore others
        while (1) {
            x = xpos;
            y = ypos;

            c = getchar();
            
            switch (c) {
            case -1:
                win = -1;
                goto RENDER;
            case '\n':
                goto RENDER;
            case 'w':
            case 'W':
                y -= 1;
                break;
            case 'a':
            case 'A':
                x -= 1;
                break;
            case 's':
            case 'S':
                y += 1;
                break;
            case 'd':
            case 'D':
                x += 1;
                break;
            case '\x1b':
                if ('\x5b' == getchar()) {
                    switch (getchar()) {
                    case '\x41':
                        y -= 1;
                        break;
                    case '\x44':
                        x -= 1;
                        break;
                    case '\x42':
                        y += 1;
                        break;
                    case '\x43':
                        x += 1;
                        break;
                    }
                }
                break;
            }

            // apply action
            if ((x == xpos && y == ypos) || (maze[x + (y * maze_w)] == '#')) {
                // no change
                continue;
            }

            // move
            maze[xpos + (ypos * maze_w)] = '.';
            xpos = x;
            ypos = y;

            if (xpos == (maze_w - 1) && ypos == (maze_h - 1)) {
                // win!
                win = 1;
                break;
            }

            if (pretty_mode) {
                // pretty mode updates each move
                // otherwise only update on newline
                break;
            }
        }
    }

    // done with maze

    if (pretty_mode) {
        // put the terminal back as we found it
        reset_terminal(0);
    }

    if (win != 1) {
        lose();
    } else {
        puts("You win!");
    }
    fflush(stdout);
    return 0;
}

