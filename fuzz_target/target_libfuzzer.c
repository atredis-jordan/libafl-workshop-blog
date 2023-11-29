#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#ifdef NO_VERB
#define LOG(fmt, ...) (void)fmt
#else
#define LOG(fmt, ...) fprintf(stderr, "  DBG: " fmt "\n", ## __VA_ARGS__)
#endif

#include "t.c"

int valid_uid(const char* uid) {
    size_t i;
    char c;

    // check that the uid is at least UID_LEN long
    // check that the uid contains only valid UID characters
    // A-Z or a-z or - or _

    for (i = 0; i < UID_LEN; i++) {
        c = uid[i];

        if (c == '\0' || c == '}') {
            LOG("UID too short!");
            return -1;
        }

        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' || c == '_'))) {
            LOG("Invalid character");
            return -1;
        }
    }

    return 0;
}

char* str_append(char* out, size_t* outend, size_t* outsz, const char* in, size_t amt)
{
    size_t newsz = (*outend + amt);

    if (newsz >= *outsz) {
        LOG("Growing allocation from %zu to contain %zu", *outsz, newsz);
        while (newsz >= *outsz) {
            *outsz = *outsz << 1;
        }

        out = realloc(out, *outsz + 1);
    }

    memcpy(&out[*outend], in, amt);

    *outend = newsz;
    out[*outend] = '\0';

    return out;
}

char* process_line(const char* in) {
    const char* cursor = in;
    const char* next = in;
    const char* name = NULL;
    char* out = NULL;
    size_t outsz = 0;
    size_t outend = 0;

    outsz = strlen(in) + 1;
    out = malloc(outsz + 1);

    for (cursor=in; *cursor != '\0'; cursor++) {
        // find {{...}}
        if (cursor[0] == '{' && cursor[1] == '{') {
            if (valid_uid(&cursor[2])) {
                LOG("Invalid User Identifier");
                goto ERR;
            }

            LOG("Found UID signifier");
            // first copy from next to cursor
            out = str_append(out, &outend, &outsz, next, cursor - next);

            // then copy in the name
            name = uid_to_name(&cursor[2]);
            if (name == NULL) {
                LOG("Bad User Identifier");
                goto ERR;
            }

            out = str_append(out, &outend, &outsz, name, strlen(name));

            // then move cursor and next to the end '}}' or '\0'
            while (cursor[0] != '\0' && !(cursor[0] == '}' && cursor[1] == '}')) {
                cursor++;
            }

            if (cursor[0] == '\0') {
                next = cursor;
                break;
            } else {
                next = &cursor[2];
            }
        }
    }

    // copy out rest
    out = str_append(out, &outend, &outsz, next, cursor - next);

    return out;
ERR:
    free(out);
    return NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* input_end;
    char* rendered;
    char* line;
    char* nextline;
    char swap;

    // this is quite similar to the AFL persistent mode, but in the same process as the fuzzer instance itself
    // This will loop in process, with the fuzz client logic all in process as well
    // this increases speed a ton
    // but if global state can change between runs, it can cause instability or false results

    // the original uses getline
    // so we need to cut our input up into sequences ending in \n
    // or end of input

    // it would be simpler here to just fuzz uid_to_name after a valid_uid check
    // and then convert our solutions to templated files

    if (size < 16) {
        return 0;
    }

    line = (char*)data;
    input_end = line + size;
    nextline = NULL;

    while (line != NULL) {

        nextline = line;

        // go swap in a null after the \n
        while (1) {
            if ((nextline+1) >= input_end) {
                // no nextline
                nextline = NULL;
                // but technically we need the null to be in bounds
                // so we null terminate the end
                *(input_end - 1) = '\0';
                break;
            }
            if (*nextline == '\n') {
                nextline = nextline+1;
                swap = *nextline;
                *nextline = '\0';
                break;
            }
            // keep searching
            nextline = nextline + 1;
        }

        rendered = process_line(line);
        if (rendered == NULL) {
            // to make sure our crashes work with the original target
            // we need to break out here
            break;
        }
        LOG("Line = %s", rendered);

        free(rendered);

        if (nextline == NULL) {
            // done with this test case
            break;
        }

        *nextline = swap;
        line = nextline;
    }
    return 0;
}
