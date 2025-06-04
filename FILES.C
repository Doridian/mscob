#include <unistd.h>
#include <stdio.h>

extern "C" {

FILE* get_file(const int fileno) {
    switch (fileno) {
        case STDIN_FILENO:
            return stdin;
        case STDOUT_FILENO:
            return stdout;
        case STDERR_FILENO:
            return stderr;
    }

    return nullptr;
}

}
