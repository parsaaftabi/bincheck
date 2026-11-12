#include <stdio.h>
#include <string.h>

static int greet(int argc, char **argv) {
    char buf[64];
    const char *name = argc > 1 ? argv[1] : "world";
    strcpy(buf, name);
    return printf("hello %s\n", buf) > 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    return greet(argc, argv);
}
