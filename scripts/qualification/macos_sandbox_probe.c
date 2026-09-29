// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// What a confined plugin host can and cannot reach, printed as lines a check can
// read.
//
// This is the positive-and-negative half of the macOS restricted-host
// qualification: a bundle that carries the sandbox entitlement has to be confined
// to its own container, and "confined" is only meaningful if the operations it
// must not perform actually fail. Each line is `PROBE <name>=<outcome>`, and the
// script that runs this decides pass or fail from the outcomes rather than from
// this program's exit status, so a probe that fails to run fails loudly.
//
// The paths it is given are the *direct* parent's: the real home directory, and a
// library outside the container. Handing those to the probe is how the denial is
// aimed at something that exists — an operation that fails because the path is
// wrong proves nothing.

#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static void line(const char *name, const char *outcome) {
    printf("PROBE %s=%s\n", name, outcome);
    fflush(stdout);
}

static void attempt_write(const char *name, const char *path) {
    FILE *file = fopen(path, "w");
    if (file) {
        fputs("written\n", file);
        fclose(file);
        char outcome[512];
        snprintf(outcome, sizeof(outcome), "allowed");
        line(name, outcome);
        return;
    }
    char outcome[512];
    snprintf(outcome, sizeof(outcome), "denied:%d", errno);
    line(name, outcome);
}

static void attempt_read(const char *name, const char *path) {
    FILE *file = fopen(path, "r");
    if (file) {
        char buffer[64];
        size_t read_bytes = fread(buffer, 1, sizeof(buffer), file);
        fclose(file);
        char outcome[512];
        snprintf(outcome, sizeof(outcome), "allowed:%zu", read_bytes);
        line(name, outcome);
        return;
    }
    char outcome[512];
    snprintf(outcome, sizeof(outcome), "denied:%d", errno);
    line(name, outcome);
}

static void attempt_connect(const char *name) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        char outcome[512];
        snprintf(outcome, sizeof(outcome), "error:%d", errno);
        line(name, outcome);
        return;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(443);
    // A public address rather than a name: resolution is itself a network
    // operation, and this probe is about the socket the sandbox refuses to open.
    address.sin_addr.s_addr = htonl(0x01010101); // 1.1.1.1
    int connected = connect(socket_fd, (struct sockaddr *)&address, sizeof(address));
    int saved_errno = errno;
    close(socket_fd);
    char outcome[512];
    if (connected == 0) {
        snprintf(outcome, sizeof(outcome), "allowed");
    } else {
        snprintf(outcome, sizeof(outcome), "denied:%d", saved_errno);
    }
    line(name, outcome);
}

static void attempt_dlopen(const char *name, const char *path) {
    void *handle = dlopen(path, RTLD_NOW);
    if (handle) {
        dlclose(handle);
        line(name, "allowed");
        return;
    }
    char outcome[512];
    snprintf(outcome, sizeof(outcome), "denied");
    line(name, outcome);
}

// Create a path one component at a time, the way a host staging its own
// directories has to: the container starts with the standard skeleton, and
// "Application Support/NeMo Relay" does not exist until something makes it.
static int create_below(const char *base, const char *relative) {
    char path[4096];
    snprintf(path, sizeof(path), "%s", base);
    char remainder[4096];
    snprintf(remainder, sizeof(remainder), "%s", relative);
    char *cursor = remainder;
    while (cursor != NULL && *cursor != '\0') {
        char *separator = strchr(cursor, '/');
        if (separator != NULL) {
            *separator = '\0';
        }
        if (*cursor != '\0') {
            size_t length = strlen(path);
            snprintf(path + length, sizeof(path) - length, "/%s", cursor);
            if (mkdir(path, 0700) != 0 && errno != EEXIST) {
                return errno;
            }
        }
        cursor = separator == NULL ? NULL : separator + 1;
    }
    return 0;
}

static void attempt_create_directory(const char *name, const char *base, const char *relative) {
    int failure = create_below(base, relative);
    if (failure == 0) {
        line(name, "allowed");
        return;
    }
    char outcome[512];
    snprintf(outcome, sizeof(outcome), "denied:%d", failure);
    line(name, outcome);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: probe <real-home> <external-library>\n");
        return 2;
    }
    const char *home = getenv("HOME");
    if (home == NULL) {
        line("home_set", "unset");
        return 0;
    }
    line("home_set", "set");

    // The container the sandbox hands this process, and the two directories the
    // restricted host stages into. They have to be writable, or the confinement
    // is not usable rather than merely strict.
    // A file in the container itself, not the container path: writing "to"
    // a directory is an error the sandbox is not the cause of.
    char container_file[4096];
    snprintf(container_file, sizeof(container_file), "%s/nemo-relay-probe.txt", home);
    attempt_write("write_container", container_file);
    char support[4096];
    snprintf(
        support,
        sizeof(support),
        "%s/Library/Application Support/NeMo Relay/probe.txt",
        home
    );
    attempt_create_directory("create_app_support", home, "Library/Application Support/NeMo Relay");
    attempt_write("write_app_support", support);

    // What it must not reach: shared temporary storage, the account's real home,
    // and — as the plugin path is delivered by transfer rather than by path — a
    // library that lives outside the container. The home cases read and write a
    // file the parent can see, and the read comes back as ENOENT rather than
    // EPERM: outside its container the sandbox hides the path rather than
    // refusing the call, so the check compares outcomes and not errnos.
    attempt_write("write_tmp", "/private/tmp/nemo-relay-sandbox-probe.txt");
    char outside_read[4096];
    snprintf(outside_read, sizeof(outside_read), "%s/.CFUserTextEncoding", argv[1]);
    attempt_read("read_real_home", outside_read);
    char outside_write[4096];
    snprintf(outside_write, sizeof(outside_write), "%s/nemo-relay-sandbox-probe.txt", argv[1]);
    attempt_write("write_real_home", outside_write);
    attempt_connect("connect_outbound");
    attempt_dlopen("dlopen_external", argv[2]);
    return 0;
}
