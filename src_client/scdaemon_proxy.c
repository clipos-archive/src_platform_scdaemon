// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>



#define DEFAULT_SOCKET_SERVER_PATH "/var/run/scdaemon/socket"


typedef struct {
  int fd_in;
  FILE *file_out;
} copy_out_t;


void*
copy_out(void *rawtocopy) {
  copy_out_t *tocopy = rawtocopy;
  char c;
    
  while((recv(tocopy->fd_in, &c, 1, 0)) == 1) {
    if(fputc(c, tocopy->file_out) == EOF)
      goto copy_out_leave;
    fflush(tocopy->file_out);
  }

 copy_out_leave:
  (void)close(tocopy->fd_in);
  (void)fclose(tocopy->file_out);

  (void)kill(getpid(), SIGUSR1);

  return NULL;
}




typedef struct {
  FILE *file_in;
  int fd_out;
} copy_in_t;


void*
copy_in(void *rawtocopy) {
  copy_in_t *tocopy = rawtocopy;
  int rchar;

  while((rchar = fgetc(tocopy->file_in)) != EOF) {
    char c = rchar;
    if(send(tocopy->fd_out, &c, 1, 0) != 1)
      goto copy_in_leave;
  }

 copy_in_leave:
  (void)close(tocopy->fd_out);
  (void)fclose(tocopy->file_in);
  
  (void)kill(getpid(), SIGUSR1);

  return NULL;
}



void
signal_usr1_handler(int signal) {
}

int
main(int argc,
     char **argv) {

  int err = 0;
  int socket_fd = 0;
  struct sockaddr_un sockad;
  pthread_t other;
  pthread_attr_t attr;
  copy_out_t copy_out_data;
  copy_in_t copy_in_data;
  struct sigaction signal_usr1;


  signal_usr1.sa_handler = signal_usr1_handler;
  signal_usr1.sa_flags = 0;
  sigemptyset(&signal_usr1.sa_mask);
  
  if(sigaction(SIGUSR1, &signal_usr1, NULL)) {
    fprintf(stderr, "failed to set signal actions : %s", strerror(errno));
    return errno;
  }

  
  if((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    err = errno;
    goto main_leave;
  }

  sockad.sun_family = AF_UNIX;
  strncpy(sockad.sun_path, DEFAULT_SOCKET_SERVER_PATH, (sizeof(sockad.sun_path) - 1));

  if(connect(socket_fd, (struct sockaddr *)&sockad, sizeof(sockad))) {
    err = errno;
    goto main_leave;
  }

  if(pthread_attr_init(&attr))
    goto main_leave;

  copy_out_data.fd_in = socket_fd;
  copy_out_data.file_out = stdout;

  if(pthread_create(&other, &attr, copy_out, &copy_out_data)) {
    err = errno;
    goto main_leave;
  }

  copy_in_data.fd_out = socket_fd;
  copy_in_data.file_in = stdin;

  (void)copy_in(&copy_in_data);

  if(socket_fd) {
    (void)close(socket_fd);
  }

 main_leave:

  return err;
}
