// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "aes-whitebox/aunit.h"


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>

#include "aes-whitebox/aes.h"
#include "aes-whitebox/aes_whitebox.h"

static void err_quit(const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  strcat(buf, "\n");
  fputs(buf, stderr);
  fflush(stderr);
  va_end(ap);

  exit(1);
}


static void read_hex(const char *in, uint8_t* v, size_t size, const char* param_name) {
  if (strlen(in) != 32) {
    err_quit("Invalid param %s (got %d, expected %d)",
        param_name, strlen(in), size << 1);
  }
  for (size_t i = 0; i < size; i++) {
    sscanf(in + i * 2, "%2hhx", v + i);
  }
}

int main(int argc, char* argv[]) {
    uint8_t buffer[2*16];
    uint8_t pt[16] = {0};

    read_hex(argv[1], buffer, 2*16, "buffer");
    aes_whitebox_encrypt_cfb(buffer, pt, 16, buffer);

    for (int i = 0; i<16; i++){
        printf("%02x", buffer[i]);
    }
    printf("\n");

}
