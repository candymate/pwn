#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct {

} afl_t;

typedef struct my_mutator {
  afl_t *afl;

  char* base_prefix;
  char* base_postfix;

  int base_size;

  char* post_process_buf;

  int post_process_buf_size;
} my_mutator_t;

extern my_mutator_t *afl_custom_init(afl_t *afl, unsigned int seed);
extern size_t afl_custom_post_process(my_mutator_t *data, uint8_t *buf,
                               size_t buf_size, uint8_t **out_buf);
extern void afl_custom_deinit(my_mutator_t *data);

int main(int argc, char* argv[]) {
  my_mutator_t *data = afl_custom_init(NULL, 0x31337);
  uint8_t testcase[0x108];
  uint8_t *out_buf = NULL;

  // fill testcase
  for(int i = 0; i < 0x100; i++) {
    testcase[i] = i;
  }
  testcase[0x100] = 0;
  testcase[0x101] = 1;
  testcase[0x102] = 2;
  testcase[0x103] = 3;
  testcase[0x104] = 4;
  testcase[0x105] = 5;
  testcase[0x106] = 6;
  testcase[0x107] = 7;
  

  int result = afl_custom_post_process(data, testcase, 0x108, &out_buf);
  printf("result : %d\n", result);
  printf("outbuf : \n%s\n", out_buf);
  printf("outbuf length : %ld\n", strlen(out_buf));

  result = afl_custom_post_process(data, testcase, 0x80, &out_buf);
  printf("result : %d\n", result);
  printf("outbuf : \n%s\n", out_buf);
  printf("outbuf length : %ld\n", strlen(out_buf));

  result = afl_custom_post_process(data, testcase, 0xa0, &out_buf);
  printf("result : %d\n", result);
  printf("outbuf : \n%s\n", out_buf);
  printf("outbuf length : %ld\n", strlen(out_buf));

  afl_custom_deinit(data);
  return 0;
}