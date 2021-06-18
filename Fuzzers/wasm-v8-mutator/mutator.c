#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {

} afl_t;

typedef struct my_mutator {
  afl_t *afl;

  char* base_prefix;
  char* base_postfix;

  int base_size; // including a null byte

  char* post_process_buf;

  int post_process_buf_size; // including a null byte
} my_mutator_t;

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
my_mutator_t *afl_custom_init(afl_t *afl, unsigned int seed) {
  // srand(seed);

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {
    perror("afl_custom_init alloc");
    return NULL;
  }

  data->afl = afl;

  // read base code
  int fd = open("/home/candymate/2021/bugbounty/chrome/fuzz/wasm/base-adder/base.js", O_RDONLY);
  char* base = calloc(0x101, sizeof(char));
  data->base_size = 1; // initial null byte
  if (!base) {
    perror("base code alloc");
    return NULL;
  }
  while (1) {
    int read_cnt = read(fd, &base[data->base_size - 1], 0x100); // read size 0x100
    if (read_cnt == -1) {
      perror("base.js read fail");
      return NULL;
    }
    if (read_cnt < 0x100) {
      data->base_size += read_cnt;
      break;
    }
    data->base_size += read_cnt;
    base = realloc(base, data->base_size + 0x100);
    if (!base) {
      perror("base code realloc");
    return NULL;
    }
  }
  base[data->base_size-1] = '\0';

  char* split_str = strstr(base, "CODE");
  if (split_str == NULL) {
    perror("base.js is invalid");
    return NULL;
  }
  *split_str = '\0';
  data->base_prefix = base;
  data->base_postfix = split_str + 4;
  data->base_size -= 4;

  data->post_process_buf = calloc(0x100, sizeof(char));
  data->post_process_buf_size = 0;
  if (data->post_process_buf == NULL) {
    perror("post process buf alloc");
    return 0;
  }
  data->post_process_buf_size = 0x100;

  return data;
}

/**
 * A post-processing function to use right before AFL writes the test case to
 * disk in order to execute the target.
 *
 * (Optional) If this functionality is not needed, simply don't define this
 * function.
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Buffer containing the test case to be executed
 * @param[in] buf_size Size of the test case
 * @param[out] out_buf Pointer to the buffer containing the test case after
 *     processing. External library should allocate memory for out_buf.
 *     The buf pointer may be reused (up to the given buf_size);
 * @return Size of the output buffer after processing or the needed amount.
 *     A return of 0 indicates an error.
 */
size_t afl_custom_post_process(my_mutator_t *data, uint8_t *buf,
                               size_t buf_size, uint8_t **out_buf) {
  char* code_buf = calloc(0x100, sizeof(char));
  if (code_buf == NULL) {
    perror("code buf alloc");
    return 0;
  }
  int code_buf_size = 0x100;
  int cur_pos = 0;
  for(int i = 0; i < buf_size; i++) {
    if (cur_pos + 4 > code_buf_size) {
      code_buf = realloc(code_buf, code_buf_size + 0x100);
      if (code_buf == NULL) {
        perror("code buf realloc");
        return 0;
      }
      code_buf_size += 0x100;
    }
    if (cur_pos != 0) {
      code_buf[cur_pos++] = ',';
    }
    int digit_len = sprintf(&code_buf[cur_pos], "%d", buf[i]);
    cur_pos += digit_len;
  }

  if (data->post_process_buf_size < cur_pos + data->base_size) {
    data->post_process_buf = realloc(data->post_process_buf, cur_pos + data->base_size);
    if (data->post_process_buf == NULL) {
      perror("post process buf realloc");
      return 0;
    }
    data->post_process_buf_size = cur_pos + data->base_size;
  }
  strcpy(data->post_process_buf, data->base_prefix);
  strncat(data->post_process_buf, code_buf, cur_pos);
  strcat(data->post_process_buf, data->base_postfix);
  free(code_buf);

  *out_buf = data->post_process_buf;
  return cur_pos + data->base_size;
}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {
  free(data->base_prefix); // only prefix is freed
  free(data->post_process_buf);
  free(data);
}