#ifndef AFL_RAND_H
#define AFL_RAND_H

#include <fcntl.h>
#include "types.h"
#include "common.h"
#include "xxh3.h"

typedef struct afl_rand {

  u32  rand_cnt;                                                                            /* Random number counter*/
  u64  rand_seed[4];
  s32  dev_urandom_fd;
  s64  init_seed;
  bool fixed_seed;

} afl_rand_t;

static inline u64 afl_rand_rotl(const u64 x, int k) {

  return (x << k) | (x >> (64 - k));

}

static inline void afl_rand_seed(afl_rand_t *rnd, s64 init_seed) {

  rnd->init_seed = init_seed;
  rnd->fixed_seed = true;
  rnd->rand_seed[0] = XXH64((u8 *)&rnd->init_seed, sizeof(rnd->init_seed), HASH_CONST);
  rnd->rand_seed[1] = rnd->rand_seed[0] ^ 0x1234567890abcdef;
  rnd->rand_seed[2] = rnd->rand_seed[0] & 0x0123456789abcdef;
  rnd->rand_seed[3] = rnd->rand_seed[0] | 0x01abcde43f567908;

}

/* get the next random number */
static inline u64 afl_rand_next(afl_rand_t *rnd) {

  const uint64_t result = afl_rand_rotl(rnd->rand_seed[0] + rnd->rand_seed[3], 23) + rnd->rand_seed[0];

  const uint64_t t = rnd->rand_seed[1] << 17;

  rnd->rand_seed[2] ^= rnd->rand_seed[0];
  rnd->rand_seed[3] ^= rnd->rand_seed[1];
  rnd->rand_seed[1] ^= rnd->rand_seed[2];
  rnd->rand_seed[0] ^= rnd->rand_seed[3];

  rnd->rand_seed[2] ^= t;

  rnd->rand_seed[3] = afl_rand_rotl(rnd->rand_seed[3], 45);

  return result;

}

/* get a random int below the given int (exclusive) */
static inline u64 afl_rand_below(afl_rand_t *rnd, u64 limit) {

  if (limit <= 1) { return 0; }

  /* The boundary not being necessarily a power of 2,
     we need to ensure the result uniformity. */
  if (unlikely(!rnd->rand_cnt--) && likely(!rnd->fixed_seed)) {

    int read_len = read(rnd->dev_urandom_fd, &rnd->rand_seed, sizeof(rnd->rand_seed));
    (void)read_len;
    rnd->rand_cnt = (RESEED_RNG / 2) + (rnd->rand_seed[1] % RESEED_RNG);

  }

  /* Modulo is biased - we don't want our fuzzing to be biased so let's do it
  right. See
  https://stackoverflow.com/questions/10984974/why-do-people-say-there-is-modulo-bias-when-using-a-random-number-generator
  */

  u64 unbiased_rnd;
  do {

    unbiased_rnd = afl_rand_next(rnd);

  } while (unlikely(unbiased_rnd >= (UINT64_MAX - (UINT64_MAX % limit))));

  return unbiased_rnd % limit;

}

/* A random number between min and max, both inclusive */
static inline u64 afl_rand_between(afl_rand_t *rand, u64 min, u64 max) {

  return min + afl_rand_below(rand, max - min + 1);

}

/* initialize with a fixed seed (for reproducability) */
static inline afl_ret_t afl_rand_init_fixed_seed(afl_rand_t *rnd, s64 init_seed) {

  memset(rnd, 0, sizeof(afl_rand_t));
  afl_rand_seed(rnd, init_seed);
  return AFL_RET_SUCCESS;

}

/* initialize feeded by urandom */
static inline afl_ret_t afl_rand_init(afl_rand_t *rnd) {

  memset(rnd, 0, sizeof(afl_rand_t));
  rnd->dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (!rnd->dev_urandom_fd) { return AFL_RET_FILE_OPEN_ERROR; }
  rnd->fixed_seed = false;
  /* do one call to rand_below to seed the rng */
  afl_rand_below(rnd, 1);
  return AFL_RET_SUCCESS;

}

static inline void afl_rand_deinit(afl_rand_t *rnd) {

  if (rnd->dev_urandom_fd) { close(rnd->dev_urandom_fd); }

}

AFL_NEW_AND_DELETE_FOR(afl_rand);

#endif                                                                                                /* AFL_RAND_H */

