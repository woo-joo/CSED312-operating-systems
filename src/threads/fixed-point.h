#include <stdint.h>

/* # of fractional bits. */
#define f 14

/* Converts integer N to fixed point number. */
#define int_to_fixed(n) (n << f)

/* Converts fixed point number X to integer
   with round toward zero. */
#define fixed_to_int_round_to_zero(x) (x >> f)

/* Converts fixed point number X to integer
   with round to nearest. */
#define fixed_to_int(x) (x >= 0) ? ((x + (1 << (f - 1))) >> f) \
                                 : ((x - (1 << (f - 1))) >> f)

/* Adds two fixed point numbers X and Y. */
#define fixed_plus_fixed(x, y) (x + y)

/* Adds fixed point X and integer N. */
#define fixed_plus_int(x, n) (x + (n << f))

/* Subtracts fixed point number Y from
   fixed point number X. */
#define fixed_minus_fixed(x, y) (x - y)

/* Subtracts integer N from fixed point
   number X. */
#define fixed_minus_int(x, n) (x - (n << f))

/* Multiplies two fixed point numbers X and Y. */
#define fixed_mul_fixed(x, y) ((((int64_t)x) * y) >> f)

/* Multiplies fixed point number X and integer N. */
#define fixed_mul_int(x, n) (x * n)

/* Divides fixed point number X by fixed point
   number Y. */
#define fixed_div_fixed(x, y) ((((int64_t)x) << f) / y)

/* Divides fixed point number X by integer N. */
#define fixed_div_int(x, n) (x / n)
