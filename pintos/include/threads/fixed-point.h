#include <stdint.h>

/* 17.14 고정 소수점 연산용 */

typedef int32_t fp;
// Suppose that we are using a p.q fixed-point format, and let f = 2^q
#define F (1 << 14)
// Convert n to fixed point
#define int_to_fp(n) ((n)*F)
// Convert x to integer (rounding toward zero)
#define fp_to_int(x) ((x) / F)
// Convert x to integer (rounding to nearest)
#define fp_to_int_round(x) (((x) >= 0) ? (((x) + F / 2) / F) : (((x)-F / 2) / F))
// Add x and y
#define add_fp(x, y) ((x) + (y))
// Subtract y from x
#define sub_fp(x, y) ((x) - (y))
// Add x and n
#define add_fp_int(x, n) ((x) + (n) * (F))
// Subtract n from x
#define sub_fp_int(x, n) ((x) - (n) * (F))
// Multiply x by y
#define mult_fp(x, y) (((int64_t)(x)) * (y) / (F))
// Divide x by y
#define div_fp(x, y) (((int64_t)(x)) * (F) / (y))
// Multiply x by n
#define mult_fp_int(x, n) ((x) * (n))
// Divide x by n
#define div_fp_int(x, n) ((x) / (n))