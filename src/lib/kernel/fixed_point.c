#include "fixed_point.h"
#include <stdint.h>
#define Q (14)
#define F (1 << Q)

fixed_point_t int_to_fixed_point (int n)
{
  return n * F;
}

int fixed_point_to_int_round_zero (fixed_point_t x)
{
  return x / F;
}

int fixed_point_to_int_round_nearest (fixed_point_t x)
{
  return x > 0 ? (x + F / 2) / F : (x - F / 2) / F;
}

fixed_point_t fixed_point_add (fixed_point_t x, fixed_point_t y)
{
  return x + y;
}

fixed_point_t fixed_point_mul (fixed_point_t x, fixed_point_t y)
{
  return ((int64_t)x) * y / F;
}

fixed_point_t fixed_point_div (fixed_point_t x, fixed_point_t y)
{
  return ((int64_t)x) * F / y;
}

fixed_point_t fixed_point_add_to_int (fixed_point_t x, int n)
{
  return x + n * F;
}
fixed_point_t fixed_point_mul_to_int (fixed_point_t x, int n)
{
  return x * n;
}

fixed_point_t fixed_point_div_by_int (fixed_point_t x, int n)
{
  return x / n;
}
