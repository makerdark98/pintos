#ifndef __LIB_FIX_POINT_H
#define __LIB_FIX_POINT_H
#include <stdint.h>

#define FXPT_F 16384

typedef int fxpt_t;

fxpt_t fxpt_to_fxpt (int a);
int fxpt_to_int_floor (fxpt_t a);
int fxpt_to_int_round (fxpt_t a);
fxpt_t fxpt_add_int (fxpt_t a, int b);
fxpt_t fxpt_add_fx (fxpt_t a, fxpt_t b);
fxpt_t fxpt_sub_int (fxpt_t a, int b);
fxpt_t fxpt_sub_fx (fxpt_t a, fxpt_t b);
fxpt_t fxpt_mul_int (fxpt_t a, int b);
fxpt_t fxpt_mul_fx (fxpt_t a, fxpt_t b);
fxpt_t fxpt_div_int (fxpt_t a, int b);
fxpt_t fxpt_div_fxpt (fxpt_t a, fxpt_t b);

#endif /* lib/fixed_point.h */
