typedef int fixed_point_t;

fixed_point_t int_to_fixed_point (int);
int fixed_point_to_int_round_zero (fixed_point_t);
int fixed_point_to_int_round_nearest (fixed_point_t);

fixed_point_t fixed_point_add (fixed_point_t, fixed_point_t);
fixed_point_t fixed_point_mul (fixed_point_t, fixed_point_t);
fixed_point_t fixed_point_div (fixed_point_t, fixed_point_t);
fixed_point_t fixed_point_add_to_int (fixed_point_t, int);
fixed_point_t fixed_point_mul_to_int (fixed_point_t, int);
fixed_point_t fixed_point_div_by_int (fixed_point_t, int);
