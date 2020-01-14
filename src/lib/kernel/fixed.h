#define Q 15
#define F (1<<Q)
#define FIXED_I2F(n) (n * F)
#define FIXED_F2I_TOWARD_ZERO(x) (x / F)
#define FIXED_F2I_NEAREST(x) ((x) > 0 ? (((x) + F / 2) / F) : (((x) - F / 2 ) / F)) // BUG
#define FIXED_ADD(x, y) (x + y)
#define FIXED_SUB(x, y) (x - y)
#define FIXED_MUL(x, y) ((int)((int64_t) x * y / F))
#define FIXED_DIV(x, y) ((int)((int64_t) x * F / y))

typedef int fixed_point;
