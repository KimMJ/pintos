#define F (1 << 14)
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))
// x and y denote fixed_point numbers in 17.14 format
// n is an integer

int int_to_fp(int n);
int fp_to_int_round(int x);
int fp_to_int(int x);
int add_fp(int x, int y);
int add_mixed(int x, int n);
int sub_fp(int x, int y);
int sub_mixed(int x, int n);
int mult_fp(int x, int y);
int mult_mixed(int x, int n);
int div_fp(int x, int y);
int div_mixed(int x, int n);

int int_to_fp(int n){
  return n * F;
}
int fp_to_int_round(int x){
  return (x >= 0) ? (x + F/2)/F : (x - F/2)/F ;
}
int fp_to_int(int x){
  return x / F;
}
int add_fp(int x, int y){
  return x + y;
}
int add_mixed(int x, int n){
  return x + (n * F);
}
int sub_fp(int x, int y){
  return x - y;
}
int sub_mixed(int x, int n){
  return x - (n * F);
}
int mult_fp(int x, int y){
  return (int)((long long) x * y / F);
}
int mult_mixed(int x, int n){
  return x * n;
}
int div_fp(int x, int y){
  return (int)((long long) x * F / y);
}
int div_mixed(int x, int n){
  return x / n;
}
