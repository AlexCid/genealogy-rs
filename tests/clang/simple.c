#include <stdio.h>
extern int f2(int);

// Define a foobar
struct foobar {
	int bar;
	int foo;
};

int f(int a) {
	return a*2;
}



int main(int argc, char **argv) {
	struct foobar fb = {0};
	fb.bar = argc;
	printf("Hello !");
	printf("%d\n", f(fb.bar) + f2(fb.foo));
	return 0;
}
