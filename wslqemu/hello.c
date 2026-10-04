#include <stdio.h>
int main(void){ FILE*f=fopen("/mnt/c/Users/Apps/Downloads/com.penti.app/wslqemu/hello.txt","w"); fprintf(f,"hello from arm64\n"); fclose(f); return 0; }
