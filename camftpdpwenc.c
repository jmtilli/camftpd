#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include "argon2/include/argon2.h"

void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s\n", argv0);
	exit(1);
}


int main(int argc, char **argv)
{
	char encoded[1024];
	int err;
	char pw[1024];
	int randfd;
	char salt[16];
	if (argc != 1)
	{
		usage(argv[0]);
	}
	if (fgets(pw, (int)sizeof(pw), stdin) == NULL)
	{
		printf("EOF\n");
		return 1;
	}
	if (strlen(pw) && pw[strlen(pw)-1] == '\n')
	{
		pw[strlen(pw)-1] = '\0';
	}
	randfd = open("/dev/urandom", O_RDONLY);
	if (randfd < 0)
	{
		printf("Rand\n");
		return 1;
	}
	if (read(randfd, salt, sizeof(salt)) != (ssize_t)sizeof(salt))
	{
		printf("Rand2\n");
		return 1;
	}
	if ((err = argon2id_hash_encoded(4, 512, 1, pw, strlen(pw), salt, sizeof(salt), 64, encoded, sizeof(encoded))) != ARGON2_OK)
	{
		printf("Argon error %d\n", err);
		return 1;
	}
	printf("Argon hash: %s\n", encoded);
	return 0;
}
