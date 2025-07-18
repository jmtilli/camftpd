#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pwd.h>
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
	fprintf(stderr, "Usage: %s dir listenaddr cliaddr linuxuser ftpuser passhash\n", argv0);
	exit(1);
}
const char *user = NULL;
const char *passhash = NULL;
in_addr_t cliaddr;
in_addr_t srvaddr;
const char *cliaddrstr;

char gbuf[1024];
size_t gbufstart;
size_t gbufend;
int fd;
int bufgetc(void)
{
	if (gbufstart == gbufend)
	{
		ssize_t bytes_read;
		gbufstart = 0;
		gbufend = 0;
		bytes_read = read(fd, gbuf, sizeof(gbuf));
		if (bytes_read == 0)
		{
			return EOF;
		}
		if (bytes_read < 0)
		{
			// FIXME log error
			_exit(1);
		}
		gbufend = (size_t)bytes_read;
	}
	if (gbufstart >= gbufend)
	{
		_exit(1);
	}
	return (unsigned char)gbuf[gbufstart++];
}

size_t bufgetline(char *line, size_t maxsz)
{
	size_t i = 0;
	int ch;
	int crseen = 0;
	for (;;)
	{
		ch = bufgetc();
		if (ch == EOF)
		{
			// FIXME log error
			_exit(1);
		}
		if (ch == '\r')
		{
			if (crseen)
			{
				// FIXME log error
				_exit(1);
			}
			crseen = 1;
			continue;
		}
		if (ch == '\n')
		{
			line[i++] = '\0';
			return i-1;
		}
		if (crseen)
		{
			// FIXME log error
			_exit(1);
		}
		if (i >= maxsz-1)
		{
			// FIXME log error
			_exit(1);
		}
		if (ch == '\0')
		{
			// FIXME log error
			_exit(1);
		}
		line[i++] = (char)ch;
	}
}

int user_seen = 0;
int pass_seen = 0;
void handle_user(const char *buf, size_t sz)
{
	if (strcmp(buf, user) != 0)
	{
		// FIXME log error
		_exit(1);
	}
	user_seen = 1;
}
void handle_pass(const char *buf, size_t sz)
{
	if (!user_seen)
	{
		// FIXME log error
		_exit(1);
	}
	if (argon2id_verify(passhash, buf, strlen(buf)) != ARGON2_OK)
	{
		// FIXME log error
		_exit(1);
	}
	pass_seen = 1;
}
const char *greeting = "220 My FTP Server\r\n";
const char *passreq = "331 Password required for ";
const char *userloginstart = "230 User ";
const char *userloginend = " logged in.\r\n";
const char *cwdsuccess = "250 CWD command successful. \"/\" is current directory.\r\n";
const char *authni = "500 This security scheme is not implemented.\r\n";
const char *xfercomplete = "226 Transfer complete.\r\n";
const char *goodbye = "221 Goodbye.\r\n";
const char *typei = "200 Type set to I\r\n";
const char *typea = "200 Type set to A\r\n";
const char *mode = "BINARY";
const char *portok = "200 PORT Command Successful\r\n";
const char *systresp = "215 UNIX Type: Linux\r\n";
void child(int newfd)
{
	char buf[1024];
	size_t sz;
	int pasv = 0;
	int pasvfd = -1;
	int cliport = -1;
	fd = newfd;
	if (write(fd, greeting, strlen(greeting)) != (ssize_t)strlen(greeting))
	{
		// FIXME log error
		_exit(1);
	}
	for (;;)
	{
		sz = bufgetline(buf, sizeof(buf));
		if (sz >= 5 && buf[0] == 'U' && buf[1] == 'S' && buf[2] == 'E' && buf[3] == 'R' && buf[4] == ' ')
		{
			struct iovec iov[3];
			handle_user(buf+5, sz-5);
			iov[0].iov_base = (void*)passreq;
			iov[0].iov_len = strlen(passreq);
			iov[1].iov_base = (void*)user;
			iov[1].iov_len = strlen(user);
			iov[2].iov_base = ".\r\n";
			iov[2].iov_len = 3;
			if (writev(fd, iov, 3) != (ssize_t)(iov[0].iov_len + iov[1].iov_len + iov[2].iov_len))
			{
				// FIXME log error
				_exit(1);
			}
			continue;
		}
		if (sz == 8 && buf[0] == 'A' && buf[1] == 'U' &&
		    buf[2] == 'T' && buf[3] == 'H' && buf[4] == ' ' &&
		    buf[5] == 'T' && buf[6] == 'L' && buf[7] == 'S')
		{
			if (write(fd, authni, strlen(authni)) != (ssize_t)strlen(authni))
			{
				// FIXME log error
				_exit(1);
			}
			continue;
		}
		if (sz >= 5 && buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'S' && buf[3] == 'S' && buf[4] == ' ')
		{
			struct iovec iov[3];
			handle_pass(buf+5, sz-5);
			iov[0].iov_base = (void*)userloginstart;
			iov[0].iov_len = strlen(userloginstart);
			iov[1].iov_base = (void*)user;
			iov[1].iov_len = strlen(user);
			iov[2].iov_base = (void*)userloginend;
			iov[2].iov_len = strlen(userloginend);
			if (writev(fd, iov, 3) != (ssize_t)(iov[0].iov_len + iov[1].iov_len + iov[2].iov_len))
			{
				// FIXME log error
				_exit(1);
			}
			continue;
		}
		if (!pass_seen)
		{
			// FIXME log error
			_exit(1);
		}
		// FIXME EPSV
		if (sz >= 4 && buf[0] == 'C' && buf[1] == 'W' && buf[2] == 'D' && buf[3] == ' ')
		{
			if (write(fd, cwdsuccess, strlen(cwdsuccess)) != (ssize_t)strlen(cwdsuccess))
			{
				// FIXME log error
				_exit(1);
			}
			continue;
		}
		if (sz > 5 && buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'R' && buf[3] == 'T' && buf[4] == ' ')
		{
			int a,b,c,d,e,f;
			if (pasv)
			{
				// FIXME log error
				_exit(1);
			}
			if (sscanf(buf+5, "%d,%d,%d,%d,%d,%d", &a,&b,&c,&d,&e,&f) != 6)
			{
				// FIXME log error
				_exit(1);
			}
			if (a < 0 || b < 0 || c < 0 || d < 0 || e < 0 || f < 0)
			{
				// FIXME log error
				_exit(1);
			}
			if (a > 255 || b > 255 || c > 255 || d > 255 || e > 255 || f > 255)
			{
				// FIXME log error
				_exit(1);
			}
			if (htonl((a<<24) | (b<<16) | (c<<8) | d) != cliaddr)
			{
				// FIXME log error
				_exit(1);
			}
			cliport = (e<<8) | f;
			if (cliport == 0)
			{
				// FIXME log error
				_exit(1);
			}
			if (write(fd, portok, strlen(portok)) != (ssize_t)strlen(portok))
			{
				// FIXME log error
				_exit(1);
			}
			continue;
		}
		if (sz == 4 && buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'S' && buf[3] == 'V')
		{
			struct sockaddr_in sin;
			char respbuf[1024];
			socklen_t addrlen;
			if (cliport >= 0 || pasv)
			{
				// FIXME log error
				_exit(1);
			}
			pasvfd = socket(AF_INET, SOCK_STREAM, 0);
			if (pasvfd < 0)
			{
				// FIXME log error
				_exit(1);
			}
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = srvaddr;
			sin.sin_port = htons(0);
			if (bind(pasvfd, (const struct sockaddr*)&sin, sizeof(sin)) != 0)
			{
				// FIXME log error
				_exit(1);
			}
			if (listen(pasvfd, 512) != 0)
			{
				// FIXME log error
				_exit(1);
			}
			addrlen = sizeof(sin);
			if (getsockname(pasvfd, (struct sockaddr*)&sin, &addrlen) != 0)
			{
				// FIXME log error
				_exit(1);
			}
			if (sin.sin_family != AF_INET || addrlen != sizeof(sin))
			{
				// FIXME log error
				_exit(1);
			}
			int a,b,c,d,e,f;
			a = (ntohl(srvaddr) >> 24)&0xFF;
			b = (ntohl(srvaddr) >> 16)&0xFF;
			c = (ntohl(srvaddr) >> 8)&0xFF;
			d = (ntohl(srvaddr) >> 0)&0xFF;
			e = (ntohs(sin.sin_port)>>8)&0xFF;
			f = (ntohs(sin.sin_port)>>0)&0xFF;
			if (snprintf(respbuf, sizeof(respbuf), "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",a,b,c,d,e,f) >= (ssize_t)sizeof(respbuf))
			{
				// FIXME log error
				_exit(1);
			}
			if (write(fd, respbuf, strlen(respbuf)) != (ssize_t)strlen(respbuf))
			{
				// FIXME log error
				_exit(1);
			}
			pasv = 1;
			continue;
		}
		if (sz == 6 && buf[0] == 'T' && buf[1] == 'Y' && buf[2] == 'P' && buf[3] == 'E' && buf[4] == ' ' && buf[5] == 'I')
		{
			mode = "BINARY";
			if (write(fd, typei, strlen(typei)) != (ssize_t)strlen(typei))
			{
				// FIXME log error
				_exit(1);
			}
			continue;
		}
		if (sz == 6 && buf[0] == 'T' && buf[1] == 'Y' && buf[2] == 'P' && buf[3] == 'E' && buf[4] == ' ' && buf[5] == 'A')
		{
			mode = "ASCII";
			if (write(fd, typei, strlen(typea)) != (ssize_t)strlen(typea))
			{
				// FIXME log error
				_exit(1);
			}
			continue;
		}
		if (sz == 4 && buf[0] == 'Q' && buf[1] == 'U' && buf[2] == 'I' && buf[3] == 'T')
		{
			if (write(fd, goodbye, strlen(goodbye)) != (ssize_t)strlen(goodbye))
			{
				// FIXME log error
				_exit(1);
			}
			close(fd);
			_exit(0);
		}
		if (sz == 4 && buf[0] == 'S' && buf[1] == 'Y' && buf[2] == 'S' && buf[3] == 'T')
		{
			if (write(fd, systresp, strlen(systresp)) != (ssize_t)strlen(systresp))
			{
				// FIXME log error
				_exit(1);
			}
			continue;
		}
		if (sz > 5 && buf[0] == 'S' && buf[1] == 'T' && buf[2] == 'O' && buf[3] == 'R' && buf[4] == ' ')
		{
			int ffd;
			if (strlen(buf) != sz)
			{
				// There is extra NUL
				// FIXME log error
				_exit(1);
			}
			if (strchr(buf, '/'))
			{
				// No slash allowed
				// FIXME log error
				_exit(1);
			}
			if (strchr(buf, '\r'))
			{
				// No CR allowed
				// FIXME log error
				_exit(1);
			}
			if (strchr(buf, '\n'))
			{
				// No LF allowed
				// FIXME log error
				_exit(1);
			}
			if (strcmp(buf+5, ".") == 0)
			{
				// Current directory
				// FIXME log error
				_exit(1);
			}
			if (strcmp(buf+5, "..") == 0)
			{
				// Parent directory
				// FIXME log error
				_exit(1);
			}
			ffd = open(buf+5, O_WRONLY|O_CREAT|O_EXCL, 0444);
			if (ffd < 0)
			{
				// Can't open
				// FIXME log error
				_exit(1);
			}
			if (pasv)
			{
				char respbuf[1024];
				struct sockaddr_in sin;
				socklen_t addrlen;
				int accfd;
				addrlen = sizeof(sin);
				for (;;)
				{
					accfd = accept(pasvfd, (struct sockaddr*)&sin, &addrlen);
					if (accfd < 0)
					{
						// Can't accept
						// FIXME log error
						_exit(1);
					}
					if (sin.sin_family != AF_INET || addrlen != sizeof(sin))
					{
						// FIXME log error
						_exit(1);
					}
					if (sin.sin_addr.s_addr != cliaddr)
					{
						close(accfd);
						continue;
					}
					break;
				}
				close(pasvfd);
				pasvfd = -1;
				if (snprintf(respbuf, sizeof(respbuf), "150 Data connection accepted from %s:%d, transfer starting for %s.\r\n", cliaddrstr, (int)ntohs(sin.sin_port), buf+5) >= (ssize_t)sizeof(respbuf))
				{
					// FIXME log error
					_exit(1);
				}
				if (write(fd, respbuf, strlen(respbuf)) != (ssize_t)strlen(respbuf))
				{
					// FIXME log error
					_exit(1);
				}
				for (;;)
				{
					char fbuf[16384];
					ssize_t bytes_read;
					bytes_read = read(accfd, fbuf, sizeof(fbuf));
					if (bytes_read < 0)
					{
						// FIXME log error
						_exit(1);
					}
					if (bytes_read == 0)
					{
						break;
					}
					if (write(ffd, fbuf, (size_t)bytes_read) != bytes_read)
					{
						// FIXME log error
						_exit(1);
					}
				}
				fsync(ffd);
				close(ffd);
				close(accfd);
				if (write(fd, xfercomplete, strlen(xfercomplete)) != (ssize_t)strlen(xfercomplete))
				{
					// FIXME log error
					_exit(1);
				}
				pasv = 0;
				continue;
			}
			else
			{
				char respbuf[1024];
				int accfd;
				struct sockaddr_in sin;
				sin.sin_family = AF_INET;
				sin.sin_addr.s_addr = cliaddr;
				if (cliport <= 0 || cliport > 65535)
				{
					// FIXME log error
					_exit(1);
				}
				sin.sin_port = htons(cliport);
				cliport = -1;
				accfd = socket(AF_INET, SOCK_STREAM, 0);
				if (accfd < 0)
				{
					// FIXME log error
					_exit(1);
				}
				if (connect(accfd, (const struct sockaddr*)&sin, sizeof(sin)) != 0)
				{
					// FIXME log error
					_exit(1);
				}
				if (snprintf(respbuf, sizeof(respbuf), "150 Opening %s mode data connection.\r\n", mode) >= (ssize_t)sizeof(respbuf))
				{
					// FIXME log error
					_exit(1);
				}
				if (write(fd, respbuf, strlen(respbuf)) != (ssize_t)strlen(respbuf))
				{
					// FIXME log error
					_exit(1);
				}
				for (;;)
				{
					char fbuf[16384];
					ssize_t bytes_read;
					bytes_read = read(accfd, fbuf, sizeof(fbuf));
					if (bytes_read < 0)
					{
						// FIXME log error
						_exit(1);
					}
					if (bytes_read == 0)
					{
						break;
					}
					if (write(ffd, fbuf, (size_t)bytes_read) != bytes_read)
					{
						// FIXME log error
						_exit(1);
					}
				}
				fsync(ffd);
				close(ffd);
				close(accfd);
				if (write(fd, xfercomplete, strlen(xfercomplete)) != (ssize_t)strlen(xfercomplete))
				{
					// FIXME log error
					_exit(1);
				}
				continue;
			}
		}
		// FIXME log error, unsupported command
		_exit(0);
	}
}

int main(int argc, char **argv)
{
	int sockfd;
	struct sockaddr_in sin;
	socklen_t addrlen;
	int newfd;
	int optval = 1;
	struct passwd *pw;
	if (argc != 7)
	{
		usage(argv[0]);
	}
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		fprintf(stderr, "Can't create socket\n");
		exit(1);
	}
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(21);
	if (chdir(argv[1]) != 0)
	{
		fprintf(stderr, "Can't change directory\n");
		exit(1);
	}
	sin.sin_addr.s_addr = inet_addr(argv[2]);
	srvaddr = inet_addr(argv[2]);
	cliaddr = inet_addr(argv[3]);
	cliaddrstr = argv[3];
	pw = getpwnam(argv[4]);
	if (pw == NULL)
	{
		fprintf(stderr, "Can't find user\n");
		exit(1);
	}
	user = argv[5];
	passhash = argv[6];
	if (bind(sockfd, (const struct sockaddr*)&sin, sizeof(sin)) != 0)
	{
		fprintf(stderr, "Can't bind socket\n");
		exit(1);
	}
	if (listen(sockfd, 512) != 0)
	{
		fprintf(stderr, "Can't listen\n");
		exit(1);
	}
	if (setgid(pw->pw_gid) != 0)
	{
		fprintf(stderr, "Can't setgid\n");
		exit(1);
	}
	if (setuid(pw->pw_uid) != 0)
	{
		fprintf(stderr, "Can't setuid\n");
		exit(1);
	}
	signal(SIGCHLD, SIG_IGN);
	for (;;)
	{
		pid_t pid;
		addrlen = sizeof(sin);
		newfd = accept(sockfd, (struct sockaddr*)&sin, &addrlen);
		if (newfd < 0)
		{
			if (errno == ECONNABORTED || errno == EINTR || errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM || errno == EPROTO || errno == EPERM)
			{
				continue;
			}
			fprintf(stderr, "Can't accept\n");
			exit(1);
		}
		if (sin.sin_family != AF_INET || addrlen != sizeof(sin))
		{
			// FIXME log error
			close(newfd);
			continue;
		}
		if (sin.sin_addr.s_addr != cliaddr)
		{
			// FIXME log error
			close(newfd);
			continue;
		}
		pid = fork();
		if (pid < 0)
		{
			close(newfd);
			continue;
		}
		else if (pid == 0)
		{
			// child
			close(sockfd);
			child(newfd);
			_exit(0);
		}
		else
		{
			// parent
			close(newfd);
			continue;
		}
	}
	return 0;
}
