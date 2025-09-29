#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdint.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>

#ifndef __WIN32__
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#define closesocket close
#else // __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
typedef uint32_t in_addr_t;
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH
#ifdef EWOULDBLOCK
#undef EWOULDBLOCK
#endif // EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#define poll WSAPoll
#endif // __WIN32__

#include <zlib.h>
#include <assert.h>
#include "xdelta/xdelta3.h"

#define CHUNK_SIZE (16 * 1024)

#define NETLOADER_COMM_PORT 17491

char cmdbuf[3072];
uint32_t cmdlen=0;

//---------------------------------------------------------------------------------
void shutdownSocket(int socket, int flags) {
//---------------------------------------------------------------------------------
	if (flags)
		shutdown(socket, flags);
	closesocket(socket);
}

//---------------------------------------------------------------------------------
static int setSocketNonblocking(int sock) {
//---------------------------------------------------------------------------------

#ifndef __WIN32__
	int flags = fcntl(sock, F_GETFL);

	if (flags == -1) return -1;

	int rc = fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	if (rc != 0) return -1;
#else
	u_long iMode = 1; // non-blocking

	int rc = ioctlsocket(sock, FIONBIO, &iMode);

	if (rc != NO_ERROR) return -1;
#endif

	return 0;
}

//---------------------------------------------------------------------------------
static int socketError(const char *msg) {
//---------------------------------------------------------------------------------
#ifndef _WIN32
	int ret = errno;
	if (ret == EAGAIN)
		ret = EWOULDBLOCK;
	perror(msg);
#else
	int ret = WSAGetLastError();
	wchar_t *s = NULL;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, ret,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&s, 0, NULL);
	fprintf(stderr, "%S\n", s);
	LocalFree(s);
	if (ret == WSAEWOULDBLOCK)
		ret = EWOULDBLOCK;
#endif

	return ret;
}

//---------------------------------------------------------------------------------
int pollSocket(int fd, int events, int timeout) {
//---------------------------------------------------------------------------------
#ifndef __WIN32__
	struct pollfd pfd;
#else
	WSAPOLLFD pfd;
#endif

	pfd.fd = fd;
	pfd.events = events;
	pfd.revents = 0;

	int ret = poll(&pfd, 1, timeout);
	if (ret < 0) {
		socketError("poll");
		return -1;
	}

	if (ret == 0)
		return -1;

	if (!(pfd.revents & events)) {
		int err = 0;
		socklen_t len = sizeof(err);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
		fprintf(stderr, "socket error 0x%x on poll\n", err);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------------
	Subtract the `struct timeval' values Y from X,
	storing the result in RESULT.
	Return 1 if the difference is negative, otherwise 0.

	From http://www.gnu.org/software/libtool/manual/libc/Elapsed-Time.html
---------------------------------------------------------------------------------*/
int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y) {
//---------------------------------------------------------------------------------
	struct timeval tmp;
	tmp.tv_sec = y->tv_sec;
	tmp.tv_usec = y->tv_usec;

	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < tmp.tv_usec) {
		int nsec = (tmp.tv_usec - x->tv_usec) / 1000000 + 1;
		tmp.tv_usec -= 1000000 * nsec;
		tmp.tv_sec += nsec;
	}

	if (x->tv_usec - tmp.tv_usec > 1000000) {
		int nsec = (x->tv_usec - tmp.tv_usec) / 1000000;
		tmp.tv_usec += 1000000 * nsec;
		tmp.tv_sec -= nsec;
	}

	/*	Compute the time remaining to wait.
		tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - tmp.tv_sec;
	result->tv_usec = x->tv_usec - tmp.tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < tmp.tv_sec;
}

//---------------------------------------------------------------------------------
void timeval_add (struct timeval *result, struct timeval *x, struct timeval *y) {
//---------------------------------------------------------------------------------
	result->tv_sec = x->tv_sec + y->tv_sec;
	result->tv_usec = x->tv_usec + y->tv_usec;

	if ( result->tv_usec > 1000000) {
		result->tv_sec += result->tv_usec / 1000000;
		result->tv_usec = result->tv_usec % 1000000;
	}
}

//---------------------------------------------------------------------------------
static struct in_addr findDS(int retries) {
//---------------------------------------------------------------------------------
	struct sockaddr_in s, remote, rs;
	char recvbuf[256];
	char mess[] = "dslink-delta-host";

	int broadcastSock = socket(PF_INET, SOCK_DGRAM, 0);
	if(broadcastSock < 0) perror("create send socket");

	int optval = 1, len;
	setsockopt(broadcastSock, SOL_SOCKET, SO_BROADCAST, (char *)&optval, sizeof(optval));

	memset(&s, '\0', sizeof(struct sockaddr_in));
	s.sin_family = AF_INET;
	s.sin_port = htons(NETLOADER_COMM_PORT);
	s.sin_addr.s_addr = INADDR_BROADCAST;

	memset(&rs, '\0', sizeof(struct sockaddr_in));
	rs.sin_family = AF_INET;
	rs.sin_port = htons(NETLOADER_COMM_PORT);
	rs.sin_addr.s_addr = INADDR_ANY;

	int recvSock = socket(PF_INET, SOCK_DGRAM, 0);

	if (recvSock < 0)  perror("create receive socket");

	if(bind(recvSock, (struct sockaddr*) &rs, sizeof(rs)) < 0) perror("bind");
#ifndef __WIN32__
	fcntl(recvSock, F_SETFL, O_NONBLOCK);
#else
	u_long opt = 1;
	ioctlsocket(recvSock, FIONBIO, &opt);
#endif
	struct timeval wanted, now, result;

	gettimeofday(&wanted, NULL);

	int timeout = retries;
	while(timeout) {
		gettimeofday(&now, NULL);
		if ( timeval_subtract(&result,&wanted,&now)) {
			if(sendto(broadcastSock, mess, strlen(mess), 0, (struct sockaddr *)&s, sizeof(s)) < 0) perror("sendto");
			result.tv_sec=0;
			result.tv_usec=150000;
			timeval_add(&wanted,&now,&result);
			timeout--;
		}
		socklen_t socklen = sizeof(remote);
		len = recvfrom(recvSock,recvbuf,sizeof(recvbuf),0,(struct sockaddr *)&remote,&socklen);
		if ( len != -1) {
			if (strncmp("dslink-delta-client", recvbuf, strlen("dslink-delta-client")) == 0) {
				break;
			}
		}
	}
	if (timeout == 0) remote.sin_addr.s_addr =  INADDR_NONE;
	shutdownSocket(broadcastSock, 0);
	shutdownSocket(recvSock, SHUT_RD);
	return remote.sin_addr;
}

//---------------------------------------------------------------------------------
int sendData(int sock, int sendsize, char *buffer) {
//---------------------------------------------------------------------------------
	while(sendsize) {
		int len = send(sock, buffer, sendsize, 0);
		if (len == 0) break;
		if (len != -1) {
			sendsize -= len;
			buffer += len;
		} else {
#ifdef _WIN32
			int errcode = WSAGetLastError();
			if (errcode != WSAEWOULDBLOCK) {
				printf("error %d\n",errcode);
				break;
			}
#else
			if ( errno != EWOULDBLOCK && errno != EAGAIN) {
				perror(NULL);
				break;
			}
#endif
		}
	}
	return sendsize != 0;
}

//---------------------------------------------------------------------------------
int recvData(int sock, char *buffer, int size, int flags) {
//---------------------------------------------------------------------------------
	int len, sizeleft = size;

	while (sizeleft) {
		len = recv(sock,buffer,sizeleft,flags);
		if (len == 0) {
			size = 0;
			break;
		}
		if (len != -1) {
			sizeleft -=len;
			buffer +=len;
		} else {
#ifdef _WIN32
			int errcode = WSAGetLastError();
			if (errcode != WSAEWOULDBLOCK) {
				printf("error %d\n",errcode);
				break;
			}
#else
			if ( errno != EWOULDBLOCK && errno != EAGAIN) {
				perror(NULL);
				break;
			}
#endif
		}
	}
	return size;
}


//---------------------------------------------------------------------------------
int sendInt32LE(int socket, uint32_t size) {
//---------------------------------------------------------------------------------
	char lenbuf[4];
	lenbuf[0] = size & 0xff;
	lenbuf[1] = (size >>  8) & 0xff;
	lenbuf[2] = (size >> 16) & 0xff;
	lenbuf[3] = (size >> 24) & 0xff;

	return sendData(socket,4,lenbuf);
}

//---------------------------------------------------------------------------------
int recvInt32LE(int socket, int32_t *data) {
//---------------------------------------------------------------------------------
	char intbuf[4];
	int len = recvData(socket,intbuf,4,0);

	if (len == 4) {
		*data = intbuf[0] | intbuf[1] << 8 | intbuf[2] << 16 | intbuf[3] << 24;
		return 0;
	}

	return -1;

}

unsigned char in[CHUNK_SIZE];
unsigned char out[CHUNK_SIZE];

//---------------------------------------------------------------------------------
int sendNDSFile(in_addr_t dsaddr, char *name, size_t filesize, FILE *fh, FILE *deltaSource) {
//---------------------------------------------------------------------------------

	int retval = 0;

	int ret, flush;
	unsigned have;
	z_stream strm;

	/* allocate deflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
	if (ret != Z_OK) return ret;

	int sock = socket(AF_INET,SOCK_STREAM,0);
	if (sock < 0) {
		perror("create connection socket");
		return -1;
	}

	struct sockaddr_in s;
	memset(&s, '\0', sizeof(struct sockaddr_in));
	s.sin_family = AF_INET;
	s.sin_port = htons(NETLOADER_COMM_PORT);
	s.sin_addr.s_addr = dsaddr;

	if (connect(sock,(struct sockaddr *)&s,sizeof(s)) < 0 ) {
		struct in_addr address;
		address.s_addr = dsaddr;
		fprintf(stderr,"Connection to %s failed\n",inet_ntoa(address));
		return -1;
	}

	char mode = deltaSource == NULL ? 0 : 1;
	if (sendData(sock, 1, &mode)) {
		fprintf(stderr,"Failed sending transfer mode\n");
		retval = -1;
		goto error;
	}

	int namelen = strlen(name);

	if (sendInt32LE(sock,namelen)) {
		fprintf(stderr,"Failed sending filename length\n");
		retval = -1;
		goto error;
	}

	if (sendData(sock,namelen,name)) {
		fprintf(stderr,"Failed sending filename\n");
		retval = -1;
		goto error;
	}

	if (sendInt32LE(sock,filesize)) {
		fprintf(stderr,"Failed sending file length\n");
		retval = -1;
		goto error;
	}

	int response;

	if(recvInt32LE(sock,&response)!=0) {
		fprintf(stderr,"Invalid response\n");
		retval = 1;
		goto error;
	}

	if(response!=0) {
		switch(response) {
			case -1:
				fprintf(stderr,"Failed to create file\n");
				retval = 1;
				goto error;
			case -2:
				fprintf(stderr,"Insufficient space\n");
				retval = 1;
				goto error;
			case -3:
				fprintf(stderr,"Insufficient memory\n");
				retval = 1;
				goto error;
			case -4:
				printf("Source not found on DS, sending complete file\n");
				deltaSource = NULL;
				break;
		}
	}

	printf("Sending %s, %zu bytes\n", name, filesize);

	size_t totalsent = 0, blocks = 0;

	if (deltaSource) {
		xd3_stream stream;
		xd3_config config;
		xd3_init_config(&config, XD3_ADLER32);
		config.winsize = (2 * 1024 * 1024);
		retval = xd3_config_stream(&stream, &config);
		if (retval != 0) {
			fprintf(stderr, "Error initializing xdelta stream\n");
			goto error;
		}

		xd3_source source = {0};
		source.name = name;
		source.ioh = deltaSource;
		source.blksize = CHUNK_SIZE;
		source.curblkno = (xoff_t) -1;
		source.curblk = NULL;
		xd3_set_source(&stream, &source);

		usize_t len;
		int status = XD3_INPUT;
		bool eof = false;

		while (!eof || status != XD3_INPUT) {
			switch (status) {
			case XD3_INPUT:
				len = fread(in, 1, CHUNK_SIZE, fh);
				eof = feof(fh);
				if (eof) {
					xd3_set_flags(&stream, XD3_FLUSH | stream.flags);
				}
				xd3_avail_input(&stream, in, len);
				break;
			case XD3_OUTPUT:
				len = stream.avail_out;
				while (len) {
					int sendSize = len > CHUNK_SIZE ? CHUNK_SIZE : len;
					if (sendInt32LE(sock, sendSize)) {
						fprintf(stderr, "Failed sending chunk size\n");
						retval = -1;
						goto xdelta_cleanup;
					}
					if (sendData(sock, sendSize, (char *)stream.next_out)) {
						fprintf(stderr, "Failed sending %s\n", name);
						retval = -1;
						goto xdelta_cleanup;
					}
					len -= sendSize;
					blocks++;
				}
				totalsent += stream.avail_out;
				xd3_consume_output(&stream);
				break;
			case XD3_GETSRCBLK:
				fseek(source.ioh, source.blksize * source.getblkno, SEEK_SET);
				source.onblk = fread(out, 1, source.blksize, source.ioh);
				source.curblk = out;
				source.curblkno = source.getblkno;
				break;
			case XD3_GOTHEADER:
			case XD3_WINSTART:
			case XD3_WINFINISH:
				break;
			default:
				fprintf(stderr, "xdelta error!\n");
				retval = status;
				goto xdelta_cleanup;
			}
			status = xd3_encode_input(&stream);
		}

	xdelta_cleanup:
		if (xd3_close_stream(&stream) != 0) {
			fprintf(stderr, "Something wrong when closing stream\n");
		}
		xd3_free_stream(&stream);


		if (retval != 0) goto error;
	}
	else {
		do {
			strm.avail_in = fread(in, 1, CHUNK_SIZE, fh);
			if (ferror(fh)) {
				(void)deflateEnd(&strm);
				return Z_ERRNO;
			}
			flush = feof(fh) ? Z_FINISH : Z_NO_FLUSH;
			strm.next_in = in;
			/* run deflate() on input until output buffer not full, finish
			   compression if all of source has been read in */
			do {
				strm.avail_out = CHUNK_SIZE;
				strm.next_out = out;
				ret = deflate(&strm, flush);    /* no bad return value */
				assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
				have = CHUNK_SIZE - strm.avail_out;
	
				if (have != 0) {
					if (sendInt32LE(sock,have)) {
						fprintf(stderr,"Failed sending chunk size\n");
						retval = -1;
						goto error;
					}
	
					if (sendData(sock, have, (char *)out)) {
						fprintf(stderr,"Failed sending %s\n", name);
						retval = 1;
						(void)deflateEnd(&strm);
						goto error;
					}
	
					totalsent += have;
					blocks++;
				}
			} while (strm.avail_out == 0);
			assert(strm.avail_in == 0);     /* all input will be used */
			/* done when last data in file processed */
		} while (flush != Z_FINISH);
		assert(ret == Z_STREAM_END);        /* stream will be complete */
		(void)deflateEnd(&strm);
	}

	printf("%zu sent (%.2f%%), %zu blocks\n", totalsent, (float)(totalsent * 100.0) / filesize, blocks);

	if(recvInt32LE(sock,&response)!=0) {
		fprintf(stderr,"Failed sending %s\n",name);
		retval = 1;
		goto error;
	}


	if(sendData(sock,cmdlen+4,cmdbuf)) {

		fprintf(stderr,"Failed sending command line\n");
		retval = 1;
		goto error;

	}


error:
	shutdownSocket(sock, SHUT_WR);
	return retval;
}

#ifdef __WIN32__
static void win32_socket_cleanup(void) {
	WSACleanup();
}
#endif

//---------------------------------------------------------------------------------
void showHelp() {
//---------------------------------------------------------------------------------
	puts( PACKAGE_STRING "\n");
	printf("Usage: dslink [options] ndsfile\n");
	puts("--help,     -h   Display this information");
	puts("--address,  -a   Hostname or IPv4 address of DS");
	puts("--retries,  -r   number of times to ping before giving up");
	puts("--arg0,     -0   set argv[0]");
	puts("--delta,    -d   Enable deltas. Creates and uses [ndsfile].copy");
	puts("--server  , -s   start server after completed upload");
	puts("--version , -v   show version.");
	puts("\n");
}

//---------------------------------------------------------------------------------
int main(int argc, char **argv) {
//---------------------------------------------------------------------------------
	char *address = NULL;
	char *argv0 = NULL;
	char *endarg = NULL;
	int retries = 10;
	int server = 0;
	bool useDeltas = false;

	if (argc < 2) {
		showHelp();
		return 1;
	}

	while(1) {
		static struct option long_options[] = {
			{"address", required_argument, 0, 'a'},
			{"retries", required_argument, 0, 'r'},
			{"arg0",    required_argument, 0, '0'},
			{"args",    required_argument, 0,  1 },
			{"delta",   no_argument,       0, 'd'},
			{"server",  no_argument,       0, 's'},
			{"version", no_argument,       0, 'v'},
			{"help",    no_argument,       0, 'h'},
			{0, 0, 0, 0}
		};

		/* getopt_long stores the option index here. */
		int option_index = 0, c;

		c = getopt_long (argc, argv, "a:r:dshv0:", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1) break;

		switch(c) {

		case 'a':
			address = optarg;
			break;
		case 'r':
			errno = 0;
			retries = strtoul(optarg, &endarg, 0);
			if (endarg == optarg) errno = EINVAL;
			if (errno != 0) {
				perror("--retries");
				exit(1);
			}
			break;
		case '0':
			argv0 = optarg;
			break;
		case 'd':
			useDeltas = true;
			break;
		case 's':
			server = 1;
			break;
		case 'h':
			showHelp();
			return 0;
		case 'v':
			puts( PACKAGE_STRING );
			return 0;
		}

	}

	char *filename = argv[optind++];
	if (filename== NULL) {
		showHelp();
		return 1;
	}

	memset(cmdbuf, '\0', sizeof(cmdbuf));

	FILE *fh = fopen(filename,"rb");
	if (fh == NULL) {
		fprintf(stderr,"Failed to open %s\n",filename);
		return -1;
	}

	fseek(fh,0,SEEK_END);
	size_t filesize = ftell(fh);
	fseek(fh,0,SEEK_SET);

	char *basename = NULL;
	if((basename=strrchr(filename,'/'))!=NULL) {
		basename++;
	} else if ((basename=strrchr(filename,'\\'))!=NULL) {
		basename++;
	} else {
		basename = filename;
	}

	if (argv0 == NULL) {
		strcpy(&cmdbuf[4],"sd:/nds/");
		strcat(&cmdbuf[4],basename);
	} else {
		strcpy(&cmdbuf[4],argv0);
	}

	cmdlen = strlen(&cmdbuf[4]) + 1;

	for (int index = optind; index < argc; index++) {
		int len=strlen(argv[index]);
		if ( (cmdlen + len + 5 ) >= (sizeof(cmdbuf) - 2) ) break;
		strcpy(&cmdbuf[cmdlen+4],argv[index]);
		cmdlen+= len + 1;
	}

	cmdbuf[0] = cmdlen & 0xff;
	cmdbuf[1] = (cmdlen>>8) & 0xff;
	cmdbuf[2] = (cmdlen>>16) & 0xff;
	cmdbuf[3] = (cmdlen>>24) & 0xff;

	FILE *deltaSource = NULL;
	char sourceName[PATH_MAX];
	snprintf(sourceName, PATH_MAX, "%s.copy", filename);
	if (useDeltas) {
		deltaSource = fopen(sourceName, "rb");
		if (deltaSource == NULL) {
			printf("Previous copy not found.\n");
		}
		else {
			printf("Using %s as the delta source\n", sourceName);
		}
	}

#ifdef __WIN32__
	WSADATA wsa_data;
	if (WSAStartup (MAKEWORD(2,2), &wsa_data)) {
		printf ("WSAStartup failed\n");
		return 1;
	}
	atexit(&win32_socket_cleanup);
#endif

	struct in_addr dsaddr;
	dsaddr.s_addr  =  INADDR_NONE;

	if (address == NULL) {
		dsaddr = findDS(retries);

		if (dsaddr.s_addr == INADDR_NONE) {
			printf("No response from DS!\n");
			return 1;
		}

	} else {
		struct addrinfo *info;
		if (getaddrinfo(address, NULL, NULL, &info) == 0) {
			dsaddr = ((struct sockaddr_in*)info->ai_addr)->sin_addr;
			freeaddrinfo(info);
		}
	}

	if (dsaddr.s_addr == INADDR_NONE) {
		fprintf(stderr,"Invalid address\n");
		return 1;
	}

	int res = sendNDSFile(dsaddr.s_addr, basename, filesize, fh, deltaSource);

	fclose(fh);
	if (deltaSource) fclose(deltaSource);

	if (res == 0 && useDeltas) {
		FILE *sent = fopen(filename, "rb");
		FILE *copy = fopen(sourceName, "wb");
		if (copy != NULL && sent != NULL) {
			int c;
			while ((c = fgetc(sent)) != EOF) {
				fputc(c, copy);
			}
			printf("Saved %s\n", sourceName);
		}
		if (sent) fclose(sent);
		if (copy) fclose(copy);
	}

	if (server) {
		printf("starting server\n");

		struct sockaddr_in serv_addr;

		memset(&serv_addr, '0', sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(NETLOADER_COMM_PORT);

		int listenfd = socket(AF_INET, SOCK_STREAM, 0);
		if (listenfd < 0) {
			socketError("socket");
			return EXIT_FAILURE;
		}

		int rc = bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
		if (rc != 0) {
			socketError("bind listen socket");
			shutdownSocket(listenfd, 0);
			return EXIT_FAILURE;
		}

		rc = setSocketNonblocking(listenfd);
		if (rc == -1) {
			socketError("listen fcntl");
			shutdownSocket(listenfd, 0);
			return EXIT_FAILURE;
		}

		rc = listen(listenfd, 10);
		if (rc != 0) {
			socketError("listen");
			shutdownSocket(listenfd, 0);
			return EXIT_FAILURE;
		}

		printf("server active ...\n");

		int datafd = -1;

		while (listenfd != -1 || datafd != -1) {
			struct sockaddr_in sa_remote;

			if (pollSocket(listenfd >= 0 ? listenfd : datafd, POLLIN, -1))
				break;

			if (listenfd >= 0) {
				socklen_t addrlen = sizeof(sa_remote);
				datafd = accept(listenfd, (struct sockaddr*)&sa_remote, &addrlen);

				if (datafd < 0 && socketError("accept") != EWOULDBLOCK)
					break;

				if (datafd >= 0) {
					shutdownSocket(listenfd, 0);
					listenfd = -1;
				}
			} else {
				char recvbuf[256];
				int len = recv(datafd, recvbuf, sizeof(recvbuf), 0);

				if (len == 0 || (len < 0 && socketError("recv") != EWOULDBLOCK)) {
					shutdownSocket(datafd, 0);
					datafd = -1;
					break;
				}

				if (len > 0)
					fwrite(recvbuf, 1, len, stdout);
			}
		}

		if (listenfd >= 0)
			shutdownSocket(listenfd, 0);
		if (datafd >= 0)
			shutdownSocket(datafd, SHUT_RD);

		printf("exiting ... \n");
	}

	return res;
}

