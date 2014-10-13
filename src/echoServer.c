
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define QLEN      32  /* maximum connection queue length  */
#define BUFSIZE   4096
#define CA_CERT "./ssl_files/server/cacert.pem"
#define P_KEY "./ssl_files/server/server_priv.key"
#define S_CERT "./ssl_files/server/server.cert"
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }
extern int  errno;
int   errexit(const char *format, ...);
int   passivesock(const char *portnum, int qlen);
int   echo(SSL* ssl);
SSL_CTX* load_cert();

/*------------------------------------------------------------------------
 * main - Concurrent TCP server for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
  SSL_library_init();
  SSL_load_error_strings();

  SSL_CTX *ctx = load_cert();
  if(ctx == NULL) printf("This is NULL..\n");
  SSL *ssl = SSL_new(ctx);
  if(ssl == NULL) printf("(ssl) This is NULL..\n");

  char  *portnum = "5004";  /* Standard server port number  */
  struct sockaddr_in fsin;  /* the from address of a client */
  int msock;      /* master server socket   */
  unsigned int  alen;   /* from-address length    */

  msock = passivesock(portnum, QLEN);

  printf("Server started waiting for clients \n");

  while (1) {

    int ssock, ssl_sock;

    alen = sizeof(fsin);

    ssock = accept(msock, (struct sockaddr *)&fsin, &alen);

    SSL_set_fd(ssl, ssock);
    if (ssock < 0)
    {
      errexit("accept: %s\n", strerror(errno));
    }

    printf ("Connection from %d, port %d\n", fsin.sin_addr.s_addr,
    fsin.sin_port);

    ssl_sock = SSL_accept(ssl);
    RETURN_SSL(ssl_sock);

    while( echo(ssl) != 0 );

    SSL_shutdown(ssl);
    close(ssock);

  }//end while

}//end main

/*------------------------------------------------------------------------
 * echo - echo one buffer of data, returning byte count
 *------------------------------------------------------------------------
 */
int
echo(SSL* ssl)
{
  char  buf[BUFSIZ];
  int cc;

  cc = SSL_read(ssl, buf, sizeof buf);
  if (cc < 0)
    errexit("echo read: %s\n", strerror(errno));
  if (cc && SSL_write(ssl, buf, cc) < 0)
    errexit("echo write: %s\n", strerror(errno));
  return cc;
}

/*------------------------------------------------------------------------
 * errexit - print an error message and exit
 *------------------------------------------------------------------------
 */
int
errexit(const char *format, ...)
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
exit(1);
}

/*------------------------------------------------------------------------
 * passivesock - allocate & bind a server socket using TCP
 *------------------------------------------------------------------------
 */
int
passivesock(const char *portnum, int qlen)
/*
 * Arguments:
 *      portnum   - port number of the server
 *      qlen      - maximum server request queue length
 */
{
  struct sockaddr_in sin; /* an Internet endpoint address  */
  int     s;              /* socket descriptor             */

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;

  if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
          errexit("can't get \"%s\" port number\n", portnum);

  s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s < 0)
      errexit("can't create socket: %s\n", strerror(errno));

  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
      fprintf(stderr, "can't bind to %s port: %s; Trying other port\n",
          portnum, strerror(errno));
      sin.sin_port=htons(0); /* request a port number to be allocated
                             by bind */
      if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
          errexit("can't bind: %s\n", strerror(errno));
      else {
          int socklen = sizeof(sin);

          if (getsockname(s, (struct sockaddr *)&sin, &socklen) < 0)
                  errexit("getsockname: %s\n", strerror(errno));
          printf("New server port number is %d\n", ntohs(sin.sin_port));
      }
  }

  if (listen(s, qlen) < 0)
      errexit("can't listen on %s port: %s\n", portnum, strerror(errno));
  return s;
}

/*
 * loads the server's ssl cert from file system
 */
SSL_CTX *
load_cert()
{
  SSL_CTX *CTX = SSL_CTX_new( SSLv3_server_method() );
  //CTX = (SSL_CTX *) malloc(sizeof(CTX));
  //load server cert
  if( SSL_CTX_use_certificate_file(CTX,S_CERT,SSL_FILETYPE_PEM) <= 0 )
  {
    printf("Error Loading server cert\n");
    exit(1);
  }
  //load private key
  if( SSL_CTX_use_PrivateKey_file(CTX, P_KEY, SSL_FILETYPE_PEM) <= 0 )
  {
     printf("Error loading server key\n");
     exit(1);
  }
  //verify client
  if( !SSL_CTX_load_verify_locations(CTX,CA_CERT,NULL))
  {
    printf("Error loading verify locations\n");
    exit(1);
  }
  //check key off of cert
  if (!SSL_CTX_check_private_key(CTX)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(1);
  }

  //required to verify client
  SSL_CTX_set_verify(CTX,SSL_VERIFY_PEER,NULL);
  SSL_CTX_set_verify_depth(CTX,1);

  return CTX;
}//end load cert
