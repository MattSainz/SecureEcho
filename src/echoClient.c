#include <sys/types.h>
#include <sys/socket.h>

#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#ifndef INADDR_NONE
#define INADDR_NONE     0xffffffff
#endif  /* INADDR_NONE */

extern int  errno;

int TCPecho(const char *host, const char *portnum);
int errexit(const char *format, ...);
int connectsock(const char *host, const char *portnum);
SSL_CTX* load_cert();

#define LINELEN   128
#define C_CERT "./ssl_files/client/client.cert"
#define C_KEY "./ssl_files/client/client_priv.key"
#define C_CA "./ssl_files/client/cacert.pem"
#define RETURN_SSL(err) if ((err) < 0) { ERR_print_errors_fp(stderr); exit(1); }
/*------------------------------------------------------------------------
 * main - TCP client for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
  //required ssl initlization
  //loads encryption and hash algorithems for SSL

  char  *host = "localhost";  /* host to use if none supplied */
  char  *portnum = "5004";  /* default server port number */

  switch (argc) {
  case 1:
    host = "localhost";
    break;
  case 3:
    host = argv[2];
    /* FALL THROUGH */
  case 2:
    portnum = argv[1];
    break;
  default:
    fprintf(stderr, "usage: TCPecho [host [port]]\n");
    exit(1);
  }
  TCPecho(host, portnum);
  exit(0);
}//end main

int
TCPecho(const char *host, const char *portnum)
{
  SSL_library_init();
  SSL_load_error_strings();

  X509 *server_cert;

  SSL_CTX *ctx = load_cert();

  SSL *ssl = SSL_new(ctx);

  char  buf[LINELEN+1];   /* buffer for one line of text  */
  int s, n, err;      /* socket descriptor, read count*/
  int outchars, inchars;  /* characters sent and received */

  s = connectsock(host, portnum);

  err = SSL_set_fd(ssl,s);
  printf("Err: %d \n", err);
  RETURN_SSL(err);  

  err = SSL_connect(ssl);
  printf("Err: %d \n", err);
  RETURN_SSL(err);

  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

  server_cert = SSL_get_peer_certificate(ssl);

  if( server_cert != NULL )
  {
    printf ("Server certificate:\n");

    char* str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
    printf ("\t subject: %s\n", str);
    free (str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
    printf ("\t issuer: %s\n", str);
    free(str);

    X509_free (server_cert);

    printf("Server <<:");
    while (fgets(buf, sizeof(buf), stdin)) {
      buf[LINELEN] = '\0';  /* insure line null-terminated  */
      outchars = strlen(buf);
      (void) SSL_write(ssl, buf, outchars);

      /* read it back */
      for (inchars = 0; inchars < outchars; inchars+=n ) {
        n = SSL_read(ssl, &buf[inchars], outchars - inchars);
        if (n < 0)
          errexit("socket read failed: %s\n",
            strerror(errno));
      }
      printf("Reply: ");

      fputs(buf, stdout);
      printf("Server <<:");
    }
  }
  else
  {
    printf("Err cannot connect server does not have cert\n");
    exit(1);
  }

}//end TCPecho

int
errexit(const char *format, ...)
{
        va_list args;

        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        exit(1);
}//end errexit

int
connectsock(const char *host, const char *portnum)
/*
 * Arguments:
 *      host      - name of host to which connection is desired
 *      portnum   - server port number
 */
{

        struct hostent  *phe;   /* pointer to host information entry    */
        struct sockaddr_in sin; /* an Internet endpoint address         */
        int     s;              /* socket descriptor                    */


        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;

    /* Map port number (char string) to port number (int)*/
        if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
                errexit("can't get \"%s\" port number\n", portnum);

    /* Map host name to IP address, allowing for dotted decimal */
        if ( phe = gethostbyname(host) )
                memcpy(&sin.sin_addr, phe->h_addr, phe->h_length);
        else if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE )
                errexit("can't get \"%s\" host entry\n", host);

    /* Allocate a socket */
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
                errexit("can't create socket: %s\n", strerror(errno));

    /* Connect the socket */
        if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                errexit("can't connect to %s.%s: %s\n", host, portnum,
                        strerror(errno));
        return s;
}//end connectsock

SSL_CTX *
load_cert()
{
  SSL_CTX *ctx= SSL_CTX_new( SSLv3_client_method() );
  if( SSL_CTX_use_certificate_file(ctx,C_CERT,SSL_FILETYPE_PEM) <= 0 )
  {
    printf("Error loading client cert \n");
    exit(1);
  }
  //load a private key
  if( SSL_CTX_use_PrivateKey_file(ctx, C_KEY, SSL_FILETYPE_PEM) <= 0 )
  {
    printf("Error loading client private key \n");
    exit(1);
  }
  //load ca
  if( !SSL_CTX_load_verify_locations(ctx,C_CA, NULL) )
  {
    printf("Error loading ca \n");
    exit(1);
  }

  //request for server to be certified
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(ctx,1);

  return ctx;
}//end laod_certs
