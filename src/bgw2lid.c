#include"bgw2lid.h"

void writeLog(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vsyslog(LOG_LOCAL0, format, args);
  va_end(args);

  return;
}

int main(int argc, char *argv[])
{
  int c;
  char *idev = NULL;
  char *odev = NULL;
  pcap_t *handler;
  char errBuf[PCAP_ERRBUF_SIZE];

  int cnt = -1;
  pid_t pid;

  userArgs args;
  args.sendHandler = NULL;


  char *helpMessage= "Usage: %s [-i] <input device> [-o] <output device>\n";

  while ((c = getopt (argc, argv, ":i:o:")) != -1)
  {
    switch (c)
    {
      case 'i':
        idev = optarg;
        break;
      case 'o':
        odev = optarg;
        break;
      case '?':
        fprintf(stderr, "Unknown option -%c\n", optopt);
        fprintf(stderr, helpMessage, argv[0]);
        exit(EXIT_FAILURE);
      case ':':
        fprintf(stderr, "Option -%c requires an argument\n", optopt);
        exit(EXIT_FAILURE);
      default:
        fprintf(stderr, helpMessage, argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  if(idev == NULL || odev == NULL)
  {
    fprintf(stderr,helpMessage,argv[0]);
    exit(EXIT_FAILURE);
  }

  printf("Input device: %s\nOutput Device: %s\n", idev, odev);

  handler = pcap_open_live(idev, BUFSIZ, 1, 0, errBuf);

  if (handler == NULL)
  {
    fprintf(stderr,"Couldn't open device %s: %s\n", idev, errBuf);
    exit(EXIT_FAILURE);
  }

  args.sendHandler = pcap_open_live(odev, BUFSIZ, 0, 0, errBuf);

  if(args.sendHandler == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", odev, errBuf);
    exit(EXIT_FAILURE);
  }

  pid=fork();//child process

  if(pid == -1)
  {
    fprintf(stderr, "Error starting daemon %s\n",strerror(errno));
    exit(EXIT_FAILURE);
  }
  if(pid)
  {
    fprintf(stderr,"Daemon Started OK, PID = %i\n", pid);
    exit(EXIT_SUCCESS);
  }
  /* further code is executing in child process */
  if((setsid()) < 0)
  {
    fprintf(stderr,"[Daemon] An Error occured. Stop\n");
    exit(EXIT_FAILURE);
  }

  umask(0);

  if((chdir("/")) < 0)
  {
    fprintf(stderr,"[Daemon] Can't change directory\n");
    exit(EXIT_FAILURE);
  }
  fclose(stderr);
  fclose(stdin);
  fclose(stdout);

  /* grab the packets */

  if((pcap_datalink(handler)) == DLT_RAW)
    pcap_loop(handler, cnt,(pcap_handler)processPacketWModification, (u_char*)&args);
  else
    pcap_loop(handler, cnt,(pcap_handler)processPacketWoModification, (u_char*)&args);


  /* close session */
  pcap_close(handler);
  pcap_close(args.sendHandler);

  return 0;
}

void processPacketWModification(userArgs *args, const struct pcap_pkthdr *header, const u_char *packet)
{

  int tx_len = 0;
  char sendBuf[BUF_SIZE] = {0};
  struct ether_header *eh = (struct ether_header *) sendBuf;

  eh->ether_type = htons(ETH_P_IP); //IP proto.

  tx_len += sizeof(struct ether_header);

  memcpy(sendBuf, eh, tx_len);
  memcpy(sendBuf + tx_len, packet, header->caplen);
  tx_len += header->caplen;


  /* Sending packet */

  if((pcap_sendpacket(args->sendHandler, (const u_char*)sendBuf, tx_len)) == -1)
    writeLog("%s",pcap_geterr(args->sendHandler));

}

void processPacketWoModification(userArgs *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  char sendBuf[BUF_SIZE] = {0};

  memcpy(sendBuf, packet, header->caplen);

  /* Sending packet */

  if((pcap_sendpacket(args->sendHandler, (const u_char*)sendBuf, header->caplen)) == -1)
    writeLog("%s",pcap_geterr(args->sendHandler));

}
