#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/select.h>

#define EVENT_SIZE  1024
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

#define MAXLEN 1024

char buffer[BUF_LEN];
fd_set set;
fd_set rset;
int check_set[MAXLEN];
int max_fd;
int arrlen = 0;

/* 用echo "xxxx" >> 1.txt写入文件的时候,select能够侦测到 */
static void handle_read(int fd)
{
    memset (buffer,0,BUF_LEN);
  int length = read( fd, buffer, BUF_LEN );

  if ( length < 0 ) {
    perror( "read" );
  }
  else if (length == 0)
  {
      return;
  }
  printf("buf:%s, len:%d\n", buffer, length);

#if 0
  int i = 0;
  while ( i < length ) {
    struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];
    if ( event->len ) {
      if ( event->mask & IN_CREATE ) {
        if ( event->mask & IN_ISDIR ) {
          printf( "The directory %s was created.\n", event->name );
        }
        else {
          printf( "The file %s was created.\n", event->name );
        }
      }
      else if ( event->mask & IN_DELETE ) {
        if ( event->mask & IN_ISDIR ) {
          printf( "The directory %s was deleted.\n", event->name );
        }
        else {
          printf( "The file %s was deleted.\n", event->name );
        }
      }
      else if ( event->mask & IN_MODIFY ) {
        if ( event->mask & IN_ISDIR ) {
          printf( "The directory %s was modified.\n", event->name );
        }
        else {
          printf( "The file %s was modified. wd:%d\n", event->name ,event->wd);
        }
      }
    }
    i += EVENT_SIZE + event->len;
  }
    memset(buffer, 0, BUF_LEN);
#endif
}

static void do_select()
{
      int i = 0;
      while(1)
      {
          set = rset;
          int nready = select(max_fd+1, &set, NULL, NULL, NULL);
          if(nready == -1)
          {
              perror("error select !");
              exit(-1);
          }else if(nready == 0){
            printf("timeout!");
            continue;
          }

         for(i = 0; i < arrlen; ++i)//轮询数据连接
         {
          int set_fd = check_set[i];
          if(FD_ISSET(set_fd, &set))
          {
            handle_read(set_fd);
          }
         }
     }
}

static void AddFd(int fd)
{
    FD_SET(fd, &rset);
    check_set[arrlen++] = fd;

    if(max_fd < fd)
        max_fd = fd;
}

int main( int argc, char **argv )
{
    (void) argc;
    (void) argv;
    //初始化
    FD_ZERO(&rset);
    int i = 0;
    for(i = 0;i < MAXLEN; ++i)
          check_set[i] = -1;

    
    int fd = open("1.txt", O_RDONLY); 

    //添加监控fd
    AddFd(fd);

    //select轮询
    do_select();

    close(fd);

    exit( 0 );
}

