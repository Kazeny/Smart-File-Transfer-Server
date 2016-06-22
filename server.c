#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

struct Uploaded
{
	char *file;
	char *password;
	int secflag;

	struct Uploaded *next;
};

struct Uploaded* create_record(char*,char*,int);

void quit(int sig)
{
	exit (EXIT_SUCCESS);
}

int main()
{
	(void) signal(SIGINT,quit);
	struct Uploaded *start;
	struct Uploaded *new;
	struct Uploaded *record;
	int sno=0;
	int ufd;
	char *filename=NULL;
	int sockid;
	struct sockaddr_in addr;
	int bindid;
	int listenid;
	int acceptid;
	struct sockaddr_in caddr;
	socklen_t len=sizeof(caddr);
	char choice;
	int i=0;
	int count;
	char ch;
	char security;
	char *key=NULL;
	int uack=0;
	int dack=0;
	int dfd;
	int dwnsec=0;
	int kack;
	int closeid;

	start=new=create_record(filename,key,uack);

	unlink ("socket");

	sockid=socket(AF_INET,SOCK_STREAM,0);

	addr.sin_family=AF_INET;
	addr.sin_port=htons(4005);
	addr.sin_addr.s_addr=htonl(INADDR_ANY);
		
	bindid=bind(sockid,(struct sockaddr *)&addr,sizeof(addr));

	if(bindid<0)
	{
		perror("bind");
		goto OUT;
	}

	listenid=listen(sockid,5);

UP:	
	record=start->next;

	printf("\n..................UPLOADED FILES..................\n\n");
	printf("___________________________________________________\n");
	
	sno=1;

	while(record)
	{
		if(record->secflag==1)
		{
			printf("%d.) %s (SECURED) \n",sno,record->file);
		}

		else
		{
			printf("%d.) %s \n",sno,record->file);
		}

		record=record->next;

		sno++;
	}

	printf("\n\n___________________________________________________\n\n");

	printf("Checking for requests \n");

	acceptid=accept(sockid,(struct sockaddr *)&caddr,&len);
	
	read(acceptid,&choice,1);

	switch(choice)
	{
		case '0': break;

		case '1': printf("\nUpload request arrived \n");

			filename=(char*)malloc(sizeof(char)*20);

			i=0;

			while(1)
			{
				read(acceptid,(filename+i),1);

				if(*(filename+i)=='\0')
				{
					break;
				}

				i++;
			}

			printf("\nFile to be uploaded : %s \n",filename);

			ufd=open(filename,O_RDONLY);
	
			if(ufd>0)
			{
				uack=-1;
				write(acceptid,&uack,sizeof(int));
				break;
			}

			else
			{
				uack=0;
				write(acceptid,&uack,sizeof(int));
			}

			ufd=open(filename,O_RDWR|O_CREAT);

			if(ufd<0)
			{
				perror("open");
				goto OUT;
			}

			while(1)
			{
				read(acceptid,&count,sizeof(int));

				if(count==0)
				{
					break;
				}

				read(acceptid,&ch,1);
		
				write(ufd,&ch,1);
			}

			read(acceptid,&security,1);

			if(security=='y')
			{
				printf("\nSecurity request arrived for %s \n",filename);

				key=(char*)malloc(sizeof(char)*20);

				i=0;

				while(1)
				{
					read(acceptid,(key+i),1);

					if(*(key+i)=='\0')
					{
						break;
					}

					i++;
				}

				printf("\nKey to be set for %s : %s \n",filename,key);
			
				printf("\nFile %s uploaded on the server successfully with security \n",filename);

				uack=1;
			}
			
			else
			{
				printf("\nFile %s uploaded on the server successfully for open use \n",filename);

				uack=0;
			}
			
			new->next=create_record(filename,key,uack);
		
			new=new->next;	

			write(acceptid,&uack,sizeof(int));
	
			break;
		
		case '2': printf("\nDownload request arrived \n");

			filename=(char*)malloc(sizeof(char)*20);

			i=0;
			
			while(1)
			{
				read(acceptid,(filename+i),1);

				if(*(filename+i)=='\0')
				{
					break;
				}

				i++;
			}

			printf("\nFile to be downloaded : %s \n",filename);

			dfd=open(filename,O_RDONLY);
			
			if(dfd<0)
			{
				dack=-1;	
				write(acceptid,&dack,sizeof(int));
				break;
			}
			
			else
			{
				dack=0;
				write(acceptid,&dack,sizeof(int));	
			}

			record=start->next;

			while(record)
			{
				if(strcmp(record->file,filename)==0)
				{
					if(record->secflag==1)
					{
						dwnsec=1;
					}

					else
					{
						dwnsec=0;
					}

					break;
				}

				record=record->next;
			}

			write(acceptid,&dwnsec,sizeof(int));

			if(dwnsec==1)
			{
				printf("\nFile %s is available on the server with security \n",filename);	
	
				key=(char*)malloc(sizeof(char)*20);
			
				i=0;

				while(1)
				{
					read(acceptid,(key+i),1);

					if(*(key+i)=='\0')
					{
						break;
					}

					i++;
				}

				printf("\nKey recieved : %s \n",key);

				if(strcmp(key,record->password)==0)
				{
					printf("\nKey recieved is correct \n");

					kack=1;

					write(acceptid,&kack,sizeof(int));
				}

				else
				{
					printf("\nKey recieved is incorrect \n");
					
					kack=0;

					write(acceptid,&kack,sizeof(int));

					goto UP;
				}
			}

			else
			{
				printf("\nFile %s is available on the server for free public download \n",filename);	
				
			}

			dfd=open(filename,O_RDONLY);
	
			while(1)
			{
				count=read(dfd,&ch,1);

				write(acceptid,&count,sizeof(int));

				if(count==0)
				{
					break;
				}

				write(acceptid,&ch,1);
			}
	
			printf("\nFile %s downloaded from the server successfully \n",filename);

			break;
	}

	goto UP;
		
	closeid=close(acceptid);

	if(closeid<0)
	{
		perror("close");
		goto OUT;
	}

	return 0;
OUT:
	return -1;
}

struct Uploaded* create_record(char *filename,char *key,int flag)
{
	struct Uploaded *temp;

	temp=(struct Uploaded*)malloc(sizeof(struct Uploaded));

	temp->file=filename;
	temp->password=key;
	temp->secflag=flag;
	temp->next=NULL;

	return temp;
}
