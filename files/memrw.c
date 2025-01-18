/* see also devmem2 & memdump
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>

typedef unsigned char           SA_U8;
typedef unsigned short          SA_U16;
typedef unsigned int            SA_U32;

typedef signed char             SA_S8;
typedef short                   SA_S16;
typedef int                     SA_S32;

typedef unsigned long           SA_UL;
typedef signed long             SA_SL;

#define FATAL \
do { \
    fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", __LINE__, __FILE__, errno, strerror(errno));  \
    exit(1); \
} while(0)


/*
./devmem.b/w/l -r 0x8000000 count
./devmem.b/w/l -w 0x8000000 value

*/

#define CONFIG_SYS_MAXARGS             10
SA_S32 dump_mem(off_t map, SA_U8 *pucBase, SA_U32 u32Width, SA_U32 u32Size, SA_U32 u32LineLen);
int parse_args(int argc, char**argv, off_t *pTarget, unsigned long *pMapSize, unsigned long *pWvalue);

#define ALIGN_UP(x, align_to)  (((x) + ((align_to)-1)) & ~((align_to)-1))

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)
int cmd_get_data_size(char* arg, int default_size);

static char gszFileName[128] = {"memdump.bin"};

int main(int argc, char **argv) {
    int devMemFd, iFd;
    void *map_base, *virt_addr; 
	unsigned long read_result, writeval = 0;
	off_t target, extra_bytes, map_addr;
    unsigned long map_size;
	unsigned long readCnt = 0;
	int access_type = 'w';
	char *pcBuf;
	long page_size;
	int ret;
	
	 if (argc < 2) {
		fprintf(stderr, "\nUsage:\t%s -r/-w { address } [ len [ data ] ]\n"
			"\t-r address [len] \n"
			"\t-w address data\n",
			argv[0]);
		exit(1);
	}

    if (0 != parse_args(argc, argv, &target, &readCnt, &writeval)) {
        FATAL;
    }
	
	access_type = cmd_get_data_size(argv[0],4);
	
	page_size = sysconf(_SC_PAGE_SIZE);
	map_addr = target & ~(page_size - 1);
	extra_bytes = (target & (page_size - 1));
    map_size = ALIGN_UP(readCnt, page_size);
    printf("page_size=%ld, extra_bytes=%ld, map_size=0x%lx, map_addr=0x%lx\n", page_size, extra_bytes, map_size, map_addr); 

    if(-1 == (devMemFd = open("/dev/mem", O_RDWR | O_SYNC))) FATAL;
    
    /* Map one page */
    map_base = mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, devMemFd, map_addr);
    if(MAP_FAILED == map_base) FATAL;
    
    printf("Memory mapped at address %p.\n", map_base); 
    fflush(stdout);
    virt_addr = map_base + (target & (page_size - 1));
    
    if (0 == strcmp(argv[1], "-r")) {
		dump_mem(map_addr, (SA_U8 *)virt_addr, access_type, (readCnt+access_type-1)/access_type, 16/access_type);
    } else if (0 == strcmp(argv[1], "-w")) {
		switch(access_type) {
			case 1: 
            {
				*((unsigned char *) virt_addr) = writeval;
				read_result = *((unsigned char *) virt_addr);
				break;
			}
			case 2:
            {
				*((unsigned short *) virt_addr) = writeval;
				read_result = *((unsigned short *) virt_addr);
				break;
			}
			case 4:
			{
				*((unsigned long *) virt_addr) = writeval;
				read_result = *((unsigned long *) virt_addr);
				break;
			}
			default:
			{
				fprintf(stderr, "Illegal data type '%c'.\n", access_type);
				exit(2);
			}
		}

        printf("Written 0x%lX; readback 0x%lX\n", writeval, read_result); 
		fflush(stdout);
    }
	else if (0 == strcmp(argv[1], "-d")) {
		pcBuf = malloc(map_size);
		if (NULL == pcBuf) {
			fprintf(stderr, "Failed to allocate memory\n");
			goto alloc_fail;
		}

		/*
		 * Using a separate buffer for write stops the kernel from
		 * complaining quite as much as if we passed the mmap()ed
		 * buffer directly to write().
		 */
		printf("Start of memcpy map_base=%lx, virt_addr=%lx\n", (off_t)map_base, (off_t)virt_addr); 
		memcpy(pcBuf, (char *)map_base, readCnt);
		printf("End of memcpy map_base=%lx, virt_addr=%lx\n", (off_t)map_base, (off_t)virt_addr); 
		
		iFd = open((const char*)gszFileName, O_RDWR | O_CREAT, 0755);
		if (iFd >= 0) {
            ret = write(iFd, pcBuf+extra_bytes, readCnt);
			if (ret == -1) {
				perror("Could not write data");
			} else if (ret != (ssize_t)readCnt) {
				fprintf(stderr, "Only wrote %d bytes\n", ret);
			}
			
			close(iFd);
        }

	}
	
alloc_fail:
    munmap(map_base, map_size);
	
	close(devMemFd);
	
	return 0;
}


int parse_args(int argc, char**argv, off_t *pTarget, unsigned long *pMapSize, unsigned long *pWvalue)
{
    off_t AddrTmp;
    unsigned long ulTmp;
    char *endp;

    if ((NULL == pTarget) || (NULL == pMapSize))return -1;

    if (0 == strcmp(argv[1], "-r")) {
        if (argc < 3) {
            printf("%s -r addr [cnt]\n", argv[0]);
            return -1;
        }
        AddrTmp = strtoul(argv[2],&endp, 16);
        if (argv[2] == endp) {
            printf("Error param argv[1]=%s\n", argv[2]);
        }

        if (argc > 3) {
            ulTmp = strtoul(argv[3],&endp, 16);
            if (argv[3] == endp) {
                printf("Error param argv[1]=%s\n", argv[3]);
            }
        } else {
            ulTmp = 4;
        }

        *pTarget = AddrTmp;
        *pMapSize = ulTmp;

    } else if(0 == strcmp(argv[1], "-w")) {
        if (argc < 4) {
            printf("%s -w addr value\n", argv[0]);
            return -1;
        }
        AddrTmp = strtoul(argv[2],&endp, 16);
        if (argv[2] == endp) {
            printf("Error param argv[1]=%s\n", argv[2]);
        }

        ulTmp = strtoul(argv[3],&endp, 16);
        if (argv[3] == endp) {
            printf("Error param argv[2]=%s\n", argv[3]);
        }

        *pTarget = AddrTmp;
        *pWvalue = ulTmp;
		*pMapSize = 4; /* default to 4K */

    } else if(0 == strcmp(argv[1], "-d")) {
		if (argc < 4) {
            printf("%s -d addr len\n", argv[0]);
            return -1;
        }
		
		AddrTmp = strtoul(argv[2],&endp, 16);
        if (argv[2] == endp) {
            printf("Error param argv[2]=%s\n", argv[2]);
        }

        ulTmp = strtoul(argv[3],&endp, 16);
        if (argv[3] == endp) {
            printf("Error param argv[3]=%s\n", argv[3]);
        }
		
		if (argc > 4) {
            snprintf(gszFileName, sizeof(gszFileName), "%s", argv[4]);
        }
		
		*pTarget = AddrTmp;
		*pMapSize = ulTmp;
	}
	
	if (*pMapSize < 0) {
		printf("map size %ld is not correct \n", *pMapSize);
		exit(EXIT_FAILURE);
	}

    return 0;
}

#define MAX_LINE_LENGTH_BYTES (64)
#define DEFAULT_LINE_LENGTH_BYTES (16)
//#define isprint(a) ((a >=' ')&&(a <= '~')) 

SA_S32 dump_mem(off_t map_addr, SA_U8 *pucBase, SA_U32 u32Width, SA_U32 u32Size, SA_U32 u32LineLen)
{
        /* linebuf as a union causes proper alignment */
        union linebuf {
            SA_U32 ui[MAX_LINE_LENGTH_BYTES/sizeof(SA_U32) + 1];
            SA_U16 us[MAX_LINE_LENGTH_BYTES/sizeof(SA_U16) + 1];
            SA_U8  uc[MAX_LINE_LENGTH_BYTES/sizeof(SA_U8) + 1];
        } lb;
        int i;
        char lineBuf[256]={0};
        SA_U32 x;
        SA_UL ulAddr = (SA_UL)(void*)pucBase;
        SA_UL ulBaseAddr = ulAddr;
        SA_U8 *pucAddr = pucBase;
        SA_U8 *pucBaseAddr = pucBase;

        if (0 == ulAddr)return -1;
        
        printf("BaseAddr=0x%08lx,size=0x%08x(%d)\n", ulAddr, u32Size, u32Size);

        if (u32LineLen*u32Width > MAX_LINE_LENGTH_BYTES)
            u32LineLen = MAX_LINE_LENGTH_BYTES / u32Width;
        if (u32LineLen < 1)
            u32LineLen = DEFAULT_LINE_LENGTH_BYTES / u32Width;
    
        while (u32Size) {
            SA_U32 thislinelen = u32LineLen;

            memset(lineBuf, 0, sizeof(lineBuf));

            snprintf(lineBuf+strlen(lineBuf), sizeof(lineBuf)-strlen(lineBuf), "%08lx:", map_addr+(off_t)(pucAddr-pucBaseAddr));
    
            /* check for overflow condition */
            if (u32Size < thislinelen)
                thislinelen = u32Size;
    
            /* Copy from memory into linebuf and print hex values */
            for (i = 0; i < thislinelen; i++) {
                if (u32Width == 4)
                    x = lb.ui[i] = *(volatile SA_U32 *)pucBase;
                else if (u32Width == 2)
                    x = lb.us[i] = *(volatile SA_U16 *)pucBase;
                else
                    x = lb.uc[i] = *(volatile SA_U8 *)pucBase;
                snprintf(lineBuf+strlen(lineBuf), sizeof(lineBuf)-strlen(lineBuf), " %0*x", u32Width * 2, x);
                pucBase += u32Width;
            }

            while (thislinelen < u32LineLen) {
                /* fill line with whitespace for nice ASCII print */
                for (i=0; i<u32Width*2+1; i++)
               snprintf(lineBuf+strlen(lineBuf), sizeof(lineBuf)-strlen(lineBuf), " ");
                u32LineLen--;
            }

            /* Print data in ASCII characters */
            for (i = 0; i < thislinelen * u32Width; i++) {
                if (!isprint(lb.uc[i]) || lb.uc[i] >= 0x80)
                    lb.uc[i] = '.';
            }
            lb.uc[i] = '\0';
            snprintf(lineBuf+strlen(lineBuf), sizeof(lineBuf)-strlen(lineBuf), "\t %s", lb.uc);

            printf(" %s \n",lineBuf);
            
            /* update references */
            pucAddr += thislinelen * u32Width;
            u32Size -= thislinelen;
    
        }
    
        return 0;
}



int cmd_get_data_size(char* arg, int default_size)
{
	/* Check for a size specification .b, .w or .l.
	 */
	int len = strlen(arg);
	if (len > 2 && arg[len-2] == '.') {
		switch (arg[len-1]) {
		case 'b':
			return 1;
		case 'w':
			return 2;
		case 'l':
			return 4;
		#if 0	
		case 'q':
			return 8;
		#endif
		case 's':
			return -2;
		default:
			return -1;
		}
	}
	return default_size;
}

unsigned long parse_int (char *str) {
	long long result;
	char *endptr; 

	result = strtoll(str, &endptr, 0);
	if (str[0] == '\0' || *endptr != '\0') {
		fprintf(stderr, "\"%s\" is not a valid number\n", str);
		FATAL;
	}

	return (unsigned long)result;
}

