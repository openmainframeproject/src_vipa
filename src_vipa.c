/*
 * src_vipa.c
 *
 * Copyright IBM Corp. 2001, 2013
 * Author(s): Utz Bacher  <utz.bacher@de.ibm.com>
 *            Vivek Kashyap <vivk@us.ibm.com>
 * POLICY_LOCAL_RR by Reinhard Buendgen <buendgen@de.ibm.com>
 * POLICY_LOCAL_LC by Vivek Kashyap <vivk@us.ibm.com>
 * IPv6-support by Machihin Alexey <machihin_a@ru.ibm.com>
 *
 * Published under the terms and conditions of the CPL (common public license)
 *
 * src_vipa is provided under the terms of the enclosed common public license
 * ("agreement"). Any use, reproduction or distribution of the program
 * constitutes recipient's acceptance of this agreement.
 *
 */

/* please see the man page and the README file of src_vipa.
 * setuid programs can't be executed under src_vipa due to an LD_PRELOAD
 * security feature; they can only be executed when the real UID is 0
 */

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <netdb.h>
#include <dlfcn.h>
#include <errno.h>

#include <sys/time.h>


#define LIBC_PATH "libc.so.6"
#define DLOPEN_FLAG RTLD_LAZY


#define LOG_FACILITY LOG_USER

#define BIND_ERROR_ERRNO EADDRNOTAVAIL


#define DEFAULT_CONFIG_FILE "/etc/src_vipa.conf"
#define CONFIG_FILE_ENV "SRC_VIPA_CONFIG_FILE"

#define MAX_PORTNO 65535

#define UNINTERESTING 0
#define INTERESTING 1

#define LINE_LEN 1024
#define MAX_SOURCES_PER_DEST 8

#define DT_HASH_SIZE 16
#define MAX_NMASK    128

#define CRC_POLY  0xEDB88320

#define LOCK_T pthread_mutex_t
#define LOCKIT pthread_mutex_lock
#define UNLOCKIT pthread_mutex_unlock

#define xstr(s) str(s)
#define str(s) #s
static const char *version = "src_vipa " xstr(VERSION);

int last_pid=0;
int leader_pid;

unsigned int tab_crc32[256];
const unsigned int  coef_crc32 = 0xD202EF8D;

enum {
	ISBOUND_UNBOUND = 0,
	ISBOUND_NOMINAL = 1,
	ISBOUND_RD      = 2,
	ISBOUND_WR      = 4,
	ISBOUND_CLOSE   = 6,
};


/*
 * Supported Policies
 */
enum {
	POLICY_RANDOM,
	POLICY_RR,
	POLICY_LOCAL_RR,  /* local Round Robin with random start */
	POLICY_LOCAL_LC,  /* local least count */
	POLICY_ONEVIPA,   /* always take first vipa, fast */
};

#define RR_SHM_SIZE (sizeof(u_int32_t))

/*
 * Policy structures for LC
 * NOTE:
 *   Keep next and list at same offsets in both lc_val and lc_head resp.
 *   Keep next and lc_head at same offsets in both lc_head and lc_data resp.
 *
 */
struct lc_val {
      	struct lc_val  *prev;
	struct lc_val  *next;
	struct lc_head *head;
	int source_idx;
	int count;
};

struct lc_head {
	struct lc_head *next;
	struct lc_val  *list;
	struct lc_head *prev;
	int count;
	int num;
};

struct lc_data {
	struct lc_head *lc_head;
	struct lc_head *lc_freehead;
	int            lc_tbd_sources_count;
	int            lc_tbd_sources_index;
	LOCK_T         lc_lock;
};


/*
 * The source selection policy structure.
 *
 * Includes the policy type. The generic functions for initialisation,
 * and reset of any policy related data structures and the function
 * that selects the source as per the policy. Also includes the per
 * policy data structure.
 */


typedef struct policy {
	u_int32_t policy_type;
   	void      (*policy_setup)();
      	void      (*policy_reset)();
	struct sockaddr_storage (*policy_get_src)();

	union {
		struct {
		} random;
		struct {
			void *addr;
		} round_robin;
      		struct {
	    		unsigned int idx; /* current index of
					     round robin policy */
		} local_round_robin;
		struct lc_data local_lc;
	} policy_data;
} policy_t;

/*
 * Socket info for policy
 */
struct socket_policy_info {
	int                       socket_no;
	int                       src_idx;
	int			  bindlevel;
	struct sv_entry           *entry;
	void                      *pdata;
	struct socket_policy_info *next;
};

#ifdef LC_TEST
struct sv_entry *first_sv_entry = NULL;
#endif

/*
 * The list of destination/source address associations.
 */

typedef struct sv_entry {
	struct sv_entry *next;

	struct sockaddr_storage dest;
	u_int16_t netmask_len;

	u_int16_t no_sources;
	struct sockaddr_storage src[MAX_SOURCES_PER_DEST];
	struct policy policy;
} sv_entry_t;

/*
* The list keeps a list of host's aliases
*/

typedef struct addr_item {
	struct addr_item *next;
	struct sockaddr_storage addr;
} addr_item_t;

/*
 * The entries are stored in netmask length based hash table
 */


typedef struct hash_entry {
   	struct sv_entry *dh_entry;
      	int dh_count;
} dm_hash_entry_t;

typedef struct mask_entry {
	dm_hash_entry_t    dm_dh[DT_HASH_SIZE];
	struct mask_entry  *dm_next;
	int                dm_nlen;
} dt_mask_entry_t;

struct dest_table {
	dt_mask_entry_t *dt_dm[MAX_NMASK+1];
	dt_mask_entry_t *dt_first_dm;
} dest_table;

#define GET_FUNC(x) \
if (dl_handle) { \
	char *err; \
	dlerror(); \
	orig_ ## x=dlsym(dl_handle,#x); \
	if ((!orig_ ## x)&&(err=dlerror())) { \
		syslog(LOG_WARNING,"dlsym failed on " #x ": %s\n",err); \
		orig_ ## x=&emergency_ ## x; \
	} \
} else { \
	orig_ ## x=&emergency_ ## x; \
}

int (*orig_socket)(int domain,int type,int protocol);
int (*orig_bind)(int sockfd,const struct sockaddr *my_addr,socklen_t addrlen);
int (*orig_connect)(int sockfd,const struct sockaddr *serv_addr,
		    socklen_t addrlen);
ssize_t (*orig_sendto)(int s,const void *msg,size_t len,int flags,
	    	       const struct sockaddr *to,socklen_t tolen);
ssize_t (*orig_sendmsg)(int s,const struct msghdr *msg,int flags);
int (*orig_shutdown)(int s,int how);
int (*orig_close)(int fd);

static void *dl_handle;

/* index is kept in network order */
typedef struct sfp_entry_t {
	u_int32_t no_sources;
	struct sockaddr_storage src[MAX_SOURCES_PER_DEST];

	struct policy policy;
} sfp_entry_t;

sfp_entry_t source_for_port[MAX_PORTNO+1] = { [0 ... MAX_PORTNO] = {
	0,
}};

typedef struct shm_list_t {
	int id;
	void *addr;
	struct shm_list_t *next;
} shm_list_t;
shm_list_t *shm_list=NULL;

/* power of two for easy modulo */
#define SOCKET_HASH_BUCKETS 256

/*
 * Prototypes
 */

void init_mutexes(void);
void destroy_mutexes(void);
struct socket_policy_info *set_socket_state(int, int);
struct socket_policy_info *get_socket_state(int, int);
int insert_socket_policy_info(int, int, struct sv_entry *, void *);
int is_it_bound(int, int);
struct socket_policy_info *remove_socket_policy_info(int, int, int);
void add_sv_entry(struct sv_entry *, int, int);
unsigned int dm_hash_val(struct sockaddr_storage *, int);
void add_to_hash_table(struct sv_entry *, dt_mask_entry_t *);
static struct sv_entry *get_src_ip_entry(struct sockaddr_storage *);
static void bend_functions(void);
static void add_sfp_entry(sfp_entry_t *, int, int);
static int get_next_word(char **, char *);
void add_list_item(int, void *);
static void read_config_file(void);
void destroy_shm(void);
void policy_random_setup(struct sv_entry *, int);
void policy_rr_setup(struct sv_entry *, int);
void policy_lrr_setup(struct sv_entry *, int);
void policy_lc_setup(struct sv_entry *, int);
struct sockaddr_storage policy_lc_get_src(int, struct sv_entry *);
struct lc_head *lc_policy_update_head(struct lc_data *,
	struct lc_head *, struct lc_val *);
struct lc_head *lc_policy_insert_source(struct lc_data *,
	struct lc_head *, struct lc_val *);
void close_cleanup(int, int);
void policy_lc_reset_source(struct socket_policy_info *);
struct lc_head *lc_policy_remove_source(struct lc_data *, struct lc_val *);
struct sockaddr_storage get_source_by_policy(int, struct sv_entry *);
void initialize(void);
void finalize(void);
void init_crc32(void);
unsigned int dm_hash_val_ip4(void *, int);
unsigned int dm_hash_val_ip6(void *,int);
void bind_check(int, int, struct sv_entry *);
int bitcmp(void *, void *, int);
int addrcmp(struct sockaddr_storage *, struct sockaddr_storage *, int);
unsigned int entry_hash_get(struct sockaddr_storage *, int);
struct addr_item *read_host_names(struct hostent *);
struct addr_item *new_item(void);
void erase_addr_list(struct addr_item *);

/* return rand() XORed with our pid, to make sure different processes
 * get different random numbers when srand was done before the fork. as
 * the pid tweaks the lower order bits, myrand better is called with just
 * myrand()%n instead of using the higher order bits as indicated in the
 * man page */
inline int myrand()
{
	int pid,i;

	/* if process was forked, get a different rand value */
	pid=getpid();
	if (pid!=last_pid) {
		last_pid=pid;
		for (i=0;i<pid%7;i++) {
			rand();
		}
	}
	return (rand()^getpid());
}

/* this is not atomic. anyway. worst case is a distribution that is not
 * quite optimal, but almost */
static u_int32_t atomic_inc_and_wrap_and_return(void *addr,int wrap_value)
{
	int n,pid;
	int *i=addr;

	/* if process was forked, jump to the next offset */
	pid=getpid();
	if (pid!=last_pid) {
		last_pid=pid;
		(*i)++;
	}

	n=*i=(*i+1)%wrap_value;

	return n;
}

/* for lrr: avoid uneven balancing, when a process does a lot of forks,
 * each child doing the same then */
static u_int32_t atomic_inc_pid_and_wrap_and_return(void *addr,int wrap_value)
{
	int n,pid;
	int *i=addr;

	/* if process was forked, jump to a totally different offset */
	pid=getpid();
	if (pid!=last_pid) {
		last_pid=pid;
		(*i)+=pid%7;
	}

	n=*i=(*i+1)%wrap_value;

	return n;
}

LOCK_T ext_socket_state_lock[SOCKET_HASH_BUCKETS];

struct socket_policy_info *socket_policy_anchors[SOCKET_HASH_BUCKETS];

void init_mutexes(void)
{
	int i;

	for (i=0;i<SOCKET_HASH_BUCKETS;i++) {
		pthread_mutex_init(&ext_socket_state_lock[i],NULL);
	}
}

void destroy_mutexes(void)
{
	int i;

	for (i=0;i<SOCKET_HASH_BUCKETS;i++) {
		pthread_mutex_destroy(&ext_socket_state_lock[i]);
	}
}

struct socket_policy_info *set_socket_state(int socket_no,int lock)
{
	volatile struct socket_policy_info *sse;
	int hash_no;

      	/* no need to check for duplicates, set_state is
	 * only called once when creating socket
	 */
	hash_no=socket_no&(SOCKET_HASH_BUCKETS-1);

	if (lock)
		LOCKIT(&ext_socket_state_lock[hash_no]);

	sse=(volatile struct socket_policy_info *)
		malloc(sizeof(struct socket_policy_info));
	if (sse) {
		sse->socket_no=socket_no;
		sse->src_idx = -1;
		sse->bindlevel = ISBOUND_UNBOUND;
		sse->next=socket_policy_anchors[hash_no];
     		socket_policy_anchors[hash_no]=
			(struct socket_policy_info *)sse;
	} else {
		syslog(LOG_WARNING,"was not able to " \
		       "allocate memory for socket state " \
		       "(fd=%i) -- src_vipa may not work " \
		       "for this socket\n",socket_no);
		/* return NULL below */
	}

	if (lock)
		UNLOCKIT(&ext_socket_state_lock[hash_no]);

	return (struct socket_policy_info *)sse;
}

int is_it_bound(int socket_no,int lock)
{
	volatile struct socket_policy_info *sse;
	int retval,hash_no;

	hash_no=socket_no&(SOCKET_HASH_BUCKETS-1);
	if (lock)
		LOCKIT(&ext_socket_state_lock[hash_no]);

	sse = get_socket_state(socket_no, 0);

	if (!sse) {
     		/*
		 * Should not happen - this functions is called by
		 * sendmsg/sendto only. Act as if it is bound.
		 */
		syslog(LOG_WARNING,"could not determine socket state "
		       "in src_vipa (fd=%i) -- src_vipa may not work " \
		       "for this socket\n",socket_no);
		retval=1;
	} else {
		retval = sse->bindlevel;
	}

	if (lock)
		UNLOCKIT(&ext_socket_state_lock[hash_no]);

	return retval;
}

struct socket_policy_info *get_socket_state(int socket_no,int lock)
{
	volatile struct socket_policy_info *sse;
	int hash_no;

	hash_no=socket_no&(SOCKET_HASH_BUCKETS-1);

	if (lock)
		LOCKIT(&ext_socket_state_lock[hash_no]);

	sse=socket_policy_anchors[hash_no];
	while (sse) {
		if (sse->socket_no==socket_no) {
			break;
		}
		sse=sse->next;
	}

	if (lock)
		UNLOCKIT(&ext_socket_state_lock[hash_no]);

	return (struct socket_policy_info *)sse;
}

int insert_socket_policy_info(int sock_no,int i,
			      struct sv_entry *entry,void *pdata)
{
	struct socket_policy_info *sinfo;
	int hash_no;

	hash_no=sock_no&(SOCKET_HASH_BUCKETS-1);

	LOCKIT(&ext_socket_state_lock[hash_no]);

	sinfo = (struct socket_policy_info *)get_socket_state(sock_no, 0);
	if (!sinfo) {
		sinfo = set_socket_state(sock_no, 0);
		if (!sinfo) {
			/* couldn't allocate memory. fail the call with a
			 * different src index  */
			i--;
			goto out;
		}
	}
	if (sinfo->src_idx < 0) {
	       	sinfo->src_idx = i;
		sinfo->pdata = pdata;
		sinfo->entry = entry;
		sinfo->bindlevel = ISBOUND_NOMINAL;
	} else i = sinfo->src_idx;

out:
	UNLOCKIT(&ext_socket_state_lock[hash_no]);

	return i;
}

struct socket_policy_info *remove_socket_policy_info(int sock_no,
						     int lock_flag,
						     int bindlevel)
{
	int hash_no;
      	struct socket_policy_info *sse, *psse;

	hash_no=sock_no&(SOCKET_HASH_BUCKETS-1);

	if (lock_flag)
		LOCKIT(&ext_socket_state_lock[hash_no]);

	sse = socket_policy_anchors[hash_no];

	while(sse){
		if (sse->socket_no==sock_no) {
			sse->bindlevel |= bindlevel;
			if(!(((sse->bindlevel | bindlevel) & ISBOUND_CLOSE) ==
			   ISBOUND_CLOSE)) {
				sse = NULL;
				break;
			}
			if(socket_policy_anchors[hash_no] == sse){
				socket_policy_anchors[hash_no] = sse->next;
			} else {	
				psse->next = sse->next;
			}
			break;
		} else {
			psse = sse;
			sse = sse->next;
		}
	}

	if (lock_flag)
		UNLOCKIT(&ext_socket_state_lock[hash_no]);

	return sse;
}

/* what should we do, if bind fails?
 * variation 1: return the error, socket call fails
			errno=BIND_ERROR_ERRNO; \
			close_cleanup(sockfd,ISBOUND_NOMINAL); \
			goto out; \
 * 
 * variation 2: don't bind, continue, src_vipa doesn't work for this socket
 * just issue the user-demanded socket call
			syslog(LOG_NOTICE,"was not able to bind " \
			       "socket %i to %08x, errno=%i. Not " \
			       "using src_vipa for this socket.", \
			       sockfd,,src_addr.sin<-_addr.s_addr, \
			       errno); \
 */

void bind_check(int ver, int sockfd, struct sv_entry *entry)
{
	struct sockaddr_storage src_addr;
	int result;

	if (entry) {
		src_addr = entry->policy.policy_get_src(sockfd,entry);
		switch (ver) {
		case AF_INET:
			src_addr.ss_family = AF_INET;
			if (((struct sockaddr_in *)&src_addr)->sin_addr.s_addr == INADDR_ANY)
				return;
			((struct sockaddr_in *)&src_addr)->sin_port = htons(0);
			break;
		case AF_INET6:
			src_addr.ss_family = AF_INET6;
			if (!memcmp(&((struct sockaddr_in6 *)&src_addr)->sin6_addr,
				&in6addr_any,sizeof(struct in6_addr)))
				return;
			((struct sockaddr_in6 *)&src_addr)->sin6_port = htons(0);
			break;
		}
		result = (*orig_bind)(sockfd,(struct sockaddr *)&src_addr,sizeof(src_addr));
		if (result) {
			syslog(LOG_NOTICE,"was not able to bind "
			"socket %i, errno=%i. Not "
			"using src_vipa for this socket.",
			sockfd, errno);
		}
	}
}

void add_sv_entry(struct sv_entry *sv_entry,int line_no,int sv_count)
{
   	struct sv_entry *entry;
      	dt_mask_entry_t *dm;

	entry = (struct sv_entry *)malloc(sizeof(struct sv_entry));
	if (!entry) {
		syslog(LOG_WARNING,"no memory for storing configuration " \
		       "in memory, source in line %i might not be used\n",
		       line_no);
		return;
	}
	memcpy(entry, sv_entry, sizeof(struct sv_entry));

	/*
	 * Add to the dest_table
	 */
	dm = dest_table.dt_dm[entry->netmask_len];
	if (!dm) {
		dm = (dt_mask_entry_t *)malloc(sizeof(dt_mask_entry_t));
		if (!dm) {
			syslog(LOG_WARNING,"no memory for storing " \
			       "configuration in memory, source in " \
			       "line %i might not be used\n",
			       line_no);
			free(entry);
			return;
		}
		bzero(dm, sizeof(*dm));
		dest_table.dt_dm[entry->netmask_len] = dm;
		dm->dm_nlen = entry->netmask_len;
	}

	/*
	 * Add the mask entry to the begining of the list in dest_table
	 * for faster lookups.
	 */
	if (dest_table.dt_first_dm) {
		if(dest_table.dt_first_dm->dm_nlen < entry->netmask_len){
			dm->dm_next = dest_table.dt_first_dm;
			dest_table.dt_first_dm = dm;
		} else if (dest_table.dt_first_dm->dm_nlen !=
			   entry->netmask_len) {
			dt_mask_entry_t *dmt2 =
				dest_table.dt_first_dm->dm_next;
			dt_mask_entry_t *dmt1 =
				dest_table.dt_first_dm;
			while(dmt2 && (dmt2->dm_nlen > entry->netmask_len)) {
				dmt1 = dmt2;
				dmt2     = dmt2->dm_next;
			}
			if (!dmt2 || (dmt2->dm_nlen != dm->dm_nlen)) {
				dmt1->dm_next = dm;
				dm->dm_next = dmt2;
			}
		}
	} else {
		dest_table.dt_first_dm = dm;
	}

	/*
	 * Add to the hash table
	 */
	add_to_hash_table(entry, dm);

	/* setup policy for entry */
	if (entry->policy.policy_setup)
		entry->policy.policy_setup(entry, sv_count);

#ifdef LC_TEST
	if (!first_sv_entry && (entry->policy.policy_type == POLICY_LOCAL_LC))
		first_sv_entry = entry;
#endif

	return;
}

/*
unsigned int dm_hash_val(u_int32_t s,int masklen)
{
	unsigned int i = (s >> (32 - masklen));

	i ^= i >> 20;
	i ^= i >> 10;
	i ^= i >> 5;

	i &= (DT_HASH_SIZE - 1);

	return i;
}
*/

unsigned int dm_hash_val(struct sockaddr_storage *s, int masklen)
{
	struct sockaddr_storage var;
	
	memcpy(&var,s,sizeof(struct sockaddr_storage));
	return (s->ss_family == AF_INET)
		? dm_hash_val_ip4(&(((struct sockaddr_in *)&var)->sin_addr), masklen)
		: dm_hash_val_ip6(&(((struct sockaddr_in6 *)&var)->sin6_addr), masklen);
}

unsigned int dm_hash_val_ip4(void *ps, int masklen)
{
	u_int32_t *s = (u_int32_t *)ps;
	unsigned int i = (ntohl(s[0]) >> (32 - masklen));

	masklen -= 5;
	i ^= i >> masklen;
	while (masklen > 0) {
		i ^= i >> masklen;
		masklen -= 5;
	}
	i &= (DT_HASH_SIZE - 1);

	return i;
}

unsigned int dm_hash_val_ip6(void *ps, int masklen)
{
	unsigned char *s = (unsigned char *)ps;
	unsigned int result = 0;
	unsigned int tmp_crc = 0;
	unsigned int len = sizeof(struct in6_addr);
	int i = masklen/(sizeof(char)*8);
	int maskbits = masklen%(sizeof(char)*8);
	unsigned char mask;

	if (maskbits) {
		mask = 0xff << (sizeof(char) * 8 - maskbits);
		s[i] &= mask;
		i++; 
	}
	while (i < sizeof(struct in6_addr)) {
		s[i] = 0;
		i++;
	}

	while (len--) {
		tmp_crc = tab_crc32[(unsigned char )(tmp_crc) ^ *s++] ^ tmp_crc >> 8;
		tmp_crc ^= coef_crc32;
	}
	result = tmp_crc;
	result &= (DT_HASH_SIZE - 1);

	return result;
}

void add_to_hash_table(struct sv_entry *entry,dt_mask_entry_t *dm)
{
   	dm_hash_entry_t *dm_hash;
      	int hash = dm_hash_val(&entry->dest, entry->netmask_len);

	dm_hash = &dm->dm_dh[hash];

	/*
	 * Adding to the head of the list. Could check for duplicates?
	 */

	entry->next = (struct sv_entry *)dm_hash->dh_entry;
	dm_hash->dh_entry = entry;
	dm_hash->dh_count++;
}

/*
 * Lookup the entry table
 */
static struct sv_entry *get_src_ip_entry(struct sockaddr_storage *dest)
{
	struct sv_entry *entry;
	dt_mask_entry_t *dm = dest_table.dt_first_dm;
	dm_hash_entry_t *dh;
	int hash;

	for (; dm; dm = dm->dm_next) {
		hash = dm_hash_val(dest, dm->dm_nlen);
		dh = &dm->dm_dh[hash];
		entry = dh->dh_entry;
		for (; entry; entry = entry->next) {
			if (!addrcmp(&(entry->dest),dest,entry->netmask_len))
				return entry;
		}
	}

	return NULL; /* no action (i.e. no bind) will be taken */
}

int emergency_socket(int domain,int type,int protocol)
{errno=EINVAL; return -1;}
int socket(int domain,int type,int protocol)
{
	int result;

	if (!dl_handle)
		initialize();
	result=(*orig_socket)(domain,type,protocol);
	if (((domain==PF_INET)||(domain==PF_INET6))&&(result>=0)) {
		(void)set_socket_state(result,1);
	}
	return result;
}

/*
 * A program will not issue two binds. If it does it must be returned
 * an error - the same as it would receive if this
 * library was not there.
 */
int emergency_bind(int sockfd,const struct sockaddr *my_addr,socklen_t addrlen)
{errno=EINVAL; return -1;}
int bind(int sockfd,const struct sockaddr *my_addr,socklen_t addrlen)
{
	int result;
	sfp_entry_t *entry;
	int was_inaddr_any=0;
	struct sockaddr_storage tmp;
	
	/* if socket is uninteresting, we'll leave it as is */
	if ((my_addr->sa_family != AF_INET) && (my_addr->sa_family != AF_INET6))
		return (*orig_bind)(sockfd, my_addr, addrlen);

	if (my_addr->sa_family == AF_INET){
		/* is addr INADDR_ANY? */
		if (((struct sockaddr_in*)my_addr)->sin_addr.s_addr == htonl(INADDR_ANY)) {
			was_inaddr_any = 1;
			/* should we bind the socket in our way? */
			entry=&source_for_port[((struct sockaddr_in*)my_addr)->sin_port];
			if (entry->no_sources) {
				tmp = entry->policy.policy_get_src(sockfd,entry);
				((struct sockaddr_in*)my_addr)->sin_addr.s_addr =
				((struct sockaddr_in*)(&tmp))->sin_addr.s_addr;
			}
		}
	} else if (my_addr->sa_family == AF_INET6) {
		/* is addr INADDR_ANY? */
		if (!memcmp(&(((struct sockaddr_in6*)my_addr)->sin6_addr),
			&in6addr_any, sizeof(struct in6_addr))) {
			was_inaddr_any = 1;
			/* should we bind the socket in our way? */
			entry=&source_for_port[((struct sockaddr_in6*)my_addr)->sin6_port];
			if (entry->no_sources) {
				tmp = entry->policy.policy_get_src(sockfd,entry);
				memcpy(&(((struct sockaddr_in6*)my_addr)->sin6_addr.s6_addr),
						&(((struct sockaddr_in6*)&tmp)->sin6_addr.s6_addr),
						sizeof(struct in6_addr));
			}
		}
	}

	if (!dl_handle)
		initialize();
	result=(*orig_bind)(sockfd,my_addr,addrlen);
	if (result) {
		/*
		 * Not close but just the policy cleanup
		 */
		close_cleanup(sockfd,ISBOUND_CLOSE);

		if (was_inaddr_any) {
			/*
			 * retry INADDR_ANY bind
			 */
			if (my_addr->sa_family == AF_INET)
				((struct sockaddr_in *)my_addr)->sin_addr.s_addr =
					htonl(INADDR_ANY);
			else ((struct sockaddr_in6 *)my_addr)->sin6_addr =
				in6addr_any;
			result=(*orig_bind)(sockfd, (struct sockaddr *)my_addr, addrlen);
		}
	}

	return result;
}

/*
 * If a bind has already been called we will not bind but otherwise
 * to ensure the use of source address based on the specified policy
 * we bind before calling connect().
 */
int emergency_connect(int sockfd,const struct sockaddr *serv_addr,
		      socklen_t addrlen) {errno=EINVAL; return -1;}
int connect(int sockfd,const struct sockaddr *serv_addr,socklen_t addrlen)
{
	int result;
	struct sv_entry *entry;

	if (!dl_handle)
		initialize();
	if ((serv_addr->sa_family == AF_INET) || (serv_addr->sa_family == AF_INET6)){
	    entry = get_src_ip_entry((struct sockaddr_storage *)serv_addr);
		bind_check(serv_addr->sa_family,sockfd,entry);
	    result=(*orig_connect)(sockfd,serv_addr,addrlen);
		if (result) {
			close_cleanup(sockfd,ISBOUND_CLOSE);
		}
	} else {
		result=(*orig_connect)(sockfd,serv_addr,addrlen);
	}
	goto out; /* suppress warning and leave label out in,
		     for other variation in WE_MAY_HAVE_TO_BIND */
out:
	return result;
}

/*
 * Issue: We bind here to ensure the source selected is in
 * conformance with the policy indicated. But, what if the application
 * does a bind() now? It will fail since we bind here.
 */
ssize_t emergency_sendto(int sockfd,const void *msg,size_t len,int flags,
    			 const struct sockaddr *to,socklen_t tolen)
{errno=EINVAL; return -1;}
ssize_t sendto(int sockfd,const void *msg,size_t len,int flags,
	   const struct sockaddr *to,socklen_t tolen)
{
	ssize_t result;
	struct sv_entry *entry;

	if (!dl_handle)
		initialize();
	if (((to->sa_family == AF_INET) || (to->sa_family == AF_INET6))
		&& !is_it_bound(sockfd,1)){
	    entry=get_src_ip_entry((struct sockaddr_storage*)to);
		bind_check(to->sa_family,sockfd,entry);
	    result=(*orig_sendto)(sockfd,msg,len,flags,to,tolen);
	} else {
		result = (*orig_sendto)(sockfd,msg,len,flags,to,tolen);
	}
	goto out; /* suppress warning and leave label out in,
		     for other variation in WE_MAY_HAVE_TO_BIND */
out:
	return result;
}

/*
 * The sendmsg call might be made at anytime. If the socket is not
 * bound an address will be chosen -- therefore, we assign the address
 * as dictated by the policy. This implies a bind. What if the user
 * program, then issues a bind?
 */
ssize_t emergency_sendmsg(int sockfd,const struct msghdr *msg,int flags)
{errno=EINVAL; return -1;}
ssize_t sendmsg(int sockfd,const struct msghdr *msg,int flags)
{
	ssize_t result;
	struct sv_entry *entry=NULL;
	struct sockaddr_storage  *dst_addr = NULL;

	if (!dl_handle)
		initialize();

	if (msg->msg_name)
		dst_addr = (struct sockaddr_storage *)msg->msg_name;

    if (dst_addr && (!is_it_bound(sockfd,1)) &&
        ((dst_addr->ss_family == AF_INET) || (dst_addr->ss_family == AF_INET6))){
		entry = get_src_ip_entry((struct sockaddr_storage *)dst_addr);
		bind_check(dst_addr->ss_family,sockfd,entry);
		result=(*orig_sendmsg)(sockfd,msg,flags);
	} else {
		result=(*orig_sendmsg)(sockfd,msg,flags);
	}
	goto out; /* suppress warning and leave label out in,
		     for other variation in WE_MAY_HAVE_TO_BIND */
out:
	return result;
}

int emergency_shutdown(int s,int how) {errno=EINVAL; return -1;}
int shutdown(int s,int how)
{
	int result,bl;

	if (!dl_handle)
		initialize();
	result=(*orig_shutdown)(s,how);

	if (how == SHUT_RD)
		bl = ISBOUND_RD;
	else if (how == SHUT_WR)
		bl = ISBOUND_WR;
	else if (how == SHUT_RDWR)
		bl = ISBOUND_CLOSE;

	close_cleanup(s,bl);

	return result;
}

int emergency_close(int fd) {errno=EINVAL; return -1;}
int close(int fd)
{
	int result;
	if (!dl_handle)
		initialize();
	result=(*orig_close)(fd);
	close_cleanup(fd,ISBOUND_CLOSE);
	return result;
}

static void open_syslog(void)
{
	openlog(version,LOG_NDELAY|LOG_PID,LOG_FACILITY);
}

#ifndef LC_TEST
static void bend_functions(void)
{
	dl_handle=NULL;

	dl_handle=dlopen(LIBC_PATH,DLOPEN_FLAG);
	if (!dl_handle) {
		syslog(LOG_WARNING,"dlopen failed: %s\n",dlerror());
	}
	GET_FUNC(socket);
	GET_FUNC(bind);
	GET_FUNC(connect);
	GET_FUNC(sendto);
	GET_FUNC(sendmsg);
	GET_FUNC(shutdown);
	GET_FUNC(close);
}
#endif

/* ports are sanity-checked already */
static void add_sfp_entry(sfp_entry_t *entry,int from_port,int to_port)
{
	int i;

	for (i=from_port;i<=to_port;i++) {
		memcpy(&source_for_port[htons(i)],entry,sizeof(sfp_entry_t));
	}
}

static int get_next_word(char **line_ptr,char *next_word)
{
	int word_found = 0;
	while ((**line_ptr) && (**line_ptr!=' ') && (**line_ptr!='\t') &&
	       (**line_ptr!='\n'))  {
		if(!word_found)
			word_found=1;
		*next_word=**line_ptr;
		next_word++;
		(*line_ptr)++;
	}
	*next_word=0;

	while ((**line_ptr) && ((**line_ptr==' ') || (**line_ptr=='\t')))  {
		(*line_ptr)++;
	}
	return word_found;
}

void add_list_item(int id,void *addr)
{
	shm_list_t *entry;

	entry=(shm_list_t*)malloc(sizeof(shm_list_t));
	if (!entry) {
		syslog(LOG_WARNING,"not enough memory to store shm " \
		       "information, id %i might not be removed\n",id);
		return;
	}
	entry->id=id;
	entry->addr=addr;
	entry->next=shm_list;
	shm_list=entry;
}

static void read_config_file(void)
{
	FILE *f;
	int rc;
	char *name;
	char line[LINE_LEN];
	char *line_ptr;
	char line2[LINE_LEN];
	char next_word[LINE_LEN];
	char s[LINE_LEN];
	struct sv_entry sv_entry;
	sfp_entry_t sfp_entry;
	struct policy policy;
	int from_port,to_port;
	int i1,i2;
	int line_no=0;
	struct hostent *host;
	int i;
	int inaddr_any_occurred;
	int perms,id; /* used for rr */
	key_t key;
	struct in_addr src_arr4[MAX_SOURCES_PER_DEST];
	struct in6_addr src_arr6[MAX_SOURCES_PER_DEST];
	int count_src4, count_src6;
	int ip_ver;
	struct addr_item *first_v4, *first_v6, *cur;

	init_crc32();

	f=NULL;
	name=getenv(CONFIG_FILE_ENV);
	if (name) {
		f=fopen(name,"r");
	}
	/* use default file, if the above failed or CONFIG_FILE_ENV
	 * was not set */
	if (!f) {
		f=fopen(DEFAULT_CONFIG_FILE,"r");
		name=NULL; /* to make key generation use the default
			      config file path */
	}
	if (!f) return;

next_line:
	while (fgets(line,sizeof(line),f)!=NULL) {
		line_no++;
		if (line[0]==0) continue;
		if (line[0]=='\n') continue;
		if (line[0]=='#') continue;
		rc=sscanf(line,"%s",line2);
		if (rc==EOF) continue;

#define ____INVALIDENTRY do { \
	syslog(LOG_NOTICE,"invalid entry in config file, line %i",line_no); \
	goto next_line; \
} while (0)

		/* make sure that we don't go beyond end of line */
		line[LINE_LEN-1]=0;
		line_ptr=line;
		inaddr_any_occurred=0;
		first_v4 = NULL;
		first_v6 = NULL;

		/* destination address or .INADDR_ANY */
		get_next_word(&line_ptr,next_word);
		if (!strcmp(next_word,".INADDR_ANY")) {
			inaddr_any_occurred=1;
		} else if (2 == sscanf(next_word,"%[0-9a-z_A-Z._-:]/%u",s,&i1)) {
			if ((host = gethostbyname2(s,AF_INET)))
				first_v4 = read_host_names(host);
			if ((host = gethostbyname2(s,AF_INET6))){
				first_v6 = read_host_names(host);
			}
			if ((first_v4 == NULL) && (first_v6 == NULL)){
				____INVALIDENTRY;
			}
			sv_entry.netmask_len=(short)i1;
		} else {
			____INVALIDENTRY;
		}

		/* if .INADDR_ANY: port range */
		if (inaddr_any_occurred) {
			get_next_word(&line_ptr,next_word);
			if (2==sscanf(next_word,"%u-%u",&i1,&i2)) {
				from_port=i1;
				to_port=i2;
				if ( (from_port>MAX_PORTNO) ||
				     (to_port>MAX_PORTNO) ||
				     (from_port>to_port) ) {
					syslog(LOG_NOTICE,"config file, line" \
					" %i: Invalid port number specified",
					line_no);
					____INVALIDENTRY;
				}
			} else if (1==sscanf(next_word,"%u",&i1)) {
				from_port=to_port=i1;
				if (from_port>MAX_PORTNO) {
					syslog(LOG_NOTICE,"config file, line" \
					" %i: Invalid port number specified",
					line_no);
					____INVALIDENTRY;
				}
			} else {
				____INVALIDENTRY;
			}
		}

		/* strategy, if available */
		get_next_word(&line_ptr,next_word);
		if (!strcmp(next_word,"random")) {
			policy.policy_type=POLICY_RANDOM;
		} else if (!strncmp(next_word,"rr:",3)) {
			policy.policy_type=POLICY_RR;
			/* generate key from filename + line number */
			key=ftok((name)?name:DEFAULT_CONFIG_FILE,line_no);
			/* read permissions */
			if ( (next_word[3]<'0' || next_word[3]>'7') ||
			     (next_word[4]<'0' || next_word[4]>'7') ||
			     (next_word[5]<'0' || next_word[5]>'7') ) {
				____INVALIDENTRY;
			}
			perms=((next_word[3]-'0')<<6)
				+((next_word[4]-'0')<<3)
				+((next_word[5]-'0'));
			/* get the memory */
			id=shmget(key,RR_SHM_SIZE,perms|IPC_CREAT);
			if (id==-1) {
				____INVALIDENTRY;
			}
			policy.policy_data.round_robin.addr=shmat(id,NULL,0);
			if (policy.policy_data.round_robin.addr==(void*)-1) {
				 if (-1==shmctl(id, IPC_RMID, NULL)) {
					 syslog(LOG_WARNING,"was not able " \
						"to cleanup shm id %i\n",id);
				 }
				____INVALIDENTRY;
			}
			add_list_item(id,policy.policy_data.round_robin.addr);
		} else  if (!strcmp(next_word,"lrr")) {
			policy.policy_type=POLICY_LOCAL_RR;
		} else  if (!strcmp(next_word,"lc")) {
			policy.policy_type=POLICY_LOCAL_LC;
		} else  if (!strcmp(next_word,"onevipa")) {
			policy.policy_type=POLICY_ONEVIPA;
		} else { /* default (no policy specified) is random */
			syslog(LOG_WARNING,"No policy specified in line " \
			       "%i, using random as method.",line_no);
			policy.policy_type=POLICY_RANDOM;
		}

	 	/*
	      	 * Set policy pointers
		 */
		switch (policy.policy_type) {
		case POLICY_LOCAL_LC:
		       	policy.policy_setup = policy_lc_setup;
			policy.policy_reset = policy_lc_reset_source;
			policy.policy_get_src = policy_lc_get_src;
			break;

		case POLICY_RR:
			policy.policy_setup = policy_rr_setup;
			policy.policy_reset = NULL;
			policy.policy_get_src = get_source_by_policy;
			break;

		case POLICY_LOCAL_RR:
			policy.policy_setup = policy_lrr_setup;
			policy.policy_reset = NULL;
			policy.policy_get_src = get_source_by_policy;
			break;

		case POLICY_ONEVIPA:
			policy.policy_setup = NULL;
			policy.policy_reset = NULL;
			policy.policy_get_src = get_source_by_policy;
			break;

		case POLICY_RANDOM:
		default:
		    	policy.policy_setup = policy_random_setup;
		     	policy.policy_reset = NULL;
		      	policy.policy_get_src = get_source_by_policy;
			break;
		}

		/* source ip addresses */
		count_src4 = 0;
		count_src6 = 0;
		memset(src_arr4,0,sizeof(src_arr4));
		memset(src_arr6,0,sizeof(src_arr6));

get_next_source:
	if (get_next_word(&line_ptr,next_word)) {
		if ((count_src4 >= MAX_SOURCES_PER_DEST)||
			(count_src6 >= MAX_SOURCES_PER_DEST)) {
			syslog(LOG_NOTICE,"config file, line %i: " \
			"Specified too many source addresses. "\
			"Only %i source addresses are allowed!",
			line_no,MAX_SOURCES_PER_DEST);
			____INVALIDENTRY;
		}
		if (1 == sscanf(next_word,"%[0-9a-z_A-Z._-:]",s)) {
			if ((host = gethostbyname2(s,AF_INET))) {
				src_arr4[count_src4] =
					*(struct in_addr *)host->h_addr_list[0];
				count_src4++;
			}
			if ((host = gethostbyname2(s,AF_INET6))) {
				src_arr6[count_src6] =
					*(struct in6_addr *)host->h_addr_list[0];
				count_src6++;
			}
	} else {
		____INVALIDENTRY;
	}
	goto get_next_source;
	} else {
		/* add entry */
		if ((!count_src4) && (!count_src6)) {
			____INVALIDENTRY;
		}
		if (inaddr_any_occurred) {
		/* IPv4-entry is preferred than IPv6_entry.
		It helps to keep over old config useable.*/
			(count_src4) ? (ip_ver = AF_INET)
						 : (ip_ver = AF_INET6);
							 
			for (i=0; i< MAX_SOURCES_PER_DEST; i++) {
				if (ip_ver == AF_INET)
					((struct sockaddr_in *)&(sfp_entry.src[i]))
										->sin_addr = src_arr4[i];
				if (ip_ver == AF_INET6)((struct sockaddr_in6 *)&(sfp_entry.src[i]))
										->sin6_addr = src_arr6[i];
			}

			memcpy(&sfp_entry.policy,&policy, sizeof(struct policy));
			add_sfp_entry(&sfp_entry,from_port,to_port);
		} else {
			/* IPv4-entry is preferred than IPv6_entry.
			It helps to keep over old config useable.*/
			((first_v4 != NULL) && count_src4)	? (ip_ver = AF_INET)
												: (ip_ver = AF_INET6);
			memcpy(&sv_entry.policy,&policy,sizeof(struct policy));
			if (ip_ver == AF_INET) {
				sv_entry.no_sources = count_src4;
				cur = first_v4;
			} else {
				sv_entry.no_sources = count_src6;
				cur = first_v6;
			}
			for (i=0; i < MAX_SOURCES_PER_DEST; i++) {
				if (ip_ver == AF_INET)
					((struct sockaddr_in *)&(sv_entry.src[i]))->sin_addr =
						src_arr4[i];
				if (ip_ver == AF_INET6)
					((struct sockaddr_in6 *)&(sv_entry.src[i]))->sin6_addr =
						src_arr6[i];
			}

			while(cur != NULL){
				if (ip_ver == AF_INET) {
					((struct sockaddr_in *)&(sv_entry.dest))->sin_addr =
							((struct sockaddr_in *)&(cur->addr))->sin_addr ;
					sv_entry.dest.ss_family = AF_INET;
				}
				if (ip_ver == AF_INET6) {
					((struct sockaddr_in6 *)&(sv_entry.dest))->sin6_addr =
							((struct sockaddr_in6 *)&(cur->addr))->sin6_addr ;
					sv_entry.dest.ss_family = AF_INET6;
				}
				(ip_ver == AF_INET) ? add_sv_entry(&sv_entry,line_no,count_src4)
									: add_sv_entry(&sv_entry,line_no,count_src6);
				cur = cur->next;	
			}
			erase_addr_list(first_v4);
			erase_addr_list(first_v6);
		}
	}
	}	
	fclose(f);
}

void destroy_shm(void)
{
	int r1,r2;
	shm_list_t *entry;

	while (shm_list) {
		entry=shm_list;
		r1=shmdt(entry->addr);
		if ((!r1) && (leader_pid == getpid())) {
			r2=shmctl(entry->id,IPC_RMID,NULL);
		} else r2=0;
		if ((r1==-1)||(r2==-1)) {
			syslog(LOG_WARNING,"was not able " \
	       		       "to cleanup shm id %i\n",entry->id);
		}
		shm_list=shm_list->next;
		free(entry);
	}
}

#ifndef LC_TEST
void
__attribute ((constructor))
src_vipa_init(void)
{
	if (!dl_handle)
		initialize();
}

void
__attribute ((destructor))
src_vipa_fini(void)
{
	finalize();
}

void initialize(void)
{
	leader_pid = getpid();
	init_mutexes();
	open_syslog();
	bend_functions();
	bzero(&dest_table, sizeof(dest_table));
	read_config_file();
}

void finalize(void)
{
	if (dl_handle) dlclose(dl_handle);
	destroy_shm();
	closelog();
	destroy_mutexes();
}
#endif

/* ================= policy stuff ================================= */

/*
 * Policy functions for RANDOM
 */
void policy_random_setup(struct sv_entry *entry,int sv_count)
{
	struct timeval tod;    /* tmp var to compute random seed */
	struct timezone tzone; /* tmp var to compute random seed */

	/* generate random index to start round robin method */
	gettimeofday(&tod,&tzone);
	srand((unsigned int) tod.tv_usec);
}

/*
 * Policy functions for RR
 */
void policy_rr_setup(struct sv_entry *entry,int sv_count)
{
	struct policy *policy = &entry->policy;
	struct timeval tod;    /* tmp var to compute random seed */
	struct timezone tzone; /* tmp var to compute random seed */
	
	if (*((unsigned int*)policy->policy_data.round_robin.addr)>=
	    sv_count) {
		/* if start value out of range, generate a random one --
		 * setting start always to 0 could lead to an uneven
		 * distribution in scenarios, where src_vipa is started
		 * and exited sequentially */
		gettimeofday(&tod,&tzone);
		srand((unsigned int) tod.tv_usec);
		policy->policy_data.local_round_robin.idx=myrand() % sv_count;
		*((unsigned int*)policy->policy_data.round_robin.addr)=
			myrand() % sv_count;
	}
}

/*
 * Policy functions for LOCAL_RR
 */
void policy_lrr_setup(struct sv_entry *entry,int sv_count)
{
	struct policy *policy = &entry->policy;
	struct timeval tod;    /* tmp var to compute random seed */
	struct timezone tzone; /* tmp var to compute random seed */

	/* generate random index to start round robin method */
	gettimeofday(&tod,&tzone);
	srand((unsigned int) tod.tv_usec);
	policy->policy_data.local_round_robin.idx=myrand() % sv_count;
}

/*
 * Policy function for LC
 */
void policy_lc_setup(struct sv_entry *entry,int sv_count)
{
	struct policy *policy = &entry->policy;

	bzero(&policy->policy_data.local_lc, sizeof(struct lc_data));

	pthread_mutex_init(&policy->policy_data.local_lc.lc_lock, NULL);
}

struct sockaddr_storage
policy_lc_get_src(int sockfd, struct sv_entry *entry)
{
    	struct policy            *policy = &entry->policy;
       	struct lc_val            *lc;
	struct lc_head           *lchead;
	struct lc_data           *lcp;

	int i = 0, ret = -1;

	/*
	 * If there are source addresses that we have not considered as yet
	 * use them first.
	 */
	LOCKIT(&policy->policy_data.local_lc.lc_lock);

	lcp = &policy->policy_data.local_lc;
	if(entry->no_sources-
	   policy->policy_data.local_lc.lc_tbd_sources_count) {
		lc = (struct lc_val *)malloc(sizeof(struct lc_val));
		/*
		 * Now include it in the lc list
		 */
		if (lc) {
			lc->head = NULL;
			lc->next = lc->prev = NULL;

			i = policy->policy_data.local_lc.lc_tbd_sources_index;
			policy->policy_data.local_lc.lc_tbd_sources_count++;
			policy->policy_data.local_lc.lc_tbd_sources_index++;
			lc->count = 1;
			lc->source_idx = i;
			lchead = lc_policy_insert_source(lcp,
							 lcp->lc_head, lc);
			if (!lchead) {
				free(lc);
				syslog(LOG_WARNING,"was not able to "
				       "allocate memory for "\
			       	       "policy least count " \
				       "(fd=%i)",sockfd);

				       i = 0;
				       goto existing_sources;
			} else if (lchead != lcp->lc_head) {
				if (lcp->lc_head)
					lchead->next = lcp->lc_head->next;
				if (lchead->next)
					lchead->next->prev = lchead;
				lchead->prev = (struct lc_head *)lcp;
				lcp->lc_head = lchead;
			}

			UNLOCKIT(&lcp->lc_lock);

			ret  = insert_socket_policy_info(sockfd, i,
							 entry, (void *)lc);
			if (ret == i)
				return entry->src[i];
			else
				goto undo_lc;
		} else {
			syslog(LOG_WARNING,"was not able to allocate " \
			       "memory for policy" \
			       "least count (fd=%i)",sockfd);
			i = 0;
		}
	}

existing_sources:
	/*
	 * We need to pick the least loaded source from the source list.
	 * At the same time we need to update the list with the new count.
	 */
	lchead = policy->policy_data.local_lc.lc_head;
	if (!lchead) {
		/*
		 * no tbd sources and no head. implies no sources really ??
		 */
		syslog(LOG_WARNING,"No source list to implement policy" \
		       "least count (fd=%i)",sockfd);
	      	UNLOCKIT(&policy->policy_data.local_lc.lc_lock);
		struct sockaddr_storage tmp;
		switch (entry->src[i].ss_family) {
		case AF_INET:
			((struct sockaddr_in*)&tmp)->sin_addr.s_addr = INADDR_ANY;
			break;
		case AF_INET6:
			((struct sockaddr_in6*)&tmp)->sin6_addr = in6addr_any;
			break;
		}
	return tmp;
	}
	lc = lchead->list;
	i = lc->source_idx;
	lc->count++;
	(void)lc_policy_update_head(lcp, lcp->lc_head, lc);

	UNLOCKIT(&policy->policy_data.local_lc.lc_lock);

	ret = insert_socket_policy_info(sockfd, i, entry, (void *)lc);
	if (ret == i)
		return entry->src[i];

undo_lc:
	close_cleanup(sockfd,ISBOUND_CLOSE);
	struct sockaddr_storage tmp;
	switch (entry->src[i].ss_family) {
	case AF_INET:
		((struct sockaddr_in*)&tmp)->sin_addr.s_addr = INADDR_ANY;
		break;
	case AF_INET6:
		((struct sockaddr_in6*)&tmp)->sin6_addr = in6addr_any;
		break;
	}
	return tmp;
}

struct lc_head *lc_policy_update_head(struct lc_data *lcp,
	       			      struct lc_head *lchead,
				      struct lc_val *lcptr)
{
   	struct lc_head *rethead = lchead;

	if ((!lchead->num == 1) && (lchead->next->count > lcptr->count)) {
		lchead->count = lcptr->count;
		return lchead;
	}

	lchead = lc_policy_remove_source(lcp,  lcptr);
	rethead = lc_policy_insert_source(lcp, lchead, lcptr);
	if (!rethead) {
		/* put lc back. Not keeping count.*/
		syslog(LOG_WARNING,"Could not allocate memory. Not " \
		       "keeping count." \
		       "May cause least-count imbalance");

		lcptr->count--;
		lchead->num++;
		lcptr->next = lchead->list->next;
		lcptr->prev = (struct lc_val *)lchead;
		lcptr->next->prev = lcptr;
	}
	return rethead;
}


struct lc_head *lc_policy_insert_source(struct lc_data *lcp,
					struct lc_head *lchead,
					struct lc_val *lcptr)
{
	struct lc_head *rethead;

	if (!lchead) {
		lchead = lcp->lc_freehead;
		if (!lchead) {
			lchead = (struct lc_head *)malloc
				(sizeof(struct lc_head));
			if (!lchead)
				return NULL;
			else
				bzero(lchead, sizeof(*lchead));
		} else
			lcp->lc_freehead = lchead->next;

		lchead->count = lcptr->count;
		lchead->num = 0;
		lchead->next = lchead->prev = NULL;
		lchead->list = NULL;
	}

	if (lchead->count > lcptr->count) {
		rethead = lc_policy_insert_source(lcp, NULL, lcptr);
		if (rethead !=lchead){
			rethead->prev = lchead->prev;
			if (lchead->prev)
				lchead->prev->next = rethead;
			rethead->next = lchead;
			lchead->prev = rethead;

			lchead = rethead;
		}
	} else if (lchead->count == lcptr->count) {
		lcptr->next = lchead->list;
		if (lchead->list)
			lchead->list->prev = lcptr;
		lcptr->head = lchead;
		lchead->list = lcptr;
		lcptr->prev = (struct lc_val *)lchead;
		lchead->num++;

	} else if (lchead->count < lcptr->count) {
		rethead = lc_policy_insert_source(lcp, lchead->next, lcptr);
		if (lchead->next != rethead){
			rethead->next = lchead->next;
			if (lchead->next)
				lchead->next->prev = rethead;
			rethead->prev = lchead;
			lchead->next = rethead;
		} else if (!rethead)
		       	lchead = NULL;
	}

	return lchead;
}

void close_cleanup(int fd,int bindlevel)
{
    	struct socket_policy_info *sinfo;

	sinfo = remove_socket_policy_info(fd, 1, bindlevel);
	if (!sinfo)
		return;

	if (sinfo->src_idx != -1) {
		if (sinfo->entry->policy.policy_reset)
			sinfo->entry->policy.policy_reset(sinfo);
	}

	free(sinfo);
	return;
}

void policy_lc_reset_source(struct socket_policy_info *sinfo)
{
    	struct policy *policy = &sinfo->entry->policy;
       	struct lc_val *lcval  = (struct lc_val *)sinfo->pdata;
	struct lc_head *lchead = NULL;

	LOCKIT(&policy->policy_data.local_lc.lc_lock);

	lcval->count--;

	lchead = lc_policy_remove_source
		(&policy->policy_data.local_lc,lcval);
	lc_policy_insert_source(&policy->policy_data.local_lc,lchead, lcval);

	UNLOCKIT(&policy->policy_data.local_lc.lc_lock);
}


struct lc_head *lc_policy_remove_source(struct lc_data *lcp,
					struct lc_val *lcval)
{
    	struct lc_head *ret;

	if (lcval->prev)
		lcval->prev->next = lcval->next;

	if (lcval->next)
		lcval->next->prev = lcval->prev;

	ret = lcval->head;
	ret->num--;

	if (ret->prev != (struct lc_head *)lcp)
		ret = ret->prev;

	if (0 == lcval->head->num) {
		lcval->head->prev->next = lcval->head->next;
		if (lcval->head->next)
			lcval->head->next->prev = lcval->head->prev;

		if (lcval->head->prev == (struct lc_head *)lcp)
			ret = lcval->head->next;

		lcval->head->next = lcp->lc_freehead;
		lcp->lc_freehead = lcval->head;
	}

	lcval->next = lcval->prev = NULL;
	lcval->head = NULL;

	return ret;

}

struct sockaddr_storage get_source_by_policy(int sockfd, struct sv_entry *entry)
{
   	int i, ret;
      	struct policy *policy = &entry->policy;
	int no_sources = entry->no_sources;

	if (policy->policy_type==POLICY_RANDOM) {
		i = myrand() % no_sources;
	} else if (policy->policy_type==POLICY_ONEVIPA) {
		/* direct return here, for performance reasons */
		return entry->src[0];
	} else if (policy->policy_type==POLICY_RR) {
		i=atomic_inc_and_wrap_and_return
			(policy->policy_data.round_robin.addr,no_sources);
	} else if (policy->policy_type==POLICY_LOCAL_RR) {
		i=atomic_inc_pid_and_wrap_and_return
			(&policy->policy_data.local_round_robin.idx,
			 no_sources);
	} else { /* default: first address, although should never happen */
		i = 0;
	}

	/*
	 * Insert the entry into the sockfd array
	 */
	ret  = insert_socket_policy_info(sockfd, i, entry, (void *)entry );
	if (ret == i) {
		return entry->src[i];
	}
	else {
		struct sockaddr_storage tmp;
		switch (entry->src[i].ss_family) {
		case AF_INET:
			((struct sockaddr_in*)&tmp)->sin_addr.s_addr = INADDR_ANY;
			break;
		case AF_INET6:
			((struct sockaddr_in6*)&tmp)->sin6_addr = in6addr_any;
			break;
		}
		return tmp;
	}
}

int bitcmp(void *pa, void *pb, int bitlen)
{
	unsigned char *a = (unsigned char *)pa;
    unsigned char *b = (unsigned char *)pb;
    int fullbytes = bitlen / (sizeof(char) * 8);
    int maskbits = bitlen % (sizeof(char) * 8);
    unsigned char mask;
    int i;
	
	for (i = 0; i < fullbytes; i++){
           if (a[i] > b[i]) return 1;
           if (a[i] < b[i]) return -1;
    }
 	
	if(!maskbits)
		return 0;
	mask = 0xff << (sizeof(char) * 8 - maskbits);
	if ((a[i] & mask) > (b[i] & mask))
		return 1;
    if ((a[i] & mask) < (b[i] & mask))
		return -1;

	return 0;
}

int addrcmp(struct sockaddr_storage *a, struct sockaddr_storage *b, int bitlen)
{
	return (a->ss_family == AF_INET6)
		? bitcmp(&((struct sockaddr_in6 *)a)->sin6_addr,
			&((struct sockaddr_in6 *)b)->sin6_addr, bitlen)
		: bitcmp(&((struct sockaddr_in *)a)->sin_addr,
			&((struct sockaddr_in *)b)->sin_addr, bitlen);
}

struct addr_item *read_host_names(struct hostent *host)
{
	struct addr_item *first = NULL;
	struct addr_item *new = NULL;
	struct addr_item *prev = NULL;
	struct addr_item *cur = NULL;
	int i = 0;
	
	while (host->h_addr_list[i]) {
		new = new_item();
		switch (host->h_addrtype) {
		case AF_INET:
			memcpy(&(((struct sockaddr_in *)&(new->addr))->sin_addr),
				(struct in_addr *)host->h_addr_list[i],	sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(&(((struct sockaddr_in6 *)&(new->addr))->sin6_addr),
				(struct in6_addr *)host->h_addr_list[i], sizeof(struct in6_addr));
			break;
		}
		new->next = NULL;
		cur = first;
		if (prev == NULL) {
			new->next = first;
			first = new;
		} else {
			prev->next = new;
			new->next = cur;
		}
		i++;
	}	

	return first;	
}

void init_crc32(void)
{
	unsigned i,i2,i3;
    
	for (i = 0; i < 256; i++){
		for (i2 = i, i3 = 8; i3; i3--)
        	i2 = i2 & 1? (i2 >> 1) ^ CRC_POLY: i2 >> 1;
			tab_crc32[i] = i2;
	}
}

struct addr_item *new_item(void)
{
	struct addr_item *item;

	item = malloc(sizeof(struct addr_item));
	if (item == NULL) {
		syslog(LOG_WARNING,"Could not allocate memory. Not " \
			"keeping host's aliases.");
		exit(EXIT_FAILURE);
	}

	return item;
}

void erase_addr_list(struct addr_item *first_item)
{
	struct addr_item *cur_item;

	while (first_item != NULL) {
		cur_item = first_item->next;
		free(first_item);
		first_item = cur_item;
	}
}

#ifdef LC_TEST

struct sv_entry *first_sv_entry = NULL;

/***************************************************************************/
/*                                  TEST                                   */
/***************************************************************************/

/*
 * LC_TEST
 *
 * Create sockets and pseudo-connects. Seed with about 10 connections.
 * Then let the loop create/connect or close the sockets as per a
 * random setup. On the average the counts should balance out. 
 *
 * random function is determined as:
 *
 */

main(int argc, char *argv[])
{
	int i;
	int init_count;

	int k = 0;

	if (argc>1)
		init_count = atoi(argv[1]);
	else
		init_count = 8;

	init_mutexes();
	open_syslog();
	read_config_file();

	printf("first sv entry %x\n", first_sv_entry);
	for (i=0; i<init_count; i++) 
		pseudo_connect(i);

	while (1) {
		k++;
		if ((i = get_random_val()) > 0) {
			printf("CONNECT %d\n", i%59);
			pseudo_connect(i%59,k);
		}
		else{
			printf("CLOSE %d\n", i%59);
			pseudo_close(-i%59,k);
		}
	}

	destroy_shm();
	destroy_mutexes();
}

print_lc_list(int k)
{
	struct lc_head *lch = 
						first_sv_entry->policy.policy_data.local_lc.lc_head;
	struct lc_val *lcptr;

	printf("For %dth round:\n", k);
	printf("\tsources count %d sources index %d\n", 
			first_sv_entry->policy.policy_data.local_lc.lc_tbd_sources_count,
			first_sv_entry->policy.policy_data.local_lc.lc_tbd_sources_index);

	while(lch) {
		printf("\tCount %d\n",lch->count);
		lcptr = lch->list;
		while(lcptr) {
			printf("\t\t count %d source_idx %d\n", 
									lcptr->count, lcptr->source_idx);
			lcptr = lcptr->next;
		}
		lch = lch->next;
	}
	printf("*******************************************************\n");
}
			
	

 pseudo_connect(int i, int k)
 {
	first_sv_entry->policy.policy_get_src(i, first_sv_entry);
	print_lc_list(k);
 }

 pseudo_close(int i, int k)
 {
 	close_cleanup(i,ISBOUND_CLOSE);
	print_lc_list(k);
 }

 get_random_val()
 {
 	int random = rand();

	if (random % 3)
		return random;
	else
		return -random;
 }

#endif
