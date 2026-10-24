#include <stdlib.h>
#include <stdint.h>
uintptr_t main_tls,worker_tls;
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
void *blocks[12],*guards[12];
void *worker_block;
_Atomic int worker_ready,done;
__attribute__((noinline)) void checkpoint(void){__asm__ volatile("nop");}
void *worker(void *p){worker_tls=(uintptr_t)__builtin_thread_pointer();worker_block=malloc(128);void *g=malloc(32);free(worker_block);atomic_store(&worker_ready,1);while(!atomic_load(&done))sched_yield();free(g);return p;}
int main(void){main_tls=(uintptr_t)__builtin_thread_pointer();
 for(int i=0;i<12;i++){blocks[i]=malloc(i<9?64:0x600+(i-9)*0x200);guards[i]=malloc(32);}
 for(int i=0;i<12;i++)free(blocks[i]);
 void *sort=malloc(0x2000);
 pthread_t t;pthread_create(&t,0,worker,0);while(!atomic_load(&worker_ready))sched_yield();
 checkpoint();atomic_store(&done,1);pthread_join(t,0);free(sort);return 0;
}
