#include <stdio.h>  
#include <signal.h>  
#include <string.h>  
  
#include "librdkafka/rdkafka.h"  

static int run = 1;  
  
static void stop(int sig){  
    run = 0;  
    fclose(stdin);  
}  
  
/* 
    每条消息调用一次该回调函数，说明消息是传递成功(rkmessage->err == RD_KAFKA_RESP_ERR_NO_ERROR) 
    还是传递失败(rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR) 
    该回调函数由rd_kafka_poll()触发，在应用程序的线程上执行 
 */  
static void dr_msg_cb(rd_kafka_t *rk,  
                      const rd_kafka_message_t *rkmessage, void *opaque){  
        if(rkmessage->err)  
            fprintf(stderr, "%% Message delivery failed: %s\n",   
                    rd_kafka_err2str(rkmessage->err));  
        else  
            fprintf(stderr,  
                        "%% Message delivered (%zd bytes, "  
                        "partition %"PRId32")\n",  
                        rkmessage->len, rkmessage->partition);  
        /* rkmessage被librdkafka自动销毁*/  
}  