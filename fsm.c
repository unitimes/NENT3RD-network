//
// fsm.c
// FSM sample code
//
// Created by Minsuk Lee, 2014.11.1.
// Edited by Chuloh Bae, 2015.1.11.
// Copyright (c) 2014. Minsuk Lee All rights reserved.
// see LICENSE

#include "util.h"

#define CONNECT_TIMEOUT 2 

#define NUM_STATE   4
#define NUM_EVENT   8
#define NUM_SEQ     7
#define NUM_BUF     ((NUM_SEQ + 1)/2)

enum packet_type { F_FIN = 0, F_SYN = 1, F_ACK = 2, F_DATA = 3 };		// Packet Type
enum proto_state { WAIT_CON = 0,     SYN_SENT = 1,      SYN_RCVD = 2,     CONNECTED = 3 };		// States

// Events
enum proto_event { RCV_FIN = 0, RCV_SYN = 1, RCV_ACK = 2, RCV_DATA = 3,
                   CONNECT = 4, CLOSE = 5,   SEND = 6,    TIMEOUT = 7 };

char *pkt_name[] = { "F_FIN", "F_SYN", "F_ACK", "F_DATA" };
char *st_name[] =  { "WAIT_CON", "SYN_SENT", "SYN_RCVD", "CONNECTED" };
char *ev_name[] =  { "RCV_FIN", "RCV_SYN", "RCV_ACK", "RCV_DATA",
                     "CONNECT", "CLOSE",   "SEND",    "TIMEOUT"   };

struct state_action {           // Protocol FSM Structure
    void (* action)(void *p);
    enum proto_state next_state;
};

#define MAX_DATA_SIZE   (500)

// 512 Bytes Packet
struct packet {
	unsigned short type;		// packet_type
	unsigned int seq;			// sequence number
	unsigned int ack;			// sequence number of just arrived packet
	unsigned short size;
	char data[MAX_DATA_SIZE];
};

struct p_event {                // Event Structure
    enum proto_event event;
    struct packet packet;
    int size;
};

enum proto_state c_state = WAIT_CON;         // Initial State
volatile int timedout = 0;
unsigned int ack_expected = 0;
unsigned int next_packet_to_send = 0;
unsigned int packet_expected = 0;
unsigned int too_far = NUM_BUF;
unsigned short used_buf = 0;
struct packet out_buf[NUM_BUF];
struct packet in_buf[NUM_BUF];
unsigned short arrived[NUM_BUF] = { 0 };
unsigned short acknowledged[NUM_BUF] = { 0 };
int data_count = 0;

static void timer_handler(int signum)
{
    printf("Timedout\n");
    timedout = 1;
}

static void timer_init(void)
{
    struct sigaction sa;

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = &timer_handler;
    sigaction(SIGALRM, &sa, NULL);
}

void set_timer(int sec)
{
    struct itimerval timer;

    timedout = 0;
    timer.it_value.tv_sec = sec;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;   // Non Periodic timer
    timer.it_interval.tv_usec = 0;
    setitimer (ITIMER_REAL, &timer, NULL);
}

void send_packet(struct packet *p)
{
    printf("SEND %s\n", pkt_name[p->type]);
	Send((char *)p, sizeof(struct packet) - MAX_DATA_SIZE + p->size);
}

void send_wo_packet(int flag, unsigned short seq, unsigned short ack, void *p)
{
	struct p_event *evnt = (struct p_event *)p;
	evnt->packet.type = flag;
	evnt->packet.seq = seq;
	evnt->packet.ack = ack;
	evnt->packet.size = 0;
	send_packet(&evnt->packet);
}

static void send_ack(void *p)
{
	send_wo_packet(F_ACK, 0, ((struct p_event*)p)->packet.seq, p);
}

static void send_syn(void *p)
{
	send_wo_packet(F_SYN, ack_expected, 0, p);
	set_timer(CONNECT_TIMEOUT);
}

static void send_oldest(void *p)
{
	if (used_buf != 0)
	{
		send_packet(&(out_buf[ack_expected % NUM_BUF]));
		set_timer(CONNECT_TIMEOUT);
	}
}

static void report_con(void *p)
{
    set_timer(0);           // Stop Timer
    printf("Connected\n");
}

static void passive_con(void *p)
{
	send_ack(p);
	send_syn(p);
}

static void active_con(void *p)
{
	send_syn(p);
}

static void make_con(void *p)
{
	report_con(NULL);
}

static void close_con(void *p)
{
	send_wo_packet(F_FIN, 0, 0, p);
    printf("Connection Closed\n");
}

static void report_data(struct packet *p)
{
    printf("Data Arrived data='%s' size:%d\n",
        p->data, p->size);
}

static void check_ack(void *p)
{
	struct p_event *evnt = (struct p_event *)p;
	if (ack_expected <= evnt->packet.ack && evnt->packet.ack < next_packet_to_send)
	{
		acknowledged[evnt->packet.ack % NUM_BUF] = 1;
		while(acknowledged[ack_expected % NUM_BUF])
		{
			acknowledged[ack_expected % NUM_BUF] = 0;
			used_buf--;
			ack_expected++;
		}
	}
}

static void check_data(void *p)
{
	struct p_event *evnt = (struct p_event *)p;
	if (packet_expected <= evnt->packet.seq && evnt->packet.seq < too_far)
	{
		arrived[(evnt->packet.seq) % NUM_BUF] = 1;
		in_buf[(evnt->packet.seq) % NUM_BUF] = evnt->packet;
		send_ack(p);
		while(arrived[packet_expected % NUM_BUF])
		{
			report_data(&(in_buf[packet_expected % NUM_BUF]));
			arrived[packet_expected % NUM_BUF] = 0;
			packet_expected++;
			too_far++;
		}
	} else if (evnt->packet.seq < packet_expected)
	{
		send_ack(p);
	}
}

static void check_send(void *p)
{
	struct p_event *evnt = (struct p_event *)p;
	if (used_buf == 0)			// When insert a data into the empty outBuffer, start timer.
	{
		set_timer(CONNECT_TIMEOUT);
	}
	if (used_buf < NUM_BUF)
	{
		evnt->packet.type = F_DATA;
		evnt->packet.seq = next_packet_to_send++;
		evnt->packet.ack = 0;		// won't be checek when received
		sprintf(evnt->packet.data, "%09d", data_count++);
		evnt->packet.size = strlen(evnt->packet.data) + 1;
		out_buf[evnt->packet.seq % NUM_BUF] = evnt->packet;
		used_buf++;
		printf("Send Data to peer '%s' size:%d\n",
			evnt->packet.data, evnt->packet.size);
		send_packet(&evnt->packet);
	} else
	{
		printf("Buffer is full. Sending data is not available.\n");
	}
}

struct state_action p_FSM[NUM_STATE][NUM_EVENT] = {
  //  for each event:
  //  RCV_FIN,				   RCV_SYN,					  RCV_ACK,					  RCV_DATA,
  //  CONNECT,				   CLOSE,					  SEND,						  TIMEOUT
  
  //  WAIT_CON state
	{{ NULL, WAIT_CON },       { passive_con, SYN_RCVD }, { NULL, WAIT_CON },         { NULL, WAIT_CON },
   	 { active_con, SYN_SENT }, { NULL, WAIT_CON },        { NULL, WAIT_CON },         { NULL, WAIT_CON }}, 

  //  SYN_SENT state
	{{ close_con, WAIT_CON },  { passive_con, SYN_RCVD }, { make_con, CONNECTED },    { NULL, SYN_SENT },
   	 { NULL, SYN_SENT },       { close_con, WAIT_CON },   { NULL, SYN_SENT },         { active_con, SYN_SENT }}, 
  
  //  SYN_RCVD state
	{{ close_con, WAIT_CON },  { passive_con, SYN_RCVD }, { report_con, CONNECTED },  { NULL, SYN_RCVD },
   	 { NULL, SYN_RCVD },       { close_con, WAIT_CON },   { NULL, SYN_RCVD },         { send_syn, SYN_RCVD }}, 

  //  CONNECTED state
	{{ close_con, WAIT_CON },  { send_ack, CONNECTED },   { check_ack, CONNECTED },    { check_data, CONNECTED },
   	 { NULL, CONNECTED },      { close_con, WAIT_CON },   { check_send, CONNECTED },   { send_oldest, CONNECTED }} 

};


struct p_event *get_event(void)
{
	// make an empty event
    static struct p_event event;    // not thread-safe
    
loop:
    // Check if there is user command
    if (!kbhit()) {
        // Check if timer is timed-out
        if(timedout) {
            timedout = 0;
            event.event = TIMEOUT;
        } else {
            // Check Packet arrival by event_wait()
            ssize_t n = Recv((char*)&event.packet, sizeof(struct packet));
            if (n > 0) {
                // if then, decode header to make event
                switch (event.packet.type) {
                    case F_SYN:  event.event = RCV_SYN;  break;
                    case F_ACK:  event.event = RCV_ACK;  break;
                    case F_FIN:  event.event = RCV_FIN;  break;
                    case F_DATA:
                        event.event = RCV_DATA;
                        event.size = event.packet.size;
                        break;
                    default:
                        goto loop;
                }
            } else
                goto loop;
        }
    } else {
        int n = getchar();
        switch (n) {
            case '0': event.event = CONNECT; break;
            case '1': event.event = CLOSE;   break;
            case '2': event.event = SEND;    break;
            case '3': return NULL;  // QUIT
            default:
                goto loop;
        }
    }
	// this event has only event type
    return &event;
}

void
Protocol_Loop(void)
{
    struct p_event *eventp;

    timer_init();
    while (1) {
        printf("Current State = %s\n", st_name[c_state]);

        /* Step 0: Get Input Event */
        if((eventp = get_event()) == NULL)
            break;
        printf("EVENT : %s\n",ev_name[eventp->event]);
        /* Step 1: Do Action */
        if (p_FSM[c_state][eventp->event].action)
            p_FSM[c_state][eventp->event].action(eventp);
        else
            printf("No Action for this event\n");

        /* Step 2: Set Next State */
        c_state = p_FSM[c_state][eventp->event].next_state;
    }
}

int
main(int argc, char *argv[])
{
    ChannelNumber channel;
    ID id;
    int rateOfPacketLoss;

    printf("Channel : ");
    scanf("%d",&channel);
    printf("ID : ");
    scanf("%d",&id);
    printf("Rate of Packet Loss (0 ~ 100)%% : ");
    scanf("%d",&rateOfPacketLoss);
    if (rateOfPacketLoss < 0)
        rateOfPacketLoss = 0;
    else if (rateOfPacketLoss > 100)
        rateOfPacketLoss = 100;
        
    // Login to SIMULATOR

    if (Login(channel, id, rateOfPacketLoss) == -1) {
        printf("Login Failed\n");
        return -1;
    }

    printf("Entering protocol loop...\n");
    printf("type number '[0]CONNECT', '[1]CLOSE', '[2]SEND', or '[3]QUIT'\n");
    Protocol_Loop();

    // SIMULATOR_CLOSE

    return 0;
}

