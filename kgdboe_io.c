#include <linux/kgdb.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include "kgdboe_io.h"
#include "netpoll_wrapper.h"

struct netpoll_wrapper *s_pKgdboeNetpoll;

static const unsigned char idPacketHeader[] = { 0x45, 0x15, 0xa7, 0xaa, 0x63, 0xb5, 0xcf, 0x41, 0x9c, 0x7a, 0x25, 0x2b, 0x8d, 0xea, 0x64, 0x3e };
static const int macAddrSize = ETH_ALEN;
static const int ipAddrSize = 4;

static char s_IncomingRingBuffer[4096];
static volatile int s_IncomingRingBufferReadPosition;
static volatile int s_IncomingRingBufferWritePosition;

static char s_OutgoingBuffer[30];
static volatile int s_OutgoingBufferUsed;

static bool s_StoppedInKgdb;

static void(*pkgdb_roundup_cpus)(void);

static struct
{
	volatile bool RoundupPending;
	int RequestingCore;
} s_RoundupContext;

static void kgdboe_rx_handler(void *pContext, enum netpoll_wrapper_iface iface, int port, char *msg, int len)
{
	BUG_ON(!s_pKgdboeNetpoll);
	if (s_RoundupContext.RoundupPending && s_RoundupContext.RequestingCore == raw_smp_processor_id())
	{
		pkgdb_roundup_cpus();
		s_RoundupContext.RoundupPending = false;
	}

	if (iface == netpoll_wrapper_iface2)
	{
		if (len == (sizeof(idPacketHeader)+macAddrSize + ipAddrSize))
		{
			if (!memcmp(msg, idPacketHeader, sizeof(idPacketHeader)))
			{
				netpoll_wrapper_set_reply_addresses(s_pKgdboeNetpoll, msg + sizeof(idPacketHeader), *((int *)(msg + sizeof(idPacketHeader)+macAddrSize)));
			}
		}
	}
	else if (iface == netpoll_wrapper_iface1)
	{
		bool breakpointPending = false;

		if (!kgdb_connected && (len != 1 || msg[0] == 3))
			breakpointPending = true;

		for (int i = 0; i < len; i++) 
		{
			if (msg[i] == 3)
				breakpointPending = true;

			s_IncomingRingBuffer[s_IncomingRingBufferWritePosition++] = msg[i];
			s_IncomingRingBufferWritePosition %= sizeof(s_IncomingRingBuffer);
		}

		if (breakpointPending && !s_StoppedInKgdb && netpoll_wrapper_reply_address_assigned(s_pKgdboeNetpoll))
			kgdb_schedule_breakpoint();
	}
}


static void kgdboe_pre_exception(void)
{
	if (!kgdb_connected)
		try_module_get(THIS_MODULE);

	s_StoppedInKgdb = true;
	netpoll_wrapper_set_drop_flag(s_pKgdboeNetpoll, true);
	s_RoundupContext.RequestingCore = raw_smp_processor_id();
	s_RoundupContext.RoundupPending = true;

	while (s_RoundupContext.RoundupPending && !netpoll_wrapper_reply_address_assigned(s_pKgdboeNetpoll))
	{
		netpoll_wrapper_poll(s_pKgdboeNetpoll);
	}
}

static void kgdboe_post_exception(void)
{
	if (!kgdb_connected)
	{
		module_put(THIS_MODULE);
		netpoll_wrapper_reset_reply_address(s_pKgdboeNetpoll);
	}

	s_StoppedInKgdb = false;
	netpoll_wrapper_set_drop_flag(s_pKgdboeNetpoll, false);
}


static int kgdboe_read_char(void)
{
	BUG_ON(!s_pKgdboeNetpoll);

	while (s_IncomingRingBufferReadPosition == s_IncomingRingBufferWritePosition)
		netpoll_wrapper_poll(s_pKgdboeNetpoll);

	char result = s_IncomingRingBuffer[s_IncomingRingBufferReadPosition++];
	s_IncomingRingBufferReadPosition %= sizeof(s_IncomingRingBuffer);
	return result;
}

static void kgdboe_flush(void)
{
	if (s_OutgoingBufferUsed) 
	{
		netpoll_wrapper_send_reply(s_pKgdboeNetpoll, s_OutgoingBuffer, s_OutgoingBufferUsed);
		s_OutgoingBufferUsed = 0;
	}
}

static void kgdboe_write_char(u8 chr)
{
	s_OutgoingBuffer[s_OutgoingBufferUsed++] = chr;
	if (s_OutgoingBufferUsed == sizeof(s_OutgoingBuffer))
		kgdboe_flush();
}


static struct kgdb_io kgdboe_io_ops = {
	.name = "kgdboe",
	.read_char = kgdboe_read_char,
	.write_char = kgdboe_write_char,
	.flush = kgdboe_flush,
	.pre_exception = kgdboe_pre_exception,
	.post_exception = kgdboe_post_exception
};

int kgdboe_io_init()
{
	pkgdb_roundup_cpus = kallsyms_lookup_name("kgdb_roundup_cpus");
	if (!pkgdb_roundup_cpus)
	{
		printk(KERN_ERR "kgdboe: cannot find kgdb_roundup_cpus(). Aborting...\n");
		return -EINVAL;
	}

	s_pKgdboeNetpoll = netpoll_wrapper_create("eth0", 6443, 6444, NULL);
	if (!s_pKgdboeNetpoll)
		return -EINVAL;

	int err = kgdb_register_io_module(&kgdboe_io_ops);
	if (err != 0)
	{
		netpoll_wrapper_free(s_pKgdboeNetpoll);
		s_pKgdboeNetpoll = NULL;
		return err;
	}

	netpoll_wrapper_set_callback(s_pKgdboeNetpoll, kgdboe_rx_handler, NULL);
	printk(KERN_INFO "kgdboe: Successfully initialized. Don't forget to run the flow control program on the other PC.\n");

	return 0;
}

void kgdboe_io_cleanup()
{
	netpoll_wrapper_free(s_pKgdboeNetpoll);
	s_pKgdboeNetpoll = NULL;
}