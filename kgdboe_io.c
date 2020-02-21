#include <linux/kgdb.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/cpu.h>
#include "kgdboe_io.h"
#include "netpoll_wrapper.h"
#include "nethook.h"

struct netpoll_wrapper *g_netpoll_wrapper;

static spinlock_t exception_lock;

static char s_IncomingRingBuffer[4096];
static volatile int g_incoming_ringbuf_read_pos;
static volatile int g_incoming_ringbuf_write_pos;

static char g_outbuf[30];
static volatile int g_outbuf_used;

static bool g_stopped_in_kgdb;

static void kgdboe_rx_handler(void *ctx, int port, char *msg, int len)
{
	bool bp_pending = false;

	BUG_ON(!g_netpoll_wrapper);

	if (!kgdb_connected && (len != 1 || msg[0] == 3))
		bp_pending = true;

	for (int i = 0; i < len; i++) 
	{
		if (msg[i] == 3)
			bp_pending = true;

		s_IncomingRingBuffer[g_incoming_ringbuf_write_pos++] = msg[i];
		g_incoming_ringbuf_write_pos %= sizeof(s_IncomingRingBuffer);
	}

	if (bp_pending && !g_stopped_in_kgdb)
		kgdb_schedule_breakpoint();
}

static void kgdboe_pre_exception(void)
{
	spin_lock(&exception_lock);
	if (!kgdb_connected)
		try_module_get(THIS_MODULE);

	g_stopped_in_kgdb = true;

	nethook_take_relevant_resources();
	netpoll_wrapper_set_drop_flag(g_netpoll_wrapper, true);
}

static void kgdboe_post_exception(void)
{
	if (!kgdb_connected)
		module_put(THIS_MODULE);

	g_stopped_in_kgdb = false;
	netpoll_wrapper_set_drop_flag(g_netpoll_wrapper, false);

	nethook_release_relevant_resources();
	spin_unlock(&exception_lock);
}

static int kgdboe_read_char(void)
{
	char result;
	nethook_netpoll_work_starting();

	BUG_ON(!g_netpoll_wrapper);
	
	while (g_incoming_ringbuf_read_pos == g_incoming_ringbuf_write_pos)
		netpoll_wrapper_poll(g_netpoll_wrapper);

	result = s_IncomingRingBuffer[g_incoming_ringbuf_read_pos++];
	g_incoming_ringbuf_read_pos %= sizeof(s_IncomingRingBuffer);

	nethook_netpoll_work_done();
	return result;
}

static void kgdboe_flush(void)
{
	if (g_outbuf_used) 
	{
		nethook_netpoll_work_starting();
		netpoll_wrapper_send_reply(g_netpoll_wrapper, g_outbuf, g_outbuf_used);
		g_outbuf_used = 0;
		nethook_netpoll_work_done();
	}
}

static void kgdboe_write_char(u8 chr)
{
	g_outbuf[g_outbuf_used++] = chr;
	if (g_outbuf_used == sizeof(g_outbuf))
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

int force_single_cpu_mode(void)
{
	if (num_online_cpus() == 1)
	{
		printk(KERN_INFO "kgdboe: only one active CPU found. Skipping core shutdown.\n");
		return 0;
	}

	printk(KERN_INFO "kgdboe: single-core mode enabled. Shutting down all cores except #0. This is slower, but safer.\n");
	printk(KERN_INFO "kgdboe: you can try using multi-core mode by specifying the following argument:\n");
	printk(KERN_INFO "\tinsmod kgdboe.ko force_single_core = 0\n");
#ifdef CONFIG_HOTPLUG_CPU
	for (int i = 1; i < nr_cpu_ids; i++)
		cpu_down(i);
#else
	if (nr_cpu_ids != 1)
	{
		printk(KERN_ERR "kgdboe: failed to enable the single-CPU mode. %d CPUs found and HOTPLUG_CPU is not enabled.\n", nr_cpu_ids);
		return -EINVAL;
	}
#endif
	return 0;
}

int kgdboe_io_init(const char *device_name, int port, const char *local_ip, bool force_single_core)
{
	int err;
	u8 ipaddr[4];

	spin_lock_init(&exception_lock);

	g_netpoll_wrapper = netpoll_wrapper_create(device_name, port, local_ip);
	if (!g_netpoll_wrapper)
		return -EINVAL;
	
	if (force_single_core)
	{
		err = force_single_cpu_mode();
		if (err)
			return err;
	}
	else if (!nethook_initialize(g_netpoll_wrapper->pDeviceWithHandler))
	{
		printk(KERN_ERR "kgdboe: failed to guarantee cross-CPU network API synchronization. Aborting. Try enabling single-CPU mode.\n");
		return -EINVAL;
	}

	err = kgdb_register_io_module(&kgdboe_io_ops);
	if (err != 0)
	{
		netpoll_wrapper_free(g_netpoll_wrapper);
		g_netpoll_wrapper = NULL;
		return err;
	}

	netpoll_wrapper_set_callback(g_netpoll_wrapper, kgdboe_rx_handler, NULL);

	memcpy(ipaddr, &ip_addr_as_int(g_netpoll_wrapper->netpoll_obj.local_ip), 4);
	printk(KERN_INFO "kgdboe: Successfully initialized. Use the following gdb command to attach:\n");
	printk(KERN_INFO "\ttarget remote udp:%d.%d.%d.%d:%d\n", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3], g_netpoll_wrapper->netpoll_obj.local_port);

	return 0;
}

void kgdboe_io_cleanup(void)
{
	/*
		We don't check for race conditions between running code by other cores and unloading the module!
		There is always a small chance that unloading this module would cause a kernel panic because
		another core is executing a function hooked by us. As normally you don't need to load/unload this
		module all the time (just execute the 'detach' command in GDB and connect back when ready), we
		don't check for it here.
	*/
	kgdb_unregister_io_module(&kgdboe_io_ops);
	netpoll_wrapper_free(g_netpoll_wrapper);
	nethook_cleanup();
	g_netpoll_wrapper = NULL;
}
