
#include "attribute.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/memcluster.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/timer.h>

mem_context_t mctx = NULL;
isc_task_t t1, t2, t3;
isc_timer_t ti1, ti2, ti3;
int tick_count = 0;

static isc_boolean_t
shutdown_task(isc_task_t task, isc_event_t event) {
	char *name = event->arg;

	printf("task %p shutdown %s\n", task, name);
	return (ISC_TRUE);
}

static isc_boolean_t
tick(isc_task_t task, isc_event_t event)
{
	char *name = event->arg;

	INSIST(event->type == ISC_TIMEREVENT_TICK);

	printf("task %s (%p) tick\n", name, task);

	tick_count++;
	if (tick_count % 3 == 0)
		isc_timer_touch(ti3);

	if (tick_count == 7) {
		os_time_t expires, interval, now;

		(void)os_time_get(&now);
		expires.seconds = 5;
		expires.nanoseconds = 0;
		os_time_add(&now, &expires, &expires);
		interval.seconds = 4;
		interval.nanoseconds = 0;
		printf("*** resetting ti3 ***\n");
		INSIST(isc_timer_reset(ti3, isc_timertype_once, expires,
				       interval, ISC_TRUE)
		       == ISC_R_SUCCESS);
	}

	return (ISC_FALSE);
}

static isc_boolean_t
timeout(isc_task_t task, isc_event_t event)
{
	char *name = event->arg;
	char *type;

	INSIST(event->type == ISC_TIMEREVENT_IDLE || 
	       event->type == ISC_TIMEREVENT_LIFE);

	if (event->type == ISC_TIMEREVENT_IDLE)
		type = "idle";
	else
		type = "life";
	printf("task %s (%p) %s timeout\n", name, task, type);

	if (strcmp(name, "3") == 0) {
		printf("*** saving task 3 ***\n");
		return (ISC_FALSE);
	}
	return (ISC_TRUE);
}

void
main(int argc, char *argv[]) {
	isc_taskmgr_t manager = NULL;
	isc_timermgr_t timgr = NULL;
	unsigned int workers;
	os_time_t expires, interval, now;

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	INSIST(mem_context_create(0, 0, &mctx) == 0);
	INSIST(isc_taskmgr_create(mctx, workers, 0, &manager) == workers);
	INSIST(isc_task_create(manager, shutdown_task, "1", 0, &t1));
	INSIST(isc_task_create(manager, shutdown_task, "2", 0, &t2));
	INSIST(isc_task_create(manager, shutdown_task, "3", 0, &t3));
	INSIST(isc_timermgr_create(mctx, &timgr) == ISC_R_SUCCESS);

	printf("task 1: %p\n", t1);
	printf("task 2: %p\n", t2);
	printf("task 3: %p\n", t3);

	(void)os_time_get(&now);

	expires.seconds = 0;
	expires.nanoseconds = 0;
	interval.seconds = 2;
	interval.nanoseconds = 0;
	INSIST(isc_timer_create(timgr, isc_timertype_once, expires, interval,
				t2, timeout, "2", &ti2) == ISC_R_SUCCESS);
	expires.seconds = 0;
	expires.nanoseconds = 0;
	interval.seconds = 1;
	interval.nanoseconds = 0;
	INSIST(isc_timer_create(timgr, isc_timertype_ticker, expires, interval,
				t1, tick, "1", &ti1) == ISC_R_SUCCESS);
	expires.seconds = 10;
	expires.nanoseconds = 0;
	os_time_add(&now, &expires, &expires);
	interval.seconds = 2;
	interval.nanoseconds = 0;
	INSIST(isc_timer_create(timgr, isc_timertype_once, expires, interval,
				t3, timeout, "3", &ti3) == ISC_R_SUCCESS);

	isc_task_detach(&t1);
	isc_task_detach(&t2);
	isc_task_detach(&t3);

	sleep(15);
	printf("destroy\n");
	isc_timer_detach(&ti1);
	isc_timer_detach(&ti2);
	isc_timer_detach(&ti3);
	sleep(2);
	isc_timermgr_destroy(&timgr);
	isc_taskmgr_destroy(&manager);
	printf("destroyed\n");
	
	mem_stats(mctx, stdout);
}
