"""alienpy:: Async tooling for async machinery"""
# flake8: noqa
import sys
import asyncio
import threading

##################################################
#   GLOBAL STATE ASYNCIO LOOP
_alienpy_global_asyncio_loop = None
_thread_event = None


def get_loop():
    return _alienpy_global_asyncio_loop


def _cancel_all_tasks(loop_to_cancel):
    to_cancel = asyncio.Task.all_tasks(loop_to_cancel) if sys.version_info[1] < 7 else asyncio.all_tasks(loop_to_cancel)
    if not to_cancel: return
    for task in to_cancel: task.cancel()
    if sys.version_info[1] < 10:
        loop_to_cancel.run_until_complete(asyncio.tasks.gather(*to_cancel, loop = loop_to_cancel, return_exceptions = True))
    else:
        loop_to_cancel.run_until_complete(asyncio.tasks.gather(*to_cancel, return_exceptions = True))

    for task in to_cancel:
        if task.cancelled(): continue
        if task.exception() is not None:
            loop_to_cancel.call_exception_handler({'message': 'unhandled exception during asyncio.run() shutdown', 'exception': task.exception(), 'task': task})


def _run(mainasync, *, debug = False):
    global _alienpy_global_asyncio_loop

    if asyncio.events._get_running_loop() is not None:
        asyncio_err_msg = 'asyncio.run() cannot be called from a running event loop'
        raise RuntimeError(asyncio_err_msg)  # pylint: disable=protected-access

    if not asyncio.coroutines.iscoroutine(mainasync):
        no_coroutine_err_msg = f'a coroutine was expected, got {mainasync!r}'
        raise ValueError(no_coroutine_err_msg)

    if _alienpy_global_asyncio_loop is not None:
        loop_already_started = 'asyncio event loop already started'
        raise RuntimeError(loop_already_started)

    _alienpy_global_asyncio_loop = asyncio.events.new_event_loop()
    try:
        asyncio.events.set_event_loop(_alienpy_global_asyncio_loop)
        _alienpy_global_asyncio_loop.set_debug(debug)
        return _alienpy_global_asyncio_loop.run_until_complete(mainasync)
    finally:
        try:
            _cancel_all_tasks(_alienpy_global_asyncio_loop)
            _alienpy_global_asyncio_loop.run_until_complete(_alienpy_global_asyncio_loop.shutdown_asyncgens())
        finally:
            asyncio.events.set_event_loop(None)
            _alienpy_global_asyncio_loop.close()


async def _wait_forever():
    # global _thread_event
    _thread_event.set()
    await asyncio.get_event_loop().create_future()


def start_asyncio():
    """Initialization of main thread that will keep the asyncio loop"""
    global _thread_event
    _thread_event = threading.Event()
    threading.Thread(daemon = True, target = _run, args = (_wait_forever(),)).start()
    _thread_event.wait()


def syncify(fn):
    """DECORATOR FOR SYNCIFY FUNCTIONS:: the magic for un-async functions"""
    def syncfn(*args, **kwds):
        # submit the original coroutine to the event loop and wait for the result
        conc_future = asyncio.run_coroutine_threadsafe(fn(*args, **kwds), _alienpy_global_asyncio_loop)
        return conc_future.result()
    syncfn.as_async = fn
    return syncfn


