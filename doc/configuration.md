

- `nb-thread` : 0 to disable multi-threading. There exists only one worker. The worker will be executed on the main thread.

   otherwise, `n` workers will be executed on `n` separate threads. The main thread will read packets then dispatch the packets to workers.  