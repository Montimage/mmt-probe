# Configuration File

The configuration of MMT-Probe is defined in a file. This file is given to MMT-Probe via `-c` option of running command. 

If user does not give `-c` option, MMT-Probe will try to  find the configuration in `./mmt-probe.conf` in the current folder (where you are starting MMT-Probe).

If it does not find or there exist (syntax) errors in the file, then MMT-Probe will try to find in `/opt/mmt/probe/mmt-probe.conf`.

If no configuration file is found, MMT-Probe will stop its execution.

# Configuration Parameters

- `nb-thread` : 0 to disable multi-threading. There exists only one worker. The worker will be executed on the main thread.

   otherwise, `n` workers will be executed on `n` separate threads. The main thread will read packets then dispatch the packets to workers.  