# An example of deployment

Traffic is encapsulated in a TCP stream and sent to MMT-Probe via port 5000

For example, to analyse traffic of `eth0`:

```bash
tcpdump -i eth0  -w- | nc mmt.montimage.svc.cluster.local 5000
```

