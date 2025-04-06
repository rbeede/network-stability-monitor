# Network Stability Monitor
Tool designed to run in the background, track potential network outages.

It runs a small check every second. If a failure occurs it runs a series of more detailed checks to determine if there is an actual outage or just a false alarm. A threshold of checks must fail before an outage is recorded.

The ability to track outages as a smaller interval (e.g. 1-2 minutes) is helpful to determine any patterns or frequencies of smaller interruptions to a network.

### Running in background

#### Crontab method
```
@reboot /usr/bin/python3 /opt/NetworkStabilityMonitor/nsm.py /var/log/network-monitor.log
```
