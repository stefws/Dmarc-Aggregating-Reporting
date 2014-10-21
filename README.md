Dmarc-Aggregating-Reporting
===========================

Python 2.6 scripts to parse our Custom MTA DMARC log and generate and send DMARC Aggregated reports,
ooreport launched daily after log rotation.

To Do:
- Check various path settings of both scripts and alter to match with your environment
- Check logline parser class in dmarc.py and alter to match your log line format
- Test dmarc.py by inspecting and altering logline data from dmarc.py Main body

- Check report class in ooreport.py for setting on how to send mails in your environment
- Test possible parsed log file for sampled domains only, see trialmode and trialreport in ooreport.py
- and/or do dryruns before going live

Enjoy!
