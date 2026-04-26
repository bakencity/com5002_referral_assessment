Overview
This repository documents my full investigation of endpoint‑centric malicious activity in the Boss of the SOC v3 (BOTSv3) dataset using Splunk Enterprise.
It explains:

i. how I prepared the environment

ii. how I validated the dataset

iii. the exact Splunk queries I used

iv. why I used those queries

v. how I interpreted the results

vi. how I handled limitations in the pre‑indexed dataset

vii. the final answers to all guided questions

This README reflects a SOC‑aligned, evidence‑based workflow and satisfies the lecturer’s expectations for a clear, analytical explanation of my work.

1. Environment Setup
1.1 Splunk Installation
I installed Splunk Enterprise on an Ubuntu 22.04 LTS VM running in VirtualBox.
After installation, I enabled Splunk as a service and confirmed access via the web interface.

1.2 BOTSv3 Dataset Ingestion
I downloaded the pre‑indexed BOTSv3 buckets from Splunk’s GitHub repository and copied them into Splunk’s index directory.
A Splunk restart registered the botsv3 index successfully.

2. Dataset Validation
To ensure the dataset was correctly ingested, I performed three checks:

2.1 Sourcetype Validation
Query:

| tstats count where index="botsv3" by sourcetype
Confirmed presence of key sourcetypes:
stream:http, stream:smtp, osquery:results, wineventlog.

2.2 Time Range Validation
Query:

index="botsv3" earliest=0 | stats min(_time) max(_time)
Verified full attack timeline coverage.

2.3 Event Count Validation
Query:

| tstats count where index="botsv3"
Event count matched expected BOTSv3 volume.

These checks ensured dataset integrity before analysis.

3. Investigation Workflow
My investigative approach followed SOC best practices:

Identify relevant sourcetype(s)

Write a targeted Splunk query

Validate output

Interpret results

Cross‑check timestamps and hostnames

Document findings with screenshots

Because the dataset was pre‑indexed, some quiz‑hinted queries did not work.
I adapted all queries to match the available fields.

4. Guided Questions – My Queries, Reasoning & Findings
4.1 What port was used to download the attack tools?
Query

index=botsv3 sourcetype=stream:http http_method=GET host=FYODOR-L
| stats count by dest_port
| sort -count
Reasoning  
Summarising outbound GET traffic by dest_port highlights anomalies.

Finding  
Port 3333 was the dominant suspicious destination.

Answer: 3333

4.2 What file was downloaded that contained the attack tools?
Query


index=botsv3 sourcetype=stream:http dest_port=3333 http_method=GET
| table _time src_ip dest_ip uri_path http_content_type
Reasoning  
Filtering traffic to port 3333 reveals the payload retrieved during the attack.

Finding  
The downloaded file was /images/logos.png, a PNG‑masked malicious payload.

Answer: logos.png

4.3 What two files were streamed into the /tmp directory?
Query

index=botsv3 earliest=0 "/tmp/*" sourcetype="osquery:results"
| search action="added"
| table _time action columns.target_path
| dedup columns.target_path
Reasoning  
osquery:results logs file creation events. Filtering for /tmp isolates temporary file activity.

Finding  
After filtering noise and correlating timestamps, the malicious files were:

/tmp/colonel.c

/tmp/definitelydontinvestigatethisfile.sh

Answer: colonel.c, definitelydontinvestigatethisfile.sh

4.4 How many Frothly customer emails were exposed?
Query

index=botsv3 sourcetype=stream:smtp "Grace Hoppy"
| table _time sender sender_email receiver_email subject content_body
Reasoning  
The attacker used SMTP to exfiltrate customer data. Searching for “Grace Hoppy” isolates the malicious emails.

Dataset Limitation  
The pre‑indexed dataset did not provide a direct count.
I manually inspected each SMTP event and counted the emails listed in the Pastebin link.

Finding  
8 customer emails were exposed.

Answer: 8

4.5 What is the path of the C2 URL?
Query

index=botsv3 sourcetype=wineventlog EventCode=4104
| rex field=Message "\$t=['\\\"](?<c2_uri>[^'\\\"]+)"
| table c2_uri
| dedup c2_uri
Reasoning  
PowerShell Script Block Logging (EventCode 4104) captures obfuscated commands.
The $t= variable often stores attacker URLs.

Finding  
Three values appeared, but only one matched known BOTSv3 C2 behaviour:

/admin/get.php

Answer: /admin/get.php

4.6 Which endpoints contacted the C2 infrastructure?
Query

index=botsv3 sourcetype=stream:* dest_ip="45.77.53.176"
| stats count by host
| sort -count
Reasoning  
Summarising outbound traffic to the known C2 IP identifies compromised hosts.

Finding  
Two endpoints communicated heavily with the C2 server:

FYODOR-L

ABUNGST-L

Answer: FYODOR-L, ABUNGST-L

5. Summary of Findings
Port used for malicious download = 3333
File downloaded = logos.png
Malicious /tmp files = colonel.c, definitelydontinvestigatethisfile.sh
Exposed customer emails = 8
C2 URL path = /admin/get.php
Compromised endpoints = FYODOR-L, ABUNGST-L


6. Reflection
This investigation required adapting queries to the constraints of the pre‑indexed dataset.
I validated each result using timestamps, hostnames, and cross‑sourcetype correlation.
My workflow reflects SOC‑aligned reasoning:

Tier 1: Identified anomalies (port 3333, suspicious SMTP).

Tier 2: Correlated logs across HTTP, SMTP, osquery, and PowerShell.

Tier 3: Interpreted obfuscated commands and validated C2 behaviour.

Link to video: 
