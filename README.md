# IOC Enrichment Tool

A Python tool that **automates alert enrichment**, one of the most repetitive tasks in a Security Operations Center (SOC).

Given a list of indicators of compromise (IP addresses, domains, and file hashes), it:

1. Identifies each indicator's type, and skips private or reserved IPs so internal addresses never leave the network.
2. Looks each one up in the **VirusTotal** and **AbuseIPDB** threat intelligence APIs.
3. Assigns a verdict: **MALICIOUS, SUSPICIOUS, CLEAN, or UNKNOWN**.
4. Writes a CSV report an analyst can sort and act on.

## Why it matters

Checking indicators one at a time in a browser takes an analyst several minutes per alert. This script does it automatically and applies the same verdict rules every time. It's the same idea behind SOAR playbooks and AI-assisted triage.





## Output 1





|IOC|TYPE|VERDICT|VT MALICIOUS|ABUSE SCORE|
|-|-|-|-|-|
|8.8.8.8|I.P|CLEAN|0|0|
|44d88612fea8a8f36de82e1278abb02f|HASH|MALICIOUS|(many)|-|
|192.168.1.10|PRIVATE I.P|SKIPPED|-|-|





*The hash is the EICAR antivirus test file. It's harmless, but antivirus engines flag it on purpose, which makes it a safe way to test the "malicious" path.*



*192.168.1.10 was skipped due to it being a private as outside threat intelligence cant tell you about internal addresses because millions use the same address.*

## Output 2 





|IOC|TYPE|VERDICT|VT MALICIOUS|ABSUE SCORE|
|-|-|-|-|-|
|185.228.168.9|IP|SUSPICIOUS |1|0|
|cleanbrowsing.com|domain|CLEAN|0|-|
|94.140.14.14|94.140.14.14|CLEAN|0|11|
| adguard.com|domain|CLEAN|0|-|





185.228.168.9 is CleanBrowsing's public DNS server. It was rated SUSPICIOUS because 1 of 57 VirusTotal engines flagged it, a false positive that shows why borderline verdicts need analyst review. AdGuard DNS (94.140.14.14) had 9 abuse reports, but its score of 11 was below the suspicious threshold of 25, so it correctly stayed CLEAN.

## 

## Verdict logic

|Verdict|Rule|
|-|-|
|MALICIOUS|3 or more VirusTotal engines flag it as malicious|
|SUSPICIOUS|At least 1 engine flags it as malicious or suspicious|
|CLEAN|Found, with no detections|
|UNKNOWN|VirusTotal has never seen it|

The thresholds are constants at the top of `enrich.py`. Raising them **reduces false positives** but risks missing real threats, which is the same trade-off SOC teams tune in their SIEM rules.



## How to run

**Google Colab.** Open `run\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_in\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_colab.ipynb` in Colab, add your API keys as Colab Secrets, and run the cells.



## Security design choices

* **No API keys in code.** Keys come from environment variables or Colab Secrets, and `.gitignore` blocks `.env` files.
* **Internal IPs are never sent to third parties.** Private and reserved ranges are skipped, which avoids leaking details about internal network.
* **Rate limiting.** The script waits 15 seconds between lookups to stay within VirusTotal's free tier of 4 requests per minute.
* **Reports aren't committed.** Real investigation results can be sensitive, so `.gitignore` excludes them.

## What I'd add next

* Adding a **LLM step** that summarizes each malicious result, which then suggests a MITRE ATT\&CK technique and what next steps to take, and redacting personal data before sending anything to the model.
* **SIEM integration:** trigger the script automatically, post results to a chat channel for awarness.
* Support for URLs, and caching so repeat indicators aren't looked up twice.

## Skills shown

Python · REST APIs · threat intelligence · alert enrichment · automation · secure handling of secrets · unit testing

