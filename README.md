# VulnHunter

this code is a vulnerabilities scanner code for LFI,RFI,RCE,SQLI,XSS,XXE

example

python3 VulnHunter.py -u domain.com -t 10 -l 100 -o resulte.txt --vulns all

python3 VulnHunter.py -w urls.txt -t 10 -l 100 -o resule.txt --vulns sqli,xss,rce
