#!/bin/bash 

if [ $# -gt 2 ]; then
	echo "Usage: ./script.sh <domain>"
	echo "Example: ./script.sh yahoo.com" 
	exit 1
fi

NMAP="scans/";
if [ ! -d "$NMAP" ]; then
    # If it doesn't create it
    mkdir $NMAP
fi

TD="third-levels/";
if [ ! -d "$TD" ]; then
    # If it doesn't create it
    mkdir $TD 
fi

WS="dirscan/";
if [ ! -d "$WS" ]; then
    # If it doesn't create it
    mkdir $WS
fi
### Find subdomains such as dev.yahoo.com and output them into a subdomain text file###
echo "Gathering subdomains with Amass..."
echo $1 > subdomains.txt
amass enum -d $1 -o subdomains.txt -norecursive 
echo "Compiling third-level subdomains..."
cat subdomains.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u > third-level-subdomains.txt # Take out only domains with three layers using regex (\w+\)
echo "Gathering full third-level domains with Amass..."
for domain in $(cat third-level-subdomains.txt); do amass enum -d $domain -o third-levels/$domain.txt -norecursive & sleep 5; cat third-levels/$domain.txt | sort -u >> subdomains.txt;done

if [$# -eq 2 ]; 
then
        echo "Probing for alive third-levels with httprobe..."
        cat subdomains.txt | sort -u | grep -v $2 | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > probed.txt
else
        echo "Probing for alive third-levels with httprobe..."
        cat subdomains.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///'  | tr -d ":443" > probed.txt
fi

echo "Scanning for vulnerabilities and open ports using Nmap..."
if [ -f nmap_current.xml ];then
   cp nmap_current.xml nmap_previous.xml
fi
cat probed.txt | sort -u > probed-unique.txt

nmap -iL probed-unique.txt -T4 --script=scipag_vulscan/vulscan.nse -oA scans/nmap_current

echo "Running Gospider and ffuf" 

awk '$0="https://"$0' probed-unique.txt > spiderlinks.txt

for webdir in $(cat spiderlinks.txt); do gospider -s $webdir >> dirscan/gospider.txt ;done

for webdir in $(cat spiderlinks.txt); do ffuf -w ~/Desktop/CTF/Wordlists/Web\ Directories/common.txt -u $webdir/FUZZ -recursion -recursion-depth 3 -c -v -maxtime 60 >> dirscan/ffuf.txt

echo "Searching for Wordpress directories" 

cat dirscan/ffuf.txt 'wp-admin\|wp-include\|wp-login.php' > dirscan/wp-admin.txt
cat dirscan/gospider.txt | grep  'wp-admin\|wp-include\|wp-login.php' >> dirscan/wp-admin.txt
if
 cat dirscan/wp-admin.txt | grep 'wp-admin\|wp-include\|wp-login.php'
then
 echo "Found Word-Press Directory" 
  for wpscan in $(cat dirscan/wp-admin.txt); do wpscan --url $wpscan --api-token tP8SO6Fufa5apCd1R1ww3mJ8cRQcGfLsLKYw5uFmcW4;done
else 
 echo "No Wordpress directories found."
fi
