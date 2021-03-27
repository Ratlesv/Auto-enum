if [ $# -gt 1 ]; then
	echo "Usage: ./script.sh <domain>"
	echo "Example: ./script.sh yahoo.com" 
	exit 1
fi

#if [ $# -gt -1 ]; then
 #       echo "Usage: ./script.sh <domain>"
  #      echo "Example: ./script.sh yahoo.com" 
   #     exit 1
#fi

WS="dirscan/";
if [ ! -d "$WS" ]; then
    mkdir $WS
fi

TD="third-levels/";
if [ ! -d "$TD" ]; then
    # If it doesn't create it
    mkdir $TD 
fi


echo "Gathering subdomains with Sublist3r..."

python3 ~/BugBounty/Tools/Sublist3r/sublist3r.py -d $1 -o subdomains.txt

clear

if
	cat subdomains.txt | grep -Po "(\w+\.\w+\.\w+)$"
then
	echo "Compiling third-level subdomains..."
	cat subdomains.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u > third-level-subdomains.txt 
	echo "Gathering full third-level domains with Amass..."
	for domain in $(cat third-level-subdomains.txt); do python3 ~/BugBounty/Tools/Sublist3r/sublist3r.py -d $domain -o third-levels/$domain.txt ; cat third-levels/subdomains.txt | sort -u >> subdomains.txt;done
	if [ $# -eq 2 ];
	then
        echo "Probing for alive third-levels with httprobe..."
        cat subdomains.txt | sort -u | grep -v $2 | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > probed.txt
	else
        	echo "Probing for alive third-levels with httprobe..."
        	cat subdomains.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///'  | tr -d ":443" > probed.txt
	fi
else
	echo "No third-level domains found..."

		if [ $# -eq 2 ]; 
       		then
        	echo "Probing for alive domains with httprobe..."
        	cat subdomains.txt | sort -u | grep -v $2 | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > probed.txt
        	else
                	echo "Probing for alive domains with httprobe..."
                	cat subdomains.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///'  | tr -d ":443" > probed.txt
        	fi
fi
echo "Cleaning some files"
rm -rf third-level-subdomains.txt third-levels
echo "Running Gospider on all found URL's in subdomains (This may take a long time)"
awk '$0="https://"$0' probed.txt | sort -u | waybackurls > spiderlinks.txt
awk '$0="https://"$0' probed.txt | sort -u  >> spiderlinks.txt

gospider -S spiderlinks.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200"| awk '{print $5}'| grep "=" | qsreplace -a | >> dirscan/gospider.txt 

#for webdir in $(cat spiderlinks.txt); do ffuf -w ~/BugBounty/Wordlists/common.txt -u $webdir/FUZZ -recursion -recursion-depth 3 -c -v -maxtime 60 >> dirscan/ffuf.txt;done

echo "Making neat exploitation links in nucleilinks.txt and xsssqli.txt
cat dirscan/* | grep -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" | grep $1 | sort -u  > exploitlinks.txt

clear

echo "Running XSS scans on links.."

cat exploitlinks.txt | dalfox pipe | tee xssresults.txt

for sqli in $(cat exploitlinks.txt); do python3 ~/BugBounty/Tools/DSSS/dsss.py -u $sqli > sqliresults.txt
