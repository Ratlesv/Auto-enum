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

rm -rf dirscan third-levels *.txt

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
	echo "Gathering full third-level domains with Sublist3r..."
	for domain in $(cat third-level-subdomains.txt); do python3 ~/BugBounty/Tools/Sublist3r/sublist3r.py -d $domain -o third-levels/3dsubdomains.txt | sort -u; cat third-levels/3dsubdomains.txt | grep -Po "(\w+\.\w+\.\w+\.\w+)$" >> subdomains.txt  ;done
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
clear

echo "Cleaning some files"
rm third-level-subdomains.txt 
echo "Running Gospider on all found URL's in subdomains (This may take a long time)"
awk '$0="https://"$0' probed.txt | sort -u | waybackurls > spiderlinks.txt
awk '$0="https://"$0' probed.txt | sort -u  >> spiderlinks.txt

gospider -S spiderlinks.txt > dirscan/gospider.txt

clear

echo "Running hakrawler to get all left-over links"
for hak in $(cat spiderlinks.txt); do hakrawler -urls -subs -robots -forms  -url $hak > dirscan/hakrawler.txt;done


#for webdir in $(cat spiderlinks.txt); do ffuf -w ~/BugBounty/Wordlists/common.txt -u $webdir/FUZZ -recursion -recursion-depth 3 -c -v -maxtime 60 >> dirscan/ffuf.txt;done

echo "Making neat exploitation links with gf and some awkawk3000.."

cat dirscan/* | grep $1 | grep -e = | grep url | grep -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" | sort -u > injectionlinks.txt
#cat dirscan/* | gf sqli | grep -e "code-200"| awk '{print $5}' | sort -u | qsreplace -a > sqli.txt
#cat dirscan/* | gf xss | grep -e "code-200"| awk '{print $5}' | sort -u | qsreplace -a > xss.txt
#cat dirscan/* | gf lfi | grep -e "code-200"| awk '{print $5}' | sort -u | qsreplace -a > lfi.txt


echo "Running XSS scans on links.."

cat injectionlinks.txt | dalfox pipe > injectionresults.txt

for sqli in $(cat injectionlinks.txt); do python3 ~/BugBounty/Tools/DSSS/dsss.py -u $sqli > sqliresults.txt;done
