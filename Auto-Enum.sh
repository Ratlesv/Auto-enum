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
	echo "Gathering fourth-level domains with Sublist3r..."
	for domain in $(cat third-level-subdomains.txt); do python3 ~/BugBounty/Tools/Sublist3r/sublist3r.py -d $domain -o third-levels/$domain.txt ;done
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
cat third-levels/* | grep -Po "(\w+\.\w+\.\w+\.\w+)$"
rm -rf third-level-subdomains.txt third-levels/ 



echo "Running hakrawler to crawl links from live hosts"
awk '$0="https://"$0' probed.txt | sort -u  > spiderlinks.txt
awk '$0="http://"$0' probed.txt | sort -u  >> spiderlinks.txt
for hak in $(cat spiderlinks.txt); do hakrawler -all -url $hak >> dirscan/hakrawler.txt;done
cat dirscan/hakrawler.txt
echo "Done with the first hakrawler scan."

echo "Running hawkrawler again on newly crawled links"
for hak in $(cat spiderlinks.txt); do hakrawler -all -url $hak >> dirscan/hakrawler.txt;done
cat dirscan/hakrawler.txt >> spiderlinks2.txt
cat spiderlinks2.txt | grep $1 | grep url | grep -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" | sort -u >> spiderlinks.txt
rm spiderlinks2.txt 
echo "Running Gospider for the first time on hakrawler links (If this takes a long time, the second one will be VERY long)"

gospider -S spiderlinks.txt >> spiderlinks2.txt

cat spiderlinks2.txt | grep $1 | grep url | grep -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" | sort -u >> spiderlinks.txt

rm spiderlinks2.txt
clear
echo "Done with the first GoSpider scan!"
echo "Running Waybackmachine on all successfully probed domain names"
awk '$0="https://"$0' probed.txt| waybackurls | grep $1 | sort -u >> spiderlinks.txt
awk '$0="https://"$0' probed.txt | sort -u  >> spiderlinks.txt
echo "Waybackmachine links found."
clear
echo "Running Gospider on all old and randomly found links. THIS IS VERY LIKELY TO TAKE A LONG TIME ON A LARGE INFRASTRUCTURE, HAVE PATIENCE."
gospider -S spiderlinks.txt > dirscan/gospider.txt

clear

echo "Link crawling is now finished; find results in text files. Moving on to exploitation." 

#for webdir in $(cat spiderlinks.txt); do ffuf -w ~/BugBounty/Wordlists/common.txt -u $webdir/FUZZ -recursion -recursion-depth 3 -c -v -maxtime 60 >> dirscan/ffuf.txt;done

echo "Making neat exploitation links with gf and some awkawk3000.."

cat dirscan/* | grep $1 | grep -e = | grep url | grep -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" | sort -u > injectionlinks.txt
cat dirscan/* | grep $1 | grep url | grep -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" | sort -u > nuclei.txt
awk '$0="https://"$0' probed.txt | sort -u >> nuclei.txt
awk '$0="http://"$0' probed.txt | sort -u  >> nuclei.txt


#cat dirscan/* | gf sqli | grep -e "code-200"| awk '{print $5}' | sort -u | qsreplace -a > sqli.txt
#cat dirscan/* | gf xss | grep -e "code-200"| awk '{print $5}' | sort -u | qsreplace -a > xss.txt
#cat dirscan/* | gf lfi | grep -e "code-200"| awk '{print $5}' | sort -u | qsreplace -a > lfi.txt


echo "Running XSS scans on links.."

cat injectionlinks.txt | dalfox pipe > injectionresults.txt

clear

echo "Running SQL Injections on links"
# DSSS is a little slow, I'll try something else
#for sqli in $(cat injectionlinks.txt); do python3 ~/BugBounty/Tools/DSSS/dsss.py -u $sqli >> sqliresults.txt;done
for sqli in $(cat injectionlinks.txt); do sqlmap -u $sqli --batch >> sqliresults.txt; done
clear

echo "Cleaning up files..."
RES="results/";
if [ ! -d "$RES" ]; then
    mkdir $RES
fi

echo "Exploiting links with nuclei templates..."
nuclei -t nuclei-templates/ -l nuclei.txt -o results/nuclei-results.txt


echo "Scanning is done, please refer to results and other text files to see what I found..."
