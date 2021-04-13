if [ $# -eq 0 ]; then

        echo "Usage: ./script.sh <domain>"
        echo "Example: ./script.sh yahoo.com"
        exit 1
fi


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

rm -rf dirscan/ fourth-levels/ *.txt results/ links/ linkstemp/

WS="dirscan/";
if [ ! -d "$WS" ]; then
    mkdir $WS
fi

TD="fourth-levels/";
if [ ! -d "$TD" ]; then
    # If it doesn't create it
    mkdir $TD
fi

RES="results/";
if [ ! -d "$RES" ]; then
    # If it doesn't create it
    mkdir $RES
fi

TL="links/";
if [ ! -d "$TL" ]; then
    mkdir $TL
fi

LT="linkstemp/"
if [ ! -d "$LT" ]; then
    mkdir $LT
fi

#Recon and enumeration
echo "Reconnaisance started:"


echo "Gathering subdomains with Sublist3r..."

python3 ~/BugBounty/Tools/Sublist3r/sublist3r.py -d $1 -o subdomains.txt
echo $1 >> subdomains.txt
# In case sublist3r finds nothing, it's important to at least have the tried domain in the subdomain list, this is why I use this command.


# This Regex searches for xxx.xxx.xxx domains and shoves them into sublist3r again to see if there are any fourth-level subdomains to take!
if
        cat subdomains.txt | grep -Po "(\w+\.\w+\.\w+)$"
then
        echo "Compiling third-level subdomains..."
        cat subdomains.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u > third-level-subdomains.txt
        echo "Gathering fourth-level domains with Sublist3r..."
       # for domain in $(cat third-level-subdomains.txt); do python3 ~/BugBounty/Tools/Sublist3r/sublist3r.py -d $domain -o fourth-levels/$domain.txt ;done
        if [ $# -eq 2 ];
        then
        echo "Probing for alive fourth-level with httprobe..."
        cat fourth-level/* | sort -u | grep -v $2 | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > probed.txt
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

#Looks for fourth level subdomains and shoves them into our subdomains file.
echo "Cleaning some files"
rm -rf fourth-levels/
echo "Shuffling files"
#Adds http and https to the successfully probed domains to crawl. I use HTTP because not everyone is HTTPS Compliant and I wouldn't want to miss those. (Could possible double the scan time. Watch out)
awk '$0="https://"$0' probed.txt | sort -u >> spiderlinks.txt
awk '$0="http://"$0' probed.txt | sort -u  >> spiderlinks.txt


#Runs Gospider on all picked up domains to find any links assosciated with them, cleans them up into URL's within our scope and moves them to the next step (EXPLOITATION!)

echo "Running Gospider on domains (Things start taking a while from this point onwards. Be patient.)"

gospider -S spiderlinks.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" | tee spiderlinks2.txt

cat spiderlinks2.txt | gf urls | grep $1 | qsreplace -a 'input' | sort -u  >> spiderlinks.txt
rm spiderlinks2.txt
echo "Done with the GoSpider scan!"
echo "Link crawling is now finished; find results in text file: spiderlinks.txt"

#Uses gf to find possible injection points. (GF Patterns can be independently modified and I recommend you do so, a lot of parameters can go unnoticed with many of the patterns on github)

echo "Making neat exploitation links with gf"
echo "generating links to exploit"
for patt in $(cat patterns); do gf $patt spiderlinks.txt | grep $1 | qsreplace -a | sort -u | tee linkstemp/$patt-links.txt;done
for patt in $(cat patterns); do cat linkstemp/$patt-links.txt | gf $patt | qsreplace -a | sort -u | httpx > links/$patt-links.txt;done
rm -rf linkstemp/
clear

# Uses fimap to search for Local File Inclusion vulnerabilities
echo "Using fimap to scan for LFI vulns"
python2 ~/BugBounty/Tools/fimap/src/fimap.py -m -l links/lfi-links.txt -w results/lfi-results.txt
echo "fimap scan finished"
# Uses dalfox to exploit links found by crawling and waybackurls
echo "Started vulnerability scanning. Please maintain your patience"

echo "Running XSS scans on links.."

cat links/xss-links.txt | dalfox pipe | tee results/xss-results.txt

#Uses the perfectly crafted SQLMAP to find vulnerabilities in HTTP headers, PHP cookies and the provided input (Overall 10/10 tool)
echo "Running SQL Injections on links"
sqlmap -m links/sqli-links.txt --batch --level 2 | tee results/sqli-results.txt


echo "Cleaning up files!"

echo "Exploiting links with nuclei templates..."
#nuclei -t nuclei-templates/ -l spiderlinks.txt -o results/nuclei-results.txt

echo "Checking for valid waybackurls"
#Runs Waybackurls to find old links (Some of them are no longer visible on google, some lucky break might occur)
echo "Running Waybackmachine on all successfully probed domain names"
awk '$0="https://"$0' probed.txt | waybackurls | grep $1 | qsreplace -a 'input' | sort -u  >> waybackurls.txt
echo "Waybackmachine search finished."#httpx -l waybackurls.txt > spiderlinks.txt

echo "Scanning is done, please refer to results and other text files to see what I found..."
