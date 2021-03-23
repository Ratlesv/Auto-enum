#!/bin/bash 	
echo "           .       .                   .       .      .     .      ."
echo "          .    .         .    .            .     ______"
echo "      .           .             .               ////////"
echo "                .    .   ________   .  .      /////////     .    ."
echo "           .            |.____.  /\        ./////////    ."
echo "    .                 .//      \/  |\     /////////"
echo "       .       .    .//          \ |  \ /////////       .     .   ."
echo "                    ||.    .    .| |  ///////// .     ."
echo "     .    .         ||           | |//`,/////                ."
echo "             .       \\        ./ //  /  \/   .               "
echo "  .                    \\.___./ //\` '   ,_\     .     ."
echo "          .           .     \ //////\ , /   \                 .    ."
echo "                       .    ///////// \|  '  |    ."
echo "      .        .          ///////// .   \ _ /          ."
echo "                        /////////                              ."
echo "                 .   ./////////     .     ."
echo "         .           --------   .                  ..             ."
echo "  .               .        .         .                       ."
echo "                        ________________________"
echo "____________------------                        -------------_________"
echo ""
echo ""




























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

WS="wpscan/";
if [ ! -d "$WS" ]; then

    mkdir $WS
fi

WS="dirscan/";
if [ ! -d "$WS" ]; then

    mkdir $WS
fi

echo "Gathering subdomains with Amass..."
echo $1 > subdomains.txt
amass enum -d $1 -o subdomains.txt -norecursive & sleep 5 
if 
	cat subdomains.txt | grep -Po "(\w+\.\w+\.\w+)$"
then
	echo "Compiling third-level subdomains..."
	cat subdomains.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u > third-level-subdomains.txt 
	echo "Gathering full third-level domains with Amass..."
	for domain in $(cat third-level-subdomains.txt); do amass enum -d $domain -o third-levels/$domain.txt -norecursive; cat third-levels/$domain.txt | sort -u >> subdomains.txt;done

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
echo "Scanning for vulnerabilities and open ports using Nmap..."
if [ -f nmap_current.xml ];then
   cp nmap_current.xml nmap_previous.xml
fi
cat probed.txt | sort -u > probed-unique.txt

nmap -iL probed-unique.txt -T4 --script=scipag_vulscan/vulscan.nse -oA scans/nmap_current

echo "Running Gospider and ffuf" 

awk '$0="https://"$0' probed-unique.txt > spiderlinks.txt

#for webdir in $(cat spiderlinks.txt); do gospider -s $webdir >> dirscan/gospider.txt ;done

for webdir in $(cat spiderlinks.txt); do ffuf -w ~/Desktop/CTF/Wordlists/Web\ Directories/common.txt -u $webdir/FUZZ -recursion -recursion-depth 3 -c -v -maxtime 60 >> dirscan/ffuf.txt;done

echo "Searching for Wordpress directories" 
cat dirscan/ffuf.txt | egrep -o 'https?://[^ ]+'\ | grep 'wp-admin\|wp-includes\|wp-login.php\|wp-content' > wpscan/wp-admin.txt
cat dirscan/gospider.txt | egrep -o 'https?://[^ ]+' | grep 'wp-admin\|wp-includes\|wp-login.php\|wp-content'>> wpscan/wp-admin.txt
cat wpscan/wp-admin.txt | sed 's|wp-includes.*|wp-includes|' | sort -u | sed 's|wp-admin.*|wp-admin|' | sort -u | sed 's|wp-content.*|wp-content|' | sort -u | sed 's|wp-login.php.*|wp-login.php|' | sort -u > wpscan/wp-admin-stripped.txt
rm wp-admin.txt
if
 cat wpscan/wp-admin-stripped.txt | grep 'wp-admin\|wp-include\|wp-login.php\|wp-contents'
then
 echo "Found Word-Press Directories and saved them in wpscan/wp-admin-stripped.txt..." 
  #for wpscan in $(cat wpscan/wp-admin-stripped.txt); do wpscan --url $wpscan --ignore-main-redirect --random-user-agent --api-token tP8SO6Fufa5apCd1R1ww3mJ8cRQcGfLsLKYw5uFmcW4 -e;done
else 
 echo "No Wordpress directories found..."
fi
