#!/bin/sh
# This is an auto enumeration script meant to make the web hacking process a little easier by automating the mind numbing tasks, currently this script does the following.

#1. Gather subdomains with Amass and organize them neatly into .subdomains
#2. Run another Amass scan on third-level subdomains found and sort by unique into .third-level-subdomains
#3. Probe third and fourth level subdomains with HTTProbe to find which subdomains are still up, sort by unique and print into Alive-Hosts.txt
#4. Run an OWASP-Nettacker scan on every one of the alive subdomains and print the results into results/$domain.html

# Making sure necessary directories are available

results="results/";
if [ ! -d "$results" ]; then
    # If it doesn't create it
    mkdir $results
fi

TD=".third-levels/";
if [ ! -d "$TD" ]; then
    # If it doesn't create it
    mkdir $TD
fi


# If commands are greater than one, print this menu. I should add less than one, too.

if [ $# -gt 1 ]; then
cat .banner
echo "Usage: ./script.sh <domain>"
echo "Example: ./script.sh yahoo.com" 
exit 1
fi

#If commands are less than one
if [ $# -lt 1 ]; then
	cat .banner
	echo "Usage: ./script.sh <domain>"
	echo "Example: ./script.sh yahoo.com" 
	exit 1
fi



#Show Banner
cat .banner

# Gather Subdomains with AMASS and add the original subdomain to the list as well (amass doesn't)
echo "                   Scanning for Third-Level-Subdomains                                     "
echo $1 > .subdomains
amass enum -d $1 -o .subdomains -norecursive
clear
cat .banner

# Grep for third level subdomains, sort them and send only third level sub domains to Amass
echo "                   Found These Subdomains:"
cat .subdomains | sort -u
if 
cat .subdomains | grep -Po "(\w+\.\w+\.\w+)$"
then

cat .subdomains | grep -Po "(\w+\.\w+\.\w+)$" | sort -u > .third-level-subdomains 

echo "                   Scanning Found Third-Level-Subdomains for Fourth-Level Subdomains                 "

for domain in $(cat .third-level-subdomains); do amass enum -d $domain -o .third-levels/.$domain -norecursive; cat .third-levels/.$domain | sort -u >> .subdomains;done
clear 
cat .banner

echo "                   Found these fourth-level subdomains"
cat .subdomains | sort -u


#Probe for live HTTPS hosts using HTTProbe and saves unique results into Alive-Hosts.txt
	if [ $# -eq 2 ];
	then
        	echo "                   Probing for alive third level domains with HTTProbe...             "
        cat .subdomains | sort -u | grep -v $2 | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > .probed
	else
        	echo "                   Probing for alive third level domains with HTTProbe...             "
        	cat .subdomains | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///'  | tr -d ":443" > .probed
	fi
else
	
	
		if [ $# -eq 2 ]; 
       		then
        	echo "                   Probing for alive third level domains with HTTProbe...             "
        	cat .subdomains | sort -u | grep -v $1 | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > .probed
        	else
                	echo "                   Probing for alive third level domains with HTTProbe...             "
                	cat .subdomains | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///'  | tr -d ":443" > .probed
        	fi
fi

cat .probed | sort -u > Alive-Hosts.txt

clear
cat .banner
echo "Currently testing these subdomains:"
cat Alive-Hosts.txt 


