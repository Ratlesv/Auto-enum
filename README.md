This script uses Tomnomnom's Amass tool to get multi-level sub-domains, neatly categorizes them into text files by applying the AWK AWK 3000 and runs an NMAP
scan on every open port. It also fuzzes all webdirectories for interesting URL's with PHP inputs or Wordpress directories. If it finds wordpress directories
this script also scans them using wpscan for vulnerabilities and outputs the results into a folder. 

## If you're looking to try this, I recommend you install the tools in the same way this script is meant to run

https://github.com/Isaac-The-Brave/Fresh-Ubuntu-Server-to-Attack-Box

use the install script here.
