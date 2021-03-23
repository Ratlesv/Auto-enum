This script uses Tomnomnom's Amass tool to get multi-level sub-domains, neatly categorizes them into text files by applying the AWK AWK 3000 and runs an NMAP
scan on every open port. It also fuzzes all webdirectories for interesting URL's with PHP inputs or Wordpress directories. If it finds wordpress directories
this script also scans them using wpscan for vulnerabilities and outputs the results into a folder. 

This is still under developed and has multiple iterations.
