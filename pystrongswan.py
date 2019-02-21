#!/usr/bin/python3

import os
import subprocess

os.system("clear")
def scep_help():
    print("Simple Certificate Enrollment Protocol : 802x.1 Wired Authentication")
    print("")
    print("""Network Device Enrollment Service allows us to obtain certificates for routers
or other network devices using the Simple Certificate Enrollment Protocol (SCEP).

In order to complete certificate enrollment for network devices following
informations are required : 

=> CA certificate should be pre installed in your system.
=> The SCEP url http-or-https://scep_hostname or ip address/certsrv/mscep/mscep.dll
=> The enrollment challenge password.
=> Common Name,this will be for 802.1 Wired Authentication""")
print("")


def scep_envbuild():

    #Remove old certificates from scep path
    #While compilation of strongsawn set the config path to /etc else
    #it will go to default /usr/etc

    os.system("rm -rf /tmp/scep-certs/*")
    os.system("mkdir /tmp/scep-certs/")

    os.system("rm -rf /tmp/Final-Scep-Cert")
    os.system("mkdir /tmp/Final-Scep-Cert")

    os.system("rm -rf  /usr/etc/ipsec.d/cacerts/*")
    os.system("rm -rf /usr/etc/ipsec.d/certs/*")
    os.system("rm -rf /usr/etc/ipsec.d/private/*")
    os.system("rm -rf /usr/etc/ipsec.d/reqs/*")

    os.system("rm -rf  /etc/ipsec.d/cacerts/*")
    os.system("rm -rf /etc/ipsec.d/certs/*")
    os.system("rm -rf /etc/ipsec.d/private/*")
    os.system("rm -rf /etc/ipsec.d/reqs/*")

    print(" ")
    print("Preparing SCEP environment")
    print("--------------------------")
    #Check for IPSec service
    process_name="/usr/libexec/ipsec/starter"
    tmp=os.popen("ps -auxf").read()

    if process_name not in tmp[:]:
        os.system("ipsec start")
    else:
        print("IPSec service is running")


def final_certificate(scep_url,challengepass,cname):

    args = 'ipsec scepclient --out pkcs1=local_key.der --out cert=local_cert.der --dn  CN='+cname+' -p '+challengepass+ ' --url '+scep_url+ ' --in cacert-enc=caCert-ra-1.der --in cacert-sig=caCert-ra-2.der -f --debug 3 2>> /var/log/scep'
    check_pass = subprocess.call(args,shell=True,stdout=subprocess.PIPE)

    if check_pass > 0 :
        print("")
        print("Error: SCEP Enrollment failed.Please check /var/log/scep")
    else:
        print("")
        print("SCEP Enrollment Successfull.Please check /var/log/scep")
        print("")
        print("Bulding SCEP Certificate : /usr/etc/ipsec.d/certs")
        args1 = 'openssl x509 -inform der -outform pem -in /usr/etc/ipsec.d/certs/local_cert.der -out /usr/etc/ipsec.d/certs/'+cname+'-scep.pem'
        subprocess.call(args1,shell=True,stdout=subprocess.PIPE)
        print("")
        print("Building Private Key : /usr/etc/ipsec.d/private/")
        args2 = 'openssl pkey -inform der -outform pem -in /usr/etc/ipsec.d/private/local_key.der -out /usr/etc/ipsec.d/private/Private_key-scep.pem'
        subprocess.call(args2,shell=True,stdout=subprocess.PIPE)



def download_ca_ra_certificates(scep_url,challengepass,cname):

    args1 = '/usr/sbin/ipsec scepclient --out caCert --url ' +scep_url +' -f --debug 3 2>> /tmp/scep_log'
    p = subprocess.call(args1,shell=True,stdout=subprocess.PIPE)
    
    if p > 0 :
        print("")
        print("Error: SCEP Enrollment failed. Please check /tmp/scep_log")
    else:
        print("")
        print("Generating RSA PKCS10 Key")
        #Generating RSA Private Key
        args2 = 'ipsec scepclient --out pkcs1=local_key.der -k 2048 -f'
        subprocess.call(args2,shell=True,stdout=subprocess.PIPE)

        #Generate a PKCS#10 request and store it in file HOSTNAME.der
        args3 = 'ipsec scepclient --out pkcs1=local_key.der -k 2048 -f'
        args4 = 'ipsec scepclient --in pkcs1=local_key.der --out pkcs10=local_req.der --dn CN='+cname +' -p '+ challengepass+ ' -f'
        subprocess.call(args3,shell=True,stdout=subprocess.PIPE)
        subprocess.call(args4,shell=True,stdout=subprocess.PIPE)


def converting_certificates():

        #Converting DER Certificates to PEM Certificates
        cert_dir = "/usr/etc/ipsec.d/cacerts/"

        for cert_file in os.listdir(cert_dir):
            args5 = 'openssl x509 -inform der -outform pem -in '+cert_dir+cert_file+ ' -out /tmp/scep-certs/'+cert_file.split('.')[0]+'.pem'
            subprocess.call(args5,shell=True,stdout=subprocess.PIPE)

        #Getting CA,Key Encipherment,Digital Signature
        scep_cert_dir = "/tmp/scep-certs/"

        for scep_cert in os.listdir(scep_cert_dir):

            args6 = 'openssl x509 -in '+scep_cert_dir+scep_cert+ ' -text -noout | grep  "CA:TRUE"'
            status6 = subprocess.call(args6,shell=True,stdout=subprocess.PIPE)

            if status6 == 0 :
                print("")
                print("Building CA Certificate")
                mv_args = 'cp '+scep_cert_dir+scep_cert+' '+scep_cert_dir+scep_cert.split('.')[0]+'-CA.pem'
                subprocess.call(mv_args,shell=True,stdout=subprocess.PIPE)

            args7 = 'openssl x509 -in '+scep_cert_dir+scep_cert+ ' -text -noout | grep "Key Encipherment"'
            status7 = subprocess.call(args7,shell=True,stdout=subprocess.PIPE)

            if status7 == 0:
                print("")
                print("Building Key Encipherment Certificate")
                mv_args = 'cp '+scep_cert_dir+scep_cert+' '+scep_cert_dir+scep_cert.split('.')[0]+'-Enc.pem'
                subprocess.call(mv_args,shell=True,stdout=subprocess.PIPE)

            args8 = 'openssl x509 -in '+scep_cert_dir+scep_cert+ ' -text -noout | grep "Digital Signature"'
            status8 = subprocess.call(args8,shell=True,stdout=subprocess.PIPE)

            if status8 == 0:
                print("")
                print("Building Digital Signature Certificate")
                mv_args = 'cp '+scep_cert_dir+scep_cert+' '+scep_cert_dir+scep_cert.split('.')[0]+'-Disg.pem'
                subprocess.call(mv_args,shell=True,stdout=subprocess.PIPE)


if __name__ == '__main__':

    scep_help()
    print("")
    user_input1 = input("Enter the SCEP Enrollment URL: ")
    user_input2 = input("Enter the Challenge Password : ")
    user_input3 = input("Enter the Common Name        : ")

    scep_envbuild()
    download_ca_ra_certificates(user_input1,user_input2,user_input3)
    final_certificate(user_input1,user_input2,user_input3)
    converting_certificates()
