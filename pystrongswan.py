#!/usr/bin/python3

import os
os.system("clear")
def scep_help():
    print("Simple Certificate Enrollment Protocol : 802x.1 Wired Authentication")
    print("")
    print("""Network Device Enrollment Service allows us to obtain certificates for routers
or other network devices using the Simple Certificate Enrollment Protocol (SCEP).

In order to complete certificate enrollment for network devices following
informations are required : 

=> CA certificate which is pre installed in the system.
=> The SCEP url http-or-https://scep_hostname or ip address/certsrv/mscep/mscep.dll
=> The enrollment challenge password.
=> Extra information,Common Name.This will be for 802.1 Wired Authentication""")
print("")


def scep_envbuild():

    pass



if __name__ == '__main__':
    scep_help()
    print("")
    user_input1 = input("Enter the SCEP Enrollment URL: ")
    user_input2 = input("Enter the Challenge Password : ")
    user_input3 = input("Enter the Common Name        : ")
