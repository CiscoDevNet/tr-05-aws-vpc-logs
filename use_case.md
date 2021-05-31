Integrating SecureX with AWS to reduce dwell time and increase efficiency
=====================================
Cisco SecureX AWS VPC Flow Relay

## Business Case
SecureX is a cloud-native, built-in platform that connects our Cisco Secure portfolio and your infrastructure. It allows you to radically reduce dwell time and human-powered tasks. For SecureX, the Cisco Threat Intelligence Model (CTIM) is a Wikipedia, an abstract model that organizes data and defines data relationships. CTIM is of utmost importance for SecureX because it provides a common representation of threat information, regardless of whether its source is Cisco or a third party. In the following sections, we will dive deeper into CTIM and its components. 

Serverless relay modules are the components that enable SecureX integrations with third-party security solutions. They are serverless Python Flask applications that are intended to be deployed into AWS as Lambda applications. Because they are Flask applications, they could basically be deployed into any Python-capable host. The important feature that serverless relay modules can do, is that they can translate back and forth between CTIM, and whatever data model the third-part solution is using.  

This entire solution is built for SecureX and AWS:
* Dashboard tiles in SecureX to view high-level statistics and pivot straight into AWS. 
* Ability to query VPC flow logs from SecureX threat response (both internal and public IP address (NAT)). 
* Ability to isolate EC2 instance from SecureX threat response response API and drop down menu (both internal and public IP address (NAT)).

## Related Code Exchange submission
Please see the serverless relay module installation information [here](https://developer.cisco.com/codeexchange/github/repo/CiscoDevNet/tr-05-aws-vpc-logs).

## White Paper
Please continue your reading in this [From Complex to Cohesive](https://www.cisco.com/c/en/us/products/collateral/security/white-paper-c11-744498.html) white paper. Also please read this [SecureX and Public CloudAmazon Web Services]( https://blogs.cisco.com/developer/securexaws01).

## Related Sandbox
Currently there is no DevNet sandbox yet, however you can find all options to try out the [SecureX sandbox](https://developer.cisco.com/learning/tracks/SecureX)! Also, anyone can create a SecureX account for free.

## List of SecureX Learning Labs
* Please try out this [SecureX DevNet learning lab](https://developer.cisco.com/learning/modules/securex-serverless-relay-modules) to try this yourself. 
* Please also check out the [SecureX dev center](https://developer.cisco.com/securex/) on DevNet!

## Solutions on Ecosystem Exchange
Please check out related solutions on [DevNet Ecosystem Exchange](https://developer.cisco.com/ecosystem/solutions/#key=securex).
