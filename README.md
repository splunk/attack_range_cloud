# Splunk Cloud Attack Range

## Purpose
The Cloud Attack Range is a detection development platform, which solves three main challenges in detection engineering. First, the user is able to build quickly a small lab infrastructure as close as possible to a cloud environment. Second, the Attack Range performs attack simulation using different engines such as [Leonidas](https://github.com/FSecureLABS/leonidas) in order to generate real attack data. Third, it integrates seamlessly into any Continuous Integration / Continuous Delivery (CI/CD) pipeline to automate the detection rule testing process.  

## Architecture
The Cloud Attack Range consists of:
- pre-configured Splunk server with AWS Cloudtrail logs and Kubernetes logs
- pre-configured Phantom server
- AWS Elastic Kubernetes Service with a Wordpress app and [Splunk Connect for Kubernetes](https://github.com/splunk/splunk-connect-for-kubernetes)
- integrated [Leonidas](https://github.com/FSecureLABS/leonidas) cloud attacks

![Architecture](docs/cloud_attack_range_architecture.png)

### Logging
The following log sources are collected from the machines:
- Cloudtrail logs (```index = aws```)
- Kubernetes logs (```index = kubernetes OR index = kubernetes-metrics```)

## Running
Follow [Getting Started](https://github.com/splunk/attack_range_cloud/wiki/Configure-Cloud-Attack-Range) to configure Cloud Attack Range.  
Cloud Attack Range supports different actions:
- Build Cloud Attack Range
- Perform Cloud Attack Simulation
- Destroy Cloud Attack Range
- Stop Cloud Attack Range
- Resume Cloud Attack Range

### Build Cloud Attack Range
- Build Cloud Attack Range
```
python cloud_attack_range.py -a build
```

### Perform Cloud Attack Simulation
- Perform Cloud Attack Simulation by Mitre technique
```
python cloud_attack_range.py -a simulate -st T1136.003
```
- Perform Cloud Attack Simulation by Leonidas attack file
```
python cloud_attack_range.py -a simulate -sf leonidas/definitions/persistence/add_api_key_to_iam_user.yml -sv "user=patrick-test"
```
- Perform Cloud Attack Simulation by Leonidas attack file using custom variables and without prompt:
```
python cloud_attack_range.py -a simulate -sf leonidas/definitions/persistence/add_api_key_to_iam_user.yml -sv "user=patrick-test" --force
```

### Destroy Cloud Attack Range
- Destroy Cloud Attack Range
```
python cloud_attack_range.py -a destroy
```

### Stop Cloud Attack Range
- Stop Cloud Attack Range
```
python cloud_attack_range.py -a stop
```

### Resume Cloud Attack Range
- Resume Cloud Attack Range
```
python cloud_attack_range.py -a resume
```

## Features
- [Splunk Server](https://github.com/splunk/attack_range/wiki/Splunk-Server)
  * Indexing of Microsoft Event Logs, PowerShell Logs, Sysmon Logs, DNS Logs, ...
  * Preconfigured with multiple TAs for field extractions
  * Out of the box Splunk detections with Enterprise Security Content Update ([ESCU](https://splunkbase.splunk.com/app/3449/)) App
  * Preinstalled Machine Learning Toolkit ([MLTK](https://splunkbase.splunk.com/app/2890/))
  * Splunk UI available through port 8000 with user admin
  * ssh connection over configured ssh key

- [Splunk Enterprise Security](https://splunkbase.splunk.com/app/263/)
  * [Splunk Enterprise Security](https://splunkbase.splunk.com/app/263/) is a premium security solution requiring a paid license.
  * Enable or disable [Splunk Enterprise Security](https://splunkbase.splunk.com/app/263/) in [attack_range.conf](attack_range.conf)
  * Purchase a license, download it and store it in the apps folder to use it.

- [Splunk Phantom](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html)
  * [Splunk Phantom](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html) is a Security Orchestration and Automation platform
  * For a free development license (100 actions per day) register [here](https://my.phantom.us/login/?next=/)
  * Enable or disable [Splunk Phantom](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html) in [attack_range.conf](attack_range.conf)

- [Leonidas](https://github.com/FSecureLABS/leonidas)
  * Attack Simulation with [Leonidas](https://github.com/FSecureLABS/leonidas)
  * Uses the cloud attack TTPs in [leonidas/definitions](leonidas/definitions)
  * Leonidas uses the Cloud Attack Mitre IDs


## Support
Please use the [GitHub issue tracker](https://github.com/splunk/attack_range_cloud/issues) to submit bugs or request features.

If you have questions or need support, you can:

* Post a question to [Splunk Answers](http://answers.splunk.com)
* Join the [#security-research](https://splunk-usergroups.slack.com/messages/C1RH09ERM/) room in the [Splunk Slack channel](http://splunk-usergroups.slack.com)
* If you are a Splunk Enterprise customer with a valid support entitlement contract and have a Splunk-related question, you can also open a support case on the https://www.splunk.com/ support portal


## Author
* [Patrick Bareiß](https://twitter.com/bareiss_patrick)
* [Bhavin Patel](https://twitter.com/hackpsy)
