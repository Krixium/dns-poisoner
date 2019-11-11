# DNS Poisoner
Poisons all the DNSs.

## Usage
Edit the configuration files and run:

    ./dns-poisoner

##  Configuration
IMPORTANT: The both the configuration files must be in the same directory as the executable.

All the configuration files use the same format:

```
# comment
key=value
```

poisoner.conf valid values:
- victimIp(required): The IP of the host you wish to attack.
- gatewayIp(required): The IP of the gateway that the victim uses.
- interfaceName(required): The name of the network interface to use.

spoofed_domains.conf valid values:

This configuration file takes in 1 or more likes in the following format www.google.ca=192.168.1.1. Where the key is the domain to spoof and the key is the address to spoof it with.