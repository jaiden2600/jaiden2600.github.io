---
title: "The Process of Building my Proxmox Homelab"
---

## Overview
Recently, I purchased a Lenovo ThinkCentre Mini PC to transform into a server that will be my new homelab machine. While this is not high end, it provides enough resources for my current requirements, and if ever in the future I need to upgrade RAM or Storage the model I bought makes that easy. This project cost me around $160 in total.

I chose Proxmox because I wanted a centralized management platform where I could easily configure containers, virtual machines, and create development environments.

### Goals
This homelab will be designed to host all of my media, self-host some services, host vulnerable labs, learn some system administration, and also create my own personal infrastructure platform.

### Hardware

| Component | Model                    |
| --------- | ------------------------ |
| Mini PC   | Lenovo ThinkCentre M720q |
| CPU       | Intel i5 8400t           |
| RAM       | 8GB                      |
| SSD       | 256GB SSD                |
| GPU       | Intel UHD Graphics 630   |

The ThinkCentre M720q was chosen because it provides a good balance between cost, performance, and upgradeability. Other small computers like business PCs are also widely available, such as Dell.

### Network Diagram
![Network Diagram Photo](/assets/images/proxmox-homelab/diagram.png)

---
## Installing Proxmox
Installation was a straightforward process. I used my USB that has [Ventoy](https://www.ventoy.net/en/index.html) setup on it, downloaded the latest Proxmox VE ISO image and copied it into the USB. Using Ventoy made the installation process easier because I already had a reusable boot drive instead of needing to reflash my USB every time I booted from a different ISO.

Next step was getting Proxmox actually installed on the disk, so I connected peripherals to the Mini PC, booted from the USB, and went through the Proxmox VE installer.

### Initial Configuration
After a successful installation, I did some post-install setup, there are [Helper Scripts](https://community-scripts.org/) that can assist with common issues after installing, but I just did some manual fixes such as removing enterprise repositories from the update list.

Additonal Configuration included:
- Updating Proxmox packages
- Configuring network settings (Giving it a Static IP in my routers settings)
- Setting up a storage mount (Just my media HDD)

---
## Setting up Containers
I chose containers over virtual machines for most services because they have lower overhead and allow me to run more lightweight services on limited hardware. Virtual machines are reserved for cases where full OS isolation is required.

### My First Container
The first container I chose to setup was an **Ubuntu 24.04** system. This is mainly because there are lots of benefits from just having a spare 24/7 terminal. Personally, the main benefit I get from one is having it host my scripts and various tools to perform long-term scanning against Bug Bounty / VDP web targets. Another reason is just for unexpected scenarios, such as a long running task that isn't worth making an entire container for, and you also wouldn't need to keep your computer running.

### Jellyfin
Jellyfin is a self-hosted media server that allows me to organize and stream my media across different devices on my network. I chose Jellyfin because it is lightweight, and it doesn't require relying on third party services. The media is on a dedicated HDD attached to the server, because it keeps media separated from the OS storage and makes adding new media way easier.

### Virtual Machines vs Containers
For most services, containers provide everything I need while consuming fewer resources and less overhead. Virtual machines will mainly be used for situations requiring more isolation, such as security labs.

---
## Security
There is not too much for this section about Security, because I am not making this accessible from the public-facing internet.

The main security approach for this setup is minimizing exposure:
- Services are only accessible from the local network
- No ports are directly forwarded from the internet
- Containers and virtual machines are isolated through Proxmox
- Software updates are applied regularly

Since this is just my own private homelab, the primary security is reducing attack surface rather than adding unnecessary complexity.

---
## What I learned
- I underestimated how useful snapshots are when experimenting with new software / configurations
- Planning and resources matter, if you give too much resources to a container / VM then it will be a hassle changing it when you need those reesources back. This may seem self explanatory, but even if you don't plan on adding more VM's / Containers, you never know if you might want too later on.
- Simple designs are easier to maintain and modify. Adding many services immediately, increases maintenance requirements and more ways problems could occur