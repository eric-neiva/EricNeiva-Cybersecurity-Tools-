Network Intrusion Detection System (NIDS)

#Overview

This is a simple Python-based Network Intrusion Detection System (NIDS) that monitors network traffic for suspicious activities and potential threats.
The system uses the scapy library for packet sniffing, allowing it to analyze packets and detect various types of network traffic.

#Features
Packet Sniffing
Monitors network traffic on a specified interface.
TCP and UDP Analysis: Identifies TCP and UDP packets, including source and destination ports.
HTTP and HTTPS Detection: Flags potential HTTP and HTTPS traffic.
External Agent Monitoring: Tracks external IP addresses communicating with the network.
Prerequisites
Python 3.x
scapy library (pip install scapy)

#How to Use
Clone the repository

git clone https://github.com/yourusername/nids.git
cd nids

Install dependencies

pip install scapy

Run the NIDS

python nids.py
Make sure to replace eth0 with your actual network interface.

View the log

The NIDS logs events to nids_log.txt for future analysis.

#Customization Interface

Change the interface variable in the main function to match your network interface.
Internal IP Ranges: Update the internal_ranges list in the internal_ips method to define your internal IP address range(s).
Additional Notes
Ensure you have the necessary permissions to capture packets on the specified network interface.
Respect legal and ethical considerations when monitoring network traffic.

#Future Improvements

Implement more advanced packet analysis and threat detection.
Integrate with external threat intelligence feeds.
Enhance logging and reporting features.

Contributors
Eric Neiva

License
This project is licensed under the MIT License.

Feel free to customize the README further based on your specific requirements, add more details, and include any additional sections that might be relevant.
