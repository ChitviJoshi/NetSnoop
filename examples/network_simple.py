#!/usr/bin/env python3
"""
Test Network Anomaly
This script will trigger a HIGH network alert (>30 connections)
"""

import socket
import time

print("🌐 Network Test - Opening multiple connections...")
print("   This will create 35 network connections")
print("   Your monitor should show a HIGH NETWORK alert within 10 seconds")

sockets = []

try:
    # Create multiple connections to various servers
    servers = [
        ('google.com', 80),
        ('github.com', 80),
        ('stackoverflow.com', 80),
        ('python.org', 80),
        ('wikipedia.org', 80),
    ]
    
    # Open 7 connections to each server (35 total)
    for i in range(7):
        for server, port in servers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((server, port))
                sockets.append(s)
                print(f"   Connection {len(sockets)}/35: {server}:{port}")
            except Exception as e:
                print(f"   Failed to connect to {server}: {e}")
    
    print(f"\n✅ Opened {len(sockets)} connections!")
    print("   Your monitor should show a NETWORK alert now")
    print("\n⏳ Keeping connections open... Press Ctrl+C to stop")
    
    # Keep connections open
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\n🔌 Closing connections...")
    for s in sockets:
        try:
            s.close()
        except:
            pass
    print("👋 Test complete!")

except Exception as e:
    print(f"\n❌ Error: {e}")
    for s in sockets:
        try:
            s.close()
        except:
            pass