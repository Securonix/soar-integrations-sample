#!/usr/bin/env python3
"""Verify null checks are present in the code"""

import re

print("Verifying null checks in cisco_meraki.py...")
print("=" * 60)

with open('app/cisco_meraki.py', 'r') as f:
    content = f.read()

checks = [
    ("_init_client has connectionParameters null check", 
     r"if not connectionParameters:"),
    
    ("_init_client has api_key null check", 
     r"if not api_key:"),
    
    ("_init_client uses dict.get() for api_key", 
     r"api_key = connectionParameters\.get\('api_key'\)"),
    
    ("meraki_get_networks has request null check", 
     r"def meraki_get_networks.*?if not request or not request\.connectionParameters:", 
     re.DOTALL),
    
    ("meraki_get_networks has parameters null check", 
     r"def meraki_get_networks.*?if not request\.parameters:", 
     re.DOTALL),
    
    ("meraki_get_devices has request null check", 
     r"def meraki_get_devices.*?if not request or not request\.connectionParameters:", 
     re.DOTALL),
    
    ("meraki_get_device_uplink has request null check", 
     r"def meraki_get_device_uplink.*?if not request or not request\.connectionParameters:", 
     re.DOTALL),
    
    ("meraki_get_clients has request null check", 
     r"def meraki_get_clients.*?if not request or not request\.connectionParameters:", 
     re.DOTALL),
    
    ("meraki_remove_device has request null check", 
     r"def meraki_remove_device.*?if not request or not request\.connectionParameters:", 
     re.DOTALL),
    
    ("meraki_update_device has request null check", 
     r"def meraki_update_device.*?if not request or not request\.connectionParameters:", 
     re.DOTALL),
]

passed = 0
failed = 0

for check_name, pattern, *flags in checks:
    flag = flags[0] if flags else 0
    if re.search(pattern, content, flag):
        print(f"✅ {check_name}")
        passed += 1
    else:
        print(f"❌ {check_name}")
        failed += 1

print("=" * 60)
print(f"Results: {passed} passed, {failed} failed")

if failed == 0:
    print("\n✅ All null checks are properly implemented!")
    exit(0)
else:
    print(f"\n❌ {failed} null checks are missing!")
    exit(1)
