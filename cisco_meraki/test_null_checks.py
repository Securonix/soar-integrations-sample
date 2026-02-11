#!/usr/bin/env python3
"""Test null checks for Cisco Meraki integration"""

import sys
sys.path.insert(0, 'app')

from cisco_meraki import Cisco_Meraki
from model.request_body import RequestBody

integration = Cisco_Meraki()

print("Testing null checks...")
print("-" * 50)

# Test 1: Null connectionParameters in test_connection
print("\n1. Testing null connectionParameters in test_connection:")
try:
    integration.test_connection(None)
    print("❌ FAILED: Should have raised exception")
except Exception as e:
    print(f"✅ PASSED: {str(e)}")

# Test 2: Missing api_key in connectionParameters
print("\n2. Testing missing api_key:")
try:
    integration.test_connection({})
    print("❌ FAILED: Should have raised exception")
except Exception as e:
    print(f"✅ PASSED: {str(e)}")

# Test 3: Valid connectionParameters with dict.get()
print("\n3. Testing valid connectionParameters:")
try:
    conn_params = {"api_key": "test_key_123"}
    integration._init_client(conn_params)
    assert integration.api_key == "test_key_123"
    assert integration.base_url == "https://api.meraki.com/api/v1"
    assert "Bearer test_key_123" in integration.headers["Authorization"]
    print("✅ PASSED: Connection initialized correctly")
except Exception as e:
    print(f"❌ FAILED: {str(e)}")

# Test 4: Null request object
print("\n4. Testing null request object:")
try:
    integration.meraki_get_networks(None)
    print("❌ FAILED: Should have raised exception")
except Exception as e:
    print(f"✅ PASSED: {str(e)}")

# Test 5: Request with null connectionParameters
print("\n5. Testing request with null connectionParameters:")
try:
    class MockRequest:
        connectionParameters = None
        parameters = {"organizationId": "123"}
    
    integration.meraki_get_networks(MockRequest())
    print("❌ FAILED: Should have raised exception")
except Exception as e:
    print(f"✅ PASSED: {str(e)}")

# Test 6: Request with null parameters
print("\n6. Testing request with null parameters:")
try:
    class MockRequest:
        connectionParameters = {"api_key": "test"}
        parameters = None
    
    integration.meraki_get_networks(MockRequest())
    print("❌ FAILED: Should have raised exception")
except Exception as e:
    print(f"✅ PASSED: {str(e)}")

# Test 7: Request with missing required parameter
print("\n7. Testing request with missing organizationId:")
try:
    class MockRequest:
        connectionParameters = {"api_key": "test"}
        parameters = {}
    
    integration.meraki_get_networks(MockRequest())
    print("❌ FAILED: Should have raised exception")
except Exception as e:
    print(f"✅ PASSED: {str(e)}")

print("\n" + "=" * 50)
print("All null check tests completed!")
