from packing import *

# Sender A sends to receiver B
original_message = b"Operation starts at 2200 hours"

# Pack message from A to B
packet = pack("A", "B", original_message)

# Unpack message at B's side
result = unpack("B", "A", packet)

# Print results
print("Decrypted Message:", result['message'])
print("Signature Valid:", result['signature_valid'])
print("Timestamp:", result['timestamp'])
