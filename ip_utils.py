'''
RFC1918 private IP ranges
'''
def classify_ip(ip):
    if ip.startswith("10."):
        return "PRIVATE"
    if ip.startswith("192.168."):
        return "PRIVATE"
    if ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") \
       or ip.startswith("172.20.") or ip.startswith("172.21.") or ip.startswith("172.22.") or ip.startswith("172.23.") \
       or ip.startswith("172.24.") or ip.startswith("172.25.") or ip.startswith("172.26.") or ip.startswith("172.27.") \
       or ip.startswith("172.28.") or ip.startswith("172.29.") or ip.startswith("172.30.") or ip.startswith("172.31."):
        return "PRIVATE"
    
    # Any other IP ranges is Public
    return "PUBLIC"

def get_severity(ip_type):
    if ip_type == "PRIVATE":
        return "HIGH"
    return "MEDIUM"