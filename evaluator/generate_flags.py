
"""
Generate XOR-encrypted flag hex values for all challenges.
Usage: python3 generate_flags.py
"""

FLAG_SECRET = "P2P"  # Must match .env
FLAG_SECRET_BYTES = FLAG_SECRET.encode("utf-8")

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR encrypt data with key"""
    if not key:
        raise ValueError("FLAG_SECRET must not be empty")
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def generate_flag_hex(flag_text: str) -> str:
    """Generate XOR hex for a flag text"""
    plaintext = flag_text.encode("utf-8")
    encrypted = xor_bytes(plaintext, FLAG_SECRET_BYTES)
    return encrypted.hex()

# All 28 challenges with their flags
all_challenges = [
    # DEMO CHALLENGES (101-103)
    ("DEMO_FIREWALL_BASICS", "F1r3w4LL_B4s1cs_L34rn3d"),
    ("DEMO_IPSET_BASICS", "1Ps3t_M4st3r_Un10ck3d"),
    ("DEMO_ZERO_TRUST", "Z3r0_Tru5t_F0und4t10n_Bu1Lt"),
    
    # CATEGORY 1: ZERO TRUST (1-5)
    ("ZEROTRUST_BOARD_MEETING", "Z3r0_Tru5t_P0L1cy"),
    ("ZEROTRUST_DNS_BROKEN", "DNS_R3s0Lut10n_F1x3d"),
    ("ZEROTRUST_INSIDER_THREAT", "C2_S3rv3r_Bl0ck3d"),
    ("ZEROTRUST_SELECTIVE_PARTNER", "S3L3ct1v3_3gr3ss_C0ntr0L"),
    ("ZEROTRUST_DNS_HIJACK", "DN5_H1j4ck_M1t1g4t3d"),
    
    # CATEGORY 2: PERIMETER DEFENSE (6-10)
    ("PERIMETER_BRUTE_FORCE", "SSH_P0rt_S3cur3d"),
    ("PERIMETER_ICMP_FLOOD", "1CMP_FL00d_St0pp3d"),
    ("PERIMETER_AFTER_HOURS", "T1m3_B4s3d_4cc3ss"),
    ("PERIMETER_PARTNER_SUBNET", "Subn3t_S3gm3nt4t10n"),
    ("PERIMETER_SSH_FORTRESS", "SSH_R4t3_L1m1t_3n4bL3d"),
    
    # CATEGORY 3: DATA LOSS PREVENTION (11-15)
    ("DATALOSS_MALWARE_C2", "M4lw4r3_C2_Bl0ck3d"),
    ("DATALOSS_GDPR_FTP", "FTP_Pr0t0c0L_Bl0ck3d"),
    ("DATALOSS_TEMP_EXCEPTION", "T3mp0r4ry_4cc3ss_Gr4nt3d"),
    ("DATALOSS_DNS_TUNNEL", "DNS_TunN3L_Pr3v3nt3d"),
    ("DATALOSS_AUTO_QUARANTINE", "4ut0m4t3d_Qu4r4nt1n3"),
    
    # CATEGORY 4: TRAFFIC MANAGEMENT (16-20)
    ("TRAFFIC_BANDWIDTH_HOG", "Tr4ff1c_Pr0f1L3_Cr34t3d"),
    ("TRAFFIC_COST_OPTIMIZE", "0ffH0urs_Th0ttL3_4ppl13d"),
    ("TRAFFIC_WEEKEND_CRISIS", "W33k3nd_B4ndw1dth_C0ntr0L"),
    ("TRAFFIC_TIERED_SERVICE", "T13r3d_S3rv1c3_4ct1v3"),
    ("TRAFFIC_DYNAMIC_OPTIMIZER", "C0st_0pt1m1z3r_D3pL0y3d"),
    
    # CATEGORY 5: RECONNAISSANCE PREVENTION (21-25)
    ("RECON_STEALTH_MODE", "St3aLth_M0d3_0n"),
    ("RECON_SCANNER_BLOCK", "Sc4nn3r_1P_Bl0ck3d"),
    ("RECON_ROTATING_FEED", "R0t4t1ng_Thr34t_F33d"),
    ("RECON_MULTIVECTOR", "Mult1V3ct0r_D3f3ns3"),
    ("RECON_BEHAVIORAL_DETECT", "B3h4v10r_D3t3ct10n_4ct1v3"),
]

if __name__ == "__main__":
    print("=" * 80)
    print("FLAG XOR HEX VALUES FOR ALL 28 CHALLENGES")
    print("=" * 80)
    print(f"FLAG_SECRET: {FLAG_SECRET}")
    print("=" * 80)
    print()
    
    for i, (challenge_id, flag_text) in enumerate(all_challenges, 1):
        hex_value = generate_flag_hex(flag_text)
        print(f"{i:2d}. {challenge_id}")
        print(f"    Flag: {flag_text}")
        print(f"    Hex:  {hex_value}")
        print()
    
    print("=" * 80)
    print("Copy the hex values above into challenges.json")
    print("=" * 80)
