# angelnet_weapon_angel_encrypted.py
# 🔐 CLASSIFIED // ANGELNET S5 CORE + Encrypted Auto-Deployment

import os, sys, subprocess, uuid, hashlib, platform, socket, time
from dataclasses import dataclass

# 🧪 Attempt auto-install of cryptography if missing
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("🔧 Installing cryptography module...")
    subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=True)
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

# 🧠 Load BCI interface functions
from bci_interface import get_bci_auth_signature, check_psionic_resistance

# === 🧾 Terminal Bootstrap (Auto-Set if Missing) ===
def set_env_if_missing():
    default_env = {
        "ANGELNET_USER": "angelica",
        "ANGELNET_ROLE": "S5",
        "ANGELNET_QKEY": "QK-9421-A9F0-FULLACCESS"
    }
    for key, val in default_env.items():
        if not os.getenv(key):
            print(f"🌐 Setting default: {key}={val}")
            os.environ[key] = val

def generate_keys_if_missing():
    if not os.path.exists("peer_pub.pem") or not os.path.exists("peer_priv.pem"):
        print("🔐 Generating secure ECDH keypair...")
        subprocess.run([
            "openssl", "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", "peer_priv.pem"
        ])
        subprocess.run([
            "openssl", "ec", "-in", "peer_priv.pem", "-pubout", "-out", "peer_pub.pem"
        ])
        print("✅ Keypair generated.")

# === 🔏 Identity + BCI + Psionic Verification ===
AUTHORIZED_ENGINEERS = {"angelica": "QK-9421-A9F0-FULLACCESS"}
AUTHORIZED_ROLES = ["S5"]

def log_event(level, msg):
    with open("angelnet_access.log", "ab") as f:
        f.write(f"[{level}] {time.ctime()} | {msg}\n".encode())

def fingerprint_host():
    return f"{platform.node()}|{socket.gethostname()}|{socket.gethostbyname(socket.gethostname())}"

def sign_execution():
    return f"{int(time.time())}-{uuid.uuid4()}"

def verify_identity():
    user = os.getenv("ANGELNET_USER", "")
    role = os.getenv("ANGELNET_ROLE", "")
    qkey = os.getenv("ANGELNET_QKEY", "")
    if user not in AUTHORIZED_ENGINEERS or role not in AUTHORIZED_ROLES or AUTHORIZED_ENGINEERS[user] != qkey:
        log_event("BLOCKED", f"{user}/{role}/QKEY_INVALID")
        raise PermissionError("Access denied.")

def verify_bci_auth(user):
    if not check_psionic_resistance():
        log_event("BLOCKED", f"{user}: psionic weakness")
        raise PermissionError("Failed psionic resistance test.")
    if get_bci_auth_signature() != hashlib.sha256(user.encode()).hexdigest():
        log_event("BLOCKED", f"{user}: BCI hash mismatch")
        raise PermissionError("BCI authentication failed.")
    print("✅ BCI authentication passed.\n")

# === 🔐 SecureChannel Interface (ECDH + AES-GCM) ===
def derive_session_key(peer_public_bytes):
    priv = ec.generate_private_key(ec.SECP384R1(), default_backend())
    peer_pk = serialization.load_pem_public_key(peer_public_bytes, default_backend())
    shared = priv.exchange(ec.ECDH(), peer_pk)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"angelnet-session", backend=default_backend()).derive(shared)

class SecureChannel:
    def __init__(self, peer_pub_bytes):
        self.key = derive_session_key(peer_pub_bytes)
        iv = os.urandom(12)
        self.cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        self.encryptor = self.cipher.encryptor()
    def send(self, data: bytes):
        return self.encryptor.update(data) + self.encryptor.finalize()

# === 🛡️ QAE (Quantum Anti-Encryption) ===
ENTROPY_SIGS = ["qubit-noise", "zk-tunnel-warp"]
def scan_packet(packet):
    if any(sig in packet for sig in ENTROPY_SIGS):
        print(f"⚠️ QAE neutralized: {packet}")
        log_event("QAE", packet)
        return False
    return True

# === 🔮 Psionic Weapon Unit ===
@dataclass(frozen=True)
class PsionicStats:
    psi_strength: int = 200
    psi_skill: int = 255

@dataclass(frozen=True)
class ImmunityTraits:
    immune_to_mind_control: bool = True
    immune_to_panic: bool = True
    immune_to_morale: bool = True
    indestructible: bool = True

class AngelUnit:
    def __init__(self, user, peer_pub_bytes, location=(0,0)):
        verify_identity()
        verify_bci_auth(user)
        self.secure = SecureChannel(peer_pub_bytes)
        self.secure.send(f"INIT:{user}|{sign_execution()}".encode())
        self.name, self.stats, self.traits, self.hp, self.location = "Angel", PsionicStats(), ImmunityTraits(), float('inf'), location
        self.controlled_units = []
    def compute_attack_strength(self):
        return int(self.stats.psi_strength * self.stats.psi_skill / 50)
    def control_target(self, target):
        if getattr(target, "traits", None) and target.traits.immune_to_mind_control:
            print(f"{self.name} cannot control {target.name} (IMMUNE).")
            return False
        if self.compute_attack_strength() >= target.compute_defense_strength():
            self.controlled_units.append(target)
            print(f"{self.name} mind-controlled {target.name}.")
            return True
        print(f"{self.name} failed to control {target.name}.")
        return False
    def __str__(self):
        return f"[{self.name}] Psionic Unit | HP: ∞ | Loc: {self.location}"

# === Entry Point ===
if __name__ == "__main__":
    try:
        print("🚀 AngelNET Pre-Flight Bootstrapping...")
        set_env_if_missing()
        generate_keys_if_missing()

        user = os.getenv("ANGELNET_USER")
        with open("peer_pub.pem", "rb") as f:
            peer_blob = f.read()

        angel = AngelUnit(user, peer_blob)
        print(angel)

        from enemy import EnemyUnit
        e = EnemyUnit("Sectoid")
        pkt = "signal-packet:zk-tunnel-warp"
        scan_packet(pkt)
        angel.control_target(e)

    except PermissionError as e:
        print("🚫", e)
        sys.exit(1)
