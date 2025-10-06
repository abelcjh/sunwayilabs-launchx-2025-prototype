import os
import re
from typing import Literal
from langdetect import detect, DetectorFactory
from dotenv import load_dotenv
from providers import get_provider

# Import audit integration
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "audit"))
    from integration import audit_integration
    AUDIT_ENABLED = True
except ImportError:
    AUDIT_ENABLED = False
    print("⚠️ Audit system not available - conversations will not be audited")

# Import privacy integration
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "privacy"))
    from consent import ConsentManager
    from keybroker import KeyBroker
    PRIVACY_ENABLED = True
except ImportError:
    PRIVACY_ENABLED = False
    print("⚠️ Privacy system not available - data will not be encrypted")

load_dotenv()
DetectorFactory.seed = 0  # deterministic detection

# Initialize provider
provider = get_provider()

# Initialize privacy systems if available
consent_manager = None
key_broker = None
if PRIVACY_ENABLED:
    try:
        consent_manager = ConsentManager()
        key_broker = KeyBroker()
        print("✅ Privacy systems initialized")
    except Exception as e:
        print(f"⚠️ Failed to initialize privacy systems: {e}")
        PRIVACY_ENABLED = False

PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "rogerian_prompt.txt")
with open(PROMPT_PATH, "r", encoding="utf-8") as f:
    SYSTEM_PROMPT = f.read()

def detect_lang(text: str) -> Literal["en", "ms"]:
    try:
        lang = detect(text)
        if lang in ["ms", "id"]:
            return "ms"
        return "en"
    except Exception:
        return "en"

def create_consent_for_user(user_did: str, purpose: str = "Mental health support and counseling") -> str:
    """
    Create a consent receipt for a user.
    
    Args:
        user_did: User's Decentralized Identifier
        purpose: Purpose of data processing
        
    Returns:
        Consent ID if successful, None otherwise
    """
    if not PRIVACY_ENABLED or not consent_manager:
        print("⚠️ Privacy system not available")
        return None
    
    try:
        receipt = consent_manager.create_consent_receipt(
            subject_did=user_did,
            controller_did="did:example:mentalhealthbot",
            purpose=purpose,
            data_categories=["health_data", "conversation_data", "sentiment_data"],
            processing_activities=["analysis", "storage", "anonymization"],
            legal_basis="consent",
            retention_period_days=365
        )
        
        # Register on blockchain
        consent_manager.register_consent_on_blockchain(receipt)
        
        print(f"✅ Created consent for user {user_did}: {receipt.consent_id}")
        return receipt.consent_id
        
    except Exception as e:
        print(f"❌ Failed to create consent: {e}")
        return None


def check_user_consent(user_did: str) -> str:
    """
    Check if user has active consent, create if needed.
    
    Args:
        user_did: User's Decentralized Identifier
        
    Returns:
        Active consent ID
    """
    if not PRIVACY_ENABLED or not consent_manager:
        return None
    
    # Check existing consents for this user
    user_consents = consent_manager.list_consents_for_subject(user_did)
    
    # Find active consent
    for consent in user_consents:
        if consent_manager.check_consent_active(consent.consent_id):
            return consent.consent_id
    
    # Create new consent if none found
    return create_consent_for_user(user_did)


def encrypt_conversation_data(data: str, user_did: str) -> tuple:
    """
    Encrypt conversation data with user consent using key broker.
    
    Args:
        data: Data to encrypt
        user_did: User's Decentralized Identifier
        
    Returns:
        Tuple of (record_id, consent_id) or (None, None) if no consent
    """
    if not PRIVACY_ENABLED or not key_broker:
        return data, None
    
    consent_id = check_user_consent(user_did)
    if not consent_id:
        print(f"❌ No active consent for user {user_did}")
        return None, None
    
    # Store encrypted blob using key broker
    record_id = key_broker.store_blob(user_did, data, "conversation_data")
    return record_id, consent_id


def decrypt_conversation_data(record_id: str, user_did: str) -> str:
    """
    Decrypt conversation data using key broker.
    
    Args:
        record_id: Record ID to decrypt
        user_did: User's Decentralized Identifier
        
    Returns:
        Decrypted data or None if access denied
    """
    if not PRIVACY_ENABLED or not key_broker:
        return None
    
    return key_broker.fetch_blob(user_did, record_id, "conversation_data")


def rogerian_reply(user_input: str, user_did: str = None) -> dict:
    lang = detect_lang(user_input)
    lang_hint = "Bahasa Malaysia" if lang == "ms" else "English"

    crisis = bool(re.search(r"\b(suicide|kill myself|end it|bunuh diri)\b", user_input, re.I))

    system = SYSTEM_PROMPT + f"\nLanguage: {lang_hint}."
    if crisis:
        system += "\nUser may be in distress (crisis keywords detected). Respond with high empathy and share help-seeking options."

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_input},
    ]

    reply = provider.generate(messages)
    
    # Handle privacy and encryption if user DID provided
    record_id = None
    consent_id = None
    if user_did and PRIVACY_ENABLED:
        try:
            # Check/create consent for user
            consent_id = check_user_consent(user_did)
            if consent_id:
                # Encrypt and store sensitive conversation data
                conversation_data = f"User: {user_input}\nEVE: {reply}"
                record_id, _ = encrypt_conversation_data(conversation_data, user_did)
                if record_id:
                    print(f"🔒 Conversation data encrypted and stored: {record_id[:16]}...")
        except Exception as e:
            print(f"⚠️ Privacy handling failed: {e}")
    
    # Log conversation for audit if enabled
    if AUDIT_ENABLED:
        try:
            # Get current model information
            model_id = getattr(provider, 'model_id', None) if hasattr(provider, 'model_id') else None
            audit_integration.log_conversation(user_input, reply, lang, model_id)
        except Exception as e:
            print(f"⚠️ Audit logging failed: {e}")
    
    return {
        "reply": reply, 
        "language": lang,
        "consent_id": consent_id,
        "record_id": record_id,
        "encrypted": record_id is not None
    }
