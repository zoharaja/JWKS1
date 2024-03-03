# Import necessary dependencies and functions
from django.http import JsonResponse
from .utils import keys_store, generate_and_store_key, base_64
import jwt
import datetime
from cryptography.hazmat.primitives import serialization
from django.views.decorators.csrf import csrf_exempt
import logging 
from django.views.decorators.http import require_POST, require_GET

# Logger
logger = logging.getLogger(__name__)

# Function handles GET requests
@require_GET
@csrf_exempt
def get_keys(request):
    # Excludes expired keys
    valid_keys = [
        {
            'kty': 'RSA',
            'use': 'sig',
            'kid': kid,
            'alg': 'RS256',
            'n': base_64(key_info['public_numbers'].n),
            'e': base_64(key_info['public_numbers'].e)
        }
        for kid, key_info in keys_store.items() if key_info['expiry'] > datetime.datetime.utcnow()
    ]
    # returns JSON response with unexpired/valid keys
    return JsonResponse({'keys': valid_keys}, status=200)

# function handles POST requests
@require_POST
@csrf_exempt
def get_jwt(request):
    try:
        # Check for expired parameter
        expired = request.GET.get('expired', 'false').lower() == 'true'

        # Generate new key if expired
        if not keys_store or expired:
            kid = generate_and_store_key()
        else:
            # Get next available key
            kid = next(iter(keys_store))

        # Return the key info
        key_info = keys_store[kid]
        headers = {'kid': kid}
        payload = {
            'sub': '0610209900',
            'name': 'Zoha Raja',
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() - datetime.timedelta(minutes=1) if expired else datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }

        # Convert private key to PEM format
        private_key = key_info['private_key']
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Encodes JWT
        encoded_jwt = jwt.encode(payload, private_pem, algorithm='RS256', headers=headers)

        # Decode to string if necessary
        if isinstance(encoded_jwt, bytes):
            encoded_jwt = encoded_jwt.decode('utf-8')

        # Check if key is expired and remove it from keys_store
        if expired:
            del keys_store[kid]

        return JsonResponse({'jwt': encoded_jwt, 'token': encoded_jwt}, status=200)
    except Exception as e:

        # Log and return error
        logger.error(f"Error in get_jwt: {e}", exc_info=True)
        return JsonResponse({'error': 'Internal server error'}, status=500)