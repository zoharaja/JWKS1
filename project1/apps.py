from django.apps import AppConfig
from .utils import generate_and_store_key

class YourAppConfig(AppConfig):
    name = 'project1'

    def ready(self):
        # Generate and store an initial key
        generate_and_store_key()