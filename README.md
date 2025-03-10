# python-secret-rotator
Azure app registrations need client secrets to authenticate clients. I needed a way to update them without having to go to the Azure portal.

This is a function that will update the client secret for an app registration, then update the secret in Azure Key Vault in order to make it available to client apps.
