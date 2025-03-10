import os
import logging
import datetime
import azure.functions as func
from azure.identity.aio import DefaultAzureCredential
from azure.keyvault.secrets.aio import SecretClient
from msgraph.generated.applications.item.add_password.add_password_post_request_body import (
    AddPasswordPostRequestBody,
)
from msgraph.generated.models.password_credential import PasswordCredential
from msgraph.graph_service_client import GraphServiceClient
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

app = func.FunctionApp()


# run_on_startup=False
@app.timer_trigger(
    schedule="0 */10 * * * *",  # Every 10 minutes
    arg_name="timer",
    run_on_startup=True,
    use_monitor=False,
)
async def secret_rotation(timer: func.TimerRequest) -> None:
    """Azure Function to rotate app registration secrets and update Key Vault."""
    try:
        logging.info(f"Secret rotation initiated at {utc_now().isoformat()}")

        # Validate environment configuration
        env_vars = validate_environment()

        async with DefaultAzureCredential() as credential:
            # Generate new secret
            new_secret = await create_graph_secret(
                credential=credential,
                app_object_id=env_vars["APP_REGISTRATION_OBJECT_ID"],
                expiration_days=env_vars["SECRET_EXPIRATION_DAYS"],
            )

            # Update Key Vault
            await update_key_vault_secret(
                credential=credential,
                keyvault_uri=env_vars["KEYVAULT_URI"],
                secret_name=env_vars["KEYVAULT_SECRET_NAME"],
                secret_value=new_secret,
            )

            # Cleanup old secrets
            await cleanup_old_secrets(
                credential=credential,
                app_object_id=env_vars["APP_REGISTRATION_OBJECT_ID"],
                retention_days=1,
            )

        logging.info("Secret rotation completed successfully")

    except ClientAuthenticationError as auth_error:
        logging.error(f"Authentication failed: {str(auth_error)}")
    except HttpResponseError as http_error:
        logging.error(f"HTTP error occurred: {str(http_error)}")
    except Exception as ex:
        logging.error(f"Unexpected error: {str(ex)}")
        raise


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def validate_environment() -> dict:
    """Validate and return required environment variables."""
    required_vars = [
        "TENANT_ID",
        "APP_REGISTRATION_OBJECT_ID",
        "KEYVAULT_URI",
        "KEYVAULT_SECRET_NAME",
    ]

    missing = [var for var in required_vars if not os.environ.get(var)]
    if missing:
        raise ValueError(f"Missing environment variables: {', '.join(missing)}")

    return {
        "APP_REGISTRATION_OBJECT_ID": os.environ["APP_REGISTRATION_OBJECT_ID"],
        "KEYVAULT_URI": os.environ["KEYVAULT_URI"],
        "KEYVAULT_SECRET_NAME": os.environ["KEYVAULT_SECRET_NAME"],
        # Set to 180 days
        "SECRET_EXPIRATION_DAYS": int(os.environ.get("SECRET_EXPIRATION_DAYS", "1")),
    }


async def create_graph_secret(
    credential: DefaultAzureCredential, app_object_id: str, expiration_days: int
) -> str:
    """Create a new client secret via Microsoft Graph."""
    now = utc_now()
    credential_name = f"Rotated-{now.strftime('%Y%m%d')}"

    password_credential = PasswordCredential(
        display_name=credential_name,
        end_date_time=now + datetime.timedelta(days=expiration_days),
    )

    client = GraphServiceClient(credential)
    result = await client.applications.by_application_id(
        app_object_id
    ).add_password.post(
        AddPasswordPostRequestBody(password_credential=password_credential)
    )

    if result is None or not result.secret_text:
        raise ValueError(
            "Failed to generate new secret - empty response from Graph API"
        )

    logging.info("New secret created")
    return result.secret_text


async def update_key_vault_secret(
    credential: DefaultAzureCredential,
    keyvault_uri: str,
    secret_name: str,
    secret_value: str,
) -> None:
    """Update the secret in Azure Key Vault."""
    async with SecretClient(vault_url=keyvault_uri, credential=credential) as client:
        await client.set_secret(
            secret_name,
            secret_value,
            content_type="AppSecret",
            expires_on=utc_now() + datetime.timedelta(days=180),
        )
    logging.info(f"Key Vault secret '{secret_name}' updated successfully")


async def cleanup_old_secrets(
    credential: DefaultAzureCredential, app_object_id: str, retention_days: int
) -> None:
    """Clean up secrets older than retention period."""
    client = GraphServiceClient(credential)
    app = await client.applications.by_application_id(app_object_id).get()

    if app is None or not app.password_credentials:
        logging.info("No secrets to clean up")
        return
    
    cutoff_date = utc_now() - datetime.timedelta(days=retention_days)

    for cred in app.password_credentials:
        if cred.end_date_time and cred.end_date_time < cutoff_date:
            from msgraph.generated.applications.item.remove_password.remove_password_post_request_body import (
                RemovePasswordPostRequestBody,
            )

            await client.applications.by_application_id(
                app_object_id
            ).remove_password.post(body=RemovePasswordPostRequestBody(key_id=cred.key_id))
