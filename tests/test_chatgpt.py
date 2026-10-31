from types import SimpleNamespace as NS
from unittest.mock import Mock
import pytest
from src.llm.chatgpt_provider import ChatGPTProvider
from src.llm.base import LLMError
from test_providers import response


class Stream:
    def __init__(self, events): self.events = events
    def __enter__(self): return iter(self.events)
    def __exit__(self, *args): pass


def provider(events):
    auth, sdk = Mock(), Mock()
    auth.access_token.return_value = "test-token"
    auth.http.get.return_value.status_code = 200
    auth.http.get.return_value.json.return_value = {"models": [{"slug": "test", "visibility": "list"}]}
    sdk.responses.create.return_value = Stream(events)
    return ChatGPTProvider("test", auth=auth, client_factory=lambda **kw: sdk), sdk


def test_chatgpt_stream_shape_and_completion():
    client, sdk = provider([NS(type="response.completed", response=response())])
    assert client.generate("s", "u").provider == "chatgpt"
    args = sdk.responses.create.call_args.kwargs
    assert args["stream"] is True and args["store"] is False
    assert "max_output_tokens" not in args and "temperature" not in args


@pytest.mark.parametrize("events,code", [([], "interrupted_stream"), ([NS(type="response.incomplete")], "stream_failed"), ([NS(type="response.refusal.delta")], "refusal")])
def test_interrupted_stream_never_validates(events, code):
    client, sdk = provider(events)
    with pytest.raises(LLMError, match=code): client.generate("s", "u")
    sdk.close.assert_called_once()


def test_vault_large_records_rotate_without_plaintext_files():
    from src.llm.chatgpt_auth import CredentialStore
    class Vault:
        def __init__(self): self.entries = {}
        def get_password(self, service, user): return self.entries.get((service, user))
        def set_password(self, service, user, value):
            assert len(value.encode("utf-16-le")) <= 2560
            self.entries[service, user] = value
        def delete_password(self, service, user): del self.entries[service, user]
    store = CredentialStore.__new__(CredentialStore)
    store.keyring = Vault()
    record = {"access_token": "x" * 8000, "host_id": "test"}
    store.save(record)
    assert store.load() == record
    old_keys = set(store.keyring.entries) - {("SecureIaC", "siwc-manifest")}
    store.save({"host_id": "test", "accounts": {}})
    assert not old_keys & store.keyring.entries.keys()
