from unittest.mock import MagicMock, patch
import pytest
from agent.synthesizer import (
    verify_ollama_model,
    stream_vapt_synthesis,
    stream_chat_synthesis
)


def test_verify_ollama_model_offline():
    # When Ollama is offline or cannot connect
    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.list.side_effect = Exception("Connection refused")
        mock_client.return_value = mock_instance

        is_ready, msg = verify_ollama_model("gemma4")
        assert not is_ready
        assert "Could not connect to Ollama" in msg


def test_verify_ollama_model_found():
    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.list.return_value = {
            "models": [{"model": "gemma4:latest"}, {"model": "llama3:latest"}]
        }
        mock_client.return_value = mock_instance

        is_ready, msg = verify_ollama_model("gemma4")
        assert is_ready
        assert msg == "Ready"


def test_verify_ollama_model_default_gemma():
    # Verify default parameter "gemma" finds gemma:latest or gemma4:latest
    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.list.return_value = {
            "models": [{"model": "gemma:latest"}, {"model": "qwen2.5:0.5b"}]
        }
        mock_client.return_value = mock_instance

        is_ready, msg = verify_ollama_model()  # uses default "gemma"
        assert is_ready
        assert msg == "Ready"


def test_verify_ollama_model_not_found():
    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.list.return_value = {
            "models": [{"model": "llama3:latest"}]
        }
        mock_client.return_value = mock_instance

        is_ready, msg = verify_ollama_model("gemma4")
        assert not is_ready
        assert "not detected in local Ollama" in msg


def test_stream_vapt_synthesis_ingestion_error():
    tokens = list(stream_vapt_synthesis(""))
    assert len(tokens) == 1
    assert "Ingestion Error" in tokens[0]


def test_stream_vapt_synthesis_success():
    valid_json = '{"target": "test", "vulnerabilities": [{"title": "XSS", "severity": "MEDIUM"}]}'
    
    mock_chunks = [
        {"message": {"content": "Executive "}},
        {"message": {"content": "Summary"}},
    ]
    
    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.chat.return_value = iter(mock_chunks)
        mock_client.return_value = mock_instance

        tokens = list(stream_vapt_synthesis(valid_json, model_name="gemma4"))
        assert tokens == ["Executive ", "Summary"]


def test_stream_vapt_synthesis_inference_error():
    valid_json = '{"target": "test", "vulnerabilities": [{"title": "XSS", "severity": "MEDIUM"}]}'

    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.chat.side_effect = Exception("Out of VRAM")
        mock_client.return_value = mock_instance

        tokens = list(stream_vapt_synthesis(valid_json, model_name="gemma4"))
        assert len(tokens) == 1
        assert "Ollama Inference Error" in tokens[0]


def test_stream_chat_synthesis_success():
    mock_chunks = [
        {"message": {"content": "The "}},
        {"message": {"content": "critical finding "}},
        {"message": {"content": "is RCE."}},
    ]
    scan_context = {
        "metadata": {"target": "10.0.0.1", "authenticated_audit": True},
        "recon": {"total_hosts": 1},
        "findings": [{"title": "RCE", "severity": "CRITICAL"}]
    }
    messages = [{"role": "user", "content": "What is the worst bug?"}]

    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.chat.return_value = iter(mock_chunks)
        mock_client.return_value = mock_instance

        tokens = list(stream_chat_synthesis(messages, scan_context, model_name="gemma4"))
        assert tokens == ["The ", "critical finding ", "is RCE."]


def test_stream_chat_synthesis_default_gemma():
    mock_chunks = [{"message": {"content": "Gemma "}}, {"message": {"content": "Response"}}]
    scan_context = {"metadata": {}, "recon": {}, "findings": []}
    messages = [{"role": "user", "content": "Status check"}]

    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.chat.return_value = iter(mock_chunks)
        mock_client.return_value = mock_instance

        tokens = list(stream_chat_synthesis(messages, scan_context))
        assert tokens == ["Gemma ", "Response"]
        # Ensure client.chat was called with model='gemma'
        mock_instance.chat.assert_called_once()
        assert mock_instance.chat.call_args[1]["model"] == "gemma"


def test_stream_chat_synthesis_error():
    scan_context = {"metadata": {}, "recon": {}, "findings": []}
    messages = [{"role": "user", "content": "Hello"}]

    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.chat.side_effect = Exception("Daemon crashed")
        mock_client.return_value = mock_instance

        tokens = list(stream_chat_synthesis(messages, scan_context, model_name="gemma4"))
        assert len(tokens) == 1
        assert "Ollama Inference Error" in tokens[0]


def test_verify_ollama_model_airgap_mode():
    is_ready, msg = verify_ollama_model("airgap-autonomous")
    assert is_ready
    assert "Autonomous Air-Gap" in msg


def test_stream_chat_synthesis_airgap_mode():
    scan_context = {
        "metadata": {"target": "10.0.0.1", "scan_type": "Deep VAPT"},
        "recon": {"hosts": [{"ip": "10.0.0.1", "os": "Linux"}]},
        "findings": [{"title": "RCE", "severity": "CRITICAL", "affected_component": "10.0.0.1:80", "remediation": "Patch immediately"}]
    }
    messages = [{"role": "user", "content": "Generate executive summary"}]
    tokens = list(stream_chat_synthesis(messages, scan_context, model_name="airgap-autonomous"))
    assert len(tokens) > 1
    combined = "".join(tokens)
    assert "Executive Briefing" in combined
    assert "CRITICAL" in combined


def test_stream_vapt_synthesis_fallback():
    valid_json = '{"target": "10.0.0.1", "vulnerabilities": [{"title": "SQLi", "severity": "HIGH", "component": "10.0.0.1:80"}]}'
    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.chat.side_effect = Exception("Out of VRAM")
        mock_client.return_value = mock_instance

        tokens = list(stream_vapt_synthesis(valid_json, model_name="gemma4", fallback=True))
        assert len(tokens) > 1
        assert "Ollama Inference Error" in tokens[0]
        assert any("Executive Briefing" in t for t in tokens)


def test_stream_chat_synthesis_multimodal():
    scan_context = {"metadata": {"target": "10.0.0.1"}, "recon": {}, "findings": []}
    messages = [{"role": "user", "content": "Analyze this diagram"}]
    fake_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

    mock_chunks = [{"message": {"content": "Visual "}}, {"message": {"content": "Correlation"}}]
    with patch("ollama.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.chat.return_value = iter(mock_chunks)
        mock_client.return_value = mock_instance

        tokens = list(stream_chat_synthesis(messages, scan_context, model_name="gemma", images=[fake_b64]))
        assert tokens == ["Visual ", "Correlation"]
        # Verify images field was attached to the last user message
        sent_messages = mock_instance.chat.call_args[1]["messages"]
        user_msg = [m for m in sent_messages if m.get("role") == "user"][-1]
        assert user_msg.get("images") == [fake_b64]


def test_stream_chat_synthesis_multimodal_airgap():
    scan_context = {"metadata": {"target": "10.0.0.1"}, "recon": {}, "findings": []}
    messages = [{"role": "user", "content": "Analyze diagram"}]
    tokens = list(stream_chat_synthesis(messages, scan_context, model_name="airgap-autonomous", images=["fake_b64"]))
    combined = "".join(tokens)
    assert "Multimodal" in combined
    assert "Subnet" in combined or "Cartography" in combined


