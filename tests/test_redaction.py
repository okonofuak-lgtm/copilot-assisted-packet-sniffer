from sniffer import mask_ip, redact_sensitive_data


def test_mask_ip_hides_last_octet():
	assert mask_ip("192.168.1.42") == "192.168.1.xxx"


def test_email_address_is_redacted():
	result = redact_sensitive_data("Contact student@example.test")

	assert result == "Contact [REDACTED_EMAIL]"


def test_authorization_header_value_is_redacted():
	result = redact_sensitive_data("Authorization: Bearer example-token")

	assert result == "Authorization: [REDACTED]"


def test_cookie_header_value_is_redacted():
	result = redact_sensitive_data("Cookie: lab_session=example-value")

	assert result == "Cookie: [REDACTED]"


def test_password_query_parameter_is_redacted():
	result = redact_sensitive_data("/login?password=example-value")

	assert result == "/login?password=[REDACTED]"


def test_token_query_parameter_is_redacted():
	result = redact_sensitive_data("/login?token=example-value")

	assert result == "/login?token=[REDACTED]"


def test_api_key_query_parameter_is_redacted():
	result = redact_sensitive_data("/lookup?api_key=example-value")

	assert result == "/lookup?api_key=[REDACTED]"


def test_session_query_parameter_is_redacted():
	result = redact_sensitive_data("/account?session=example-value")

	assert result == "/account?session=[REDACTED]"
