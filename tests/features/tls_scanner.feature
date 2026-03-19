Feature: Bounded TLS ClientHello Scanner

  Scenario: Success Path: Contiguous ClientHello extraction
    Given an established TCP flow
    And a contiguous TLS ClientHello in the LogicalByteView
    When the scanner processes the handshake
    Then the following fields must be extracted:
      | field          | value       |
      | record_version | 0303        |
      | cipher_count   | 32          |
      | sni            | example.com |
    And the flow state must transition to "Fingerprinted"

  Scenario: Success Path: Fragmented Handshake (Split Scalar)
    Given an established TCP flow
    And a ClientHello fragmented such that the CipherSuite length straddles segments
    When the scanner processes the LogicalByteView
    Then the scanner must unify the length bytes in the stack scratchpad
    And correctly extract all 32 ciphers
    And the flow state must transition to "Fingerprinted"

  Scenario: Policy: GREASE and TLS 1.3 Supported Versions
    Given a TLS 1.3 ClientHello with GREASE values and "supported_versions" extension
    When the scanner processes the handshake
    Then "grease_observed" must be true
    And the effective version must be resolved from the extension
    And all GREASE values must be preserved in the raw extraction

  Scenario: Policy: ECH Visibility Limited
    Given a TLS ClientHello containing the "encrypted_client_hello" extension
    When the scanner processes the handshake
    Then the engine must signal "ECHVisibilityLimited"
    And ordinary JA3/JA4 fingerprinting must be suppressed

  Scenario: Fail-Closed: Malformed Nested Extension Length
    Given a valid TLS Handshake header
    And an extension vector claiming 100 bytes
    And a nested extension (e.g. SNI) claiming 200 bytes (Exceeding parent)
    When the scanner processes the handshake
    Then the engine must signal "MalformedTls"
    And the flow state must transition to "Impaired"

  Scenario: Fail-Closed: Not a ClientHello
    Given a TLS Handshake message of type 0x02 (ServerHello)
    When the scanner processes the message
    Then the engine must signal "NotClientHello"
    And the flow state must transition to "Impaired"

  Scenario: Truncation: Incomplete Handshake
    Given a valid TLS Record header
    And only 2 bytes of the Handshake header are available
    When the scanner processes the logical view
    Then the scanner must return "IncompleteAwaitingMoreData"
    And the flow state must remain "ClientHelloIncomplete"
