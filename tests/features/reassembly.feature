Feature: TCP Reassembly & Flow Lifecycle (EXHAUSTIVE)

  Scenario: Primary Success Path (Handshake to Fingerprint)
    Given an initialized fingerprint engine
    When the engine ingests a SYN packet for a new flow
    Then the FlowState must be "SynSeen"
    When the engine ingests a SYN-ACK packet
    Then the FlowState must be "SynAckSeen"
    When the engine ingests an ACK packet
    Then the FlowState must be "EstablishedTracking"
    When the engine ingests a partial TLS ClientHello segment
    Then the FlowState must be "ClientHelloIncomplete"
    When the engine ingests the final Handshake segment
    Then the FlowState must transition to "Fingerprinted"
    And the engine must emit a "Fingerprinted" outcome

  Scenario: Out-of-order segment logical reassembly
    Given a TCP flow in state "EstablishedTracking"
    When the engine ingests a packet with sequence 1001 and length 50
    And the engine ingests a packet with sequence 951 and length 50 (Out-of-Order)
    Then the FlowState must transition to "ClientHelloIncomplete"
    And the LogicalByteView at offset 0 must match the payload of sequence 951

  Scenario: Overlapping segment handling (First-Writer-Wins)
    Given a TCP flow in state "ClientHelloIncomplete" with 100 bytes at sequence 1000 (Content "A")
    When the engine ingests a packet with sequence 1050 and length 100 (Content "B")
    Then the LogicalByteView at sequence 1050 to 1100 must remain "A"
    And the later bytes for the overlapping range must be ignored

  Scenario: Flow Table Saturation (Hash Collision)
    Given an initialized fingerprint engine with a probe-tail limit of 16
    And a FlowMap at its target load factor
    When a packet is ingested that exceeds the 16 quadratic probes
    Then the engine must signal "CollisionDropped"
    And no new state may be allocated

  Scenario: Scratchpad Pool Exhaustion (Backpressure)
    Given an initialized fingerprint engine with a full scratchpad pool
    And a TCP flow in state "EstablishedTracking"
    When the engine ingests a payload segment requiring temporal reassembly
    Then the flow must transition to "Impaired"
    And the engine must signal "FingerprintSuppressedByBackpressure"

  Scenario: Tracking Window Overflow
    Given a TCP flow in state "ClientHelloIncomplete"
    When the engine ingests a segment beyond the 64-block sequence window
    Then the flow must transition to "Impaired"
    And the engine must signal "ObfuscatedNetworkEnvelope"

  Scenario: Fragment Budget Exhaustion
    Given a TCP flow in state "ClientHelloIncomplete" with 8 existing segments
    When the engine ingests a 9th discontiguous TCP segment
    Then the flow must transition to "Impaired"
    And the engine must signal "ExceededFragmentBudget"

  Scenario: Connection Aborted by RST
    Given a TCP flow in state "ClientHelloIncomplete"
    When the engine ingests a RST packet
    Then the flow must transition to "Aborted"
    And the engine must signal "AbortedByRst"
    And all scratchpad slots must be released

  Scenario: Flow Expiry via Timing Wheel
    Given a TCP flow in state "SynSeen"
    When the hardware clock advances by 101ms
    Then the flow must transition to "Expired"
    And the engine must signal "IncompleteTimedOut"

  Scenario: Truncation on Ambiguous Lengths (Fail-Closed)
    Given a TCP flow in state "ClientHelloIncomplete"
    When the engine ingests a TLS record with a claimed length larger than the tracking window
    Then the engine must transition to "Impaired"
    And the engine must signal "ObfuscatedNetworkEnvelope"

  Scenario: Detect ECH Outer (Impaired Transition)
    Given a TCP flow in state "EstablishedTracking"
    When the engine ingests a TLS ClientHello with ECH Outer extension
    Then the FlowState must transition to "Impaired"
    And the engine must signal "ECHVisibilityLimited"

  Scenario: Malformed TLS Record (Impaired Transition)
    Given a TCP flow in state "EstablishedTracking"
    When the engine ingests a malformed TLS record
    Then the FlowState must transition to "Impaired"
    And the engine must signal "MalformedTls"

  Scenario: Not a ClientHello Handshake (Impaired Transition)
    Given a TCP flow in state "EstablishedTracking"
    When the engine ingests a TLS ServerHello instead of ClientHello
    Then the FlowState must transition to "Impaired"
    And the engine must signal "NotClientHello"

  Scenario: Unsupported Timing Source Gating
    Given an engine initialization attempt on an unsupported CPU (Non-TSC-Safe)
    When the flow engine attempts to bind the Timing Wheel
    Then the engine must fail to initialize
    And signal "UnsupportedTimingSource"
