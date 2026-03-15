Feature: Ingestion & Hardware Bypass Physical Path
  As a network systems architect
  I want to ensure the ingestion layer provides zero-copy access to hardware buffers
  So that line-rate processing (100Gbps) is physically achievable without memory pressure

  Background:
    Given an initialized fingerprint engine
    And the environment is locked to stable Rust

  Scenario: Metadata retrieval from AF_XDP driver
    Given a simulated "AF_XDP" ingestion driver
    And the adversarial trace "tests/fixtures/pcaps/baseline_empty.pcap"
    When the engine ingests a packet from the trace
    Then the "ingress_ifindex" should be present
    And the "rss_queue_id" should be present
    And the "timestamp_ns" should match the hardware clock

  Scenario: Zero-copy packet ownership audit
    Given a simulated high-throughput packet stream
    When the engine ingests 1000 packets
    Then no heap allocations should occur in the hot path
    And the packet data must be a borrowed slice from the driver's memory pool

  Scenario: Handling of unsupported protocol envelopes
    Given a packet with more than 8 IPv6 extension headers
    When the ingestion layer attempts to locate the L4 payload
    Then the engine must signal "ObfuscatedNetworkEnvelope"
    And the flow state must be terminated immediately
