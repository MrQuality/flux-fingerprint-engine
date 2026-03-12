Feature: Baseline Ingestion Connectivity
  As a network observability engineer
  I want to ensure the engine correctly ingests packets from the PCAP injector
  So that I can verify the reassembly and parsing logic

  Scenario: Successful packet ingestion from trace
    Given an initialized fingerprint engine
    And the adversarial trace "tests/fixtures/pcaps/baseline_empty.pcap"
    When the engine ingests all packets from the trace
    Then the ingestion count should be greater than 0
    And no Panics should occur
