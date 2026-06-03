Feature: Public key encoding

  Scenario: A P256 compressed key round-trips through its bytes
    Given a random P256 public key "k"
    When I parse the bytes of P256 key "k"
    Then the parse succeeds
    And the parsed P256 key equals "k"

  Scenario: An invalid SEC1 prefix is rejected
    When I parse a P256 key whose first byte is 7
    Then the parse fails

  Scenario: A P256 key is scheme-tagged and recoverable
    Given a random P256 public key "k"
    When I tag P256 key "k" as "tagged"
    Then public key "tagged" has scheme P256
    And public key "tagged" reads back as P256 key "k"
    And reading public key "tagged" as Ed25519 fails

  Scenario: An Ed25519 key is scheme-tagged and zero-padded
    When I tag an Ed25519 key filled with 7 as "tagged"
    Then public key "tagged" has scheme Ed25519
    And the last byte of public key "tagged" is zero
    And reading public key "tagged" as P256 fails

  Scenario: An unknown scheme prefix is rejected
    When I parse a public key whose first byte is 9
    Then the public key parse fails
