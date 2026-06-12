Feature: User registry program

  Background:
    Given a funded user registry test rig

  # === register ===

  Scenario: Register creates an owner record
    Given owner "alice" with p256 keys
    When "alice" registers on-chain
    Then "alice" has a user record with no sync delegate

  Scenario: Register without an owner p256 key for Solana-only signers
    Given owner "alice" with p256 keys
    When "alice" registers on-chain without an owner p256 key
    Then "alice" has a user record without an owner p256 key

  Scenario: Registering twice fails
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    When "alice" tries to register again
    Then the transaction fails with "already in use"

  Scenario: Register rejects a zero-prefix viewing key
    Given owner "alice" with p256 keys
    When "alice" tries to register with viewing key prefix 0
    Then the transaction fails with "InvalidP256Prefix"

  Scenario: Register rejects an uncompressed-prefix viewing key
    Given owner "alice" with p256 keys
    When "alice" tries to register with viewing key prefix 4
    Then the transaction fails with "InvalidP256Prefix"

  Scenario: Register rejects a zero-prefix owner p256 key
    Given owner "alice" with p256 keys
    When "alice" tries to register with owner p256 prefix 0
    Then the transaction fails with "InvalidP256Prefix"

  Scenario: Register rejects a non-canonical nullifier pubkey
    Given owner "alice" with p256 keys
    When "alice" tries to register with a non-canonical nullifier pubkey
    Then the transaction fails with "NonCanonicalNullifierPubkey"

  # === set_sync_delegate ===

  Scenario: Set sync delegate appends an entry
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    When owner "alice" appoints sync delegate "bob"
    Then "alice" has sync delegate "bob" with 1 entries

  Scenario: Replacing the sync delegate appends another entry
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    When owner "alice" appoints sync delegate "carol"
    Then "alice" has sync delegate "carol" with 2 entries

  Scenario: A stranger cannot appoint a sync delegate for another owner
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And a stranger "mallory"
    When stranger "mallory" tries to appoint herself as sync delegate for "alice"
    Then the transaction fails with "ConstraintSeeds"

  Scenario: Set sync delegate rejects a zero-prefix sync key
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    When owner "alice" tries to appoint sync delegate "bob" with sync key prefix 0
    Then the transaction fails with "InvalidP256Prefix"

  # === rotate_sync_delegate ===

  Scenario: Sync delegate rotate appends without changing sync delegate address
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    When sync delegate "bob" rotates keys for "alice"
    Then "alice" has sync delegate "bob" with 2 entries

  Scenario: Owner cannot rotate sync delegate keys
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    When "alice" tries to rotate sync delegate keys for "alice"
    Then the transaction fails with "InvalidSyncDelegate"

  Scenario: A stranger cannot rotate sync delegate keys
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    And a stranger "mallory"
    When "mallory" tries to rotate sync delegate keys for "alice"
    Then the transaction fails with "InvalidSyncDelegate"

  Scenario: Another owner's sync delegate cannot rotate
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    And owner "dave" with p256 keys
    And "dave" registers on-chain
    And owner "dave" appoints sync delegate "carol"
    When "carol" tries to rotate sync delegate keys for "alice"
    Then the transaction fails with "InvalidSyncDelegate"

  Scenario: Rotate fails when no sync delegate was ever set
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And a stranger "mallory"
    When "mallory" tries to rotate sync delegate keys for "alice"
    Then the transaction fails with "InvalidSyncDelegate"

  Scenario: Rotate fails after revoke
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    And "bob" revokes sync delegate for "alice"
    When "bob" tries to rotate sync delegate keys for "alice"
    Then the transaction fails with "InvalidSyncDelegate"

  Scenario: Rotate rejects a zero-prefix viewing key
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    When sync delegate "bob" tries to rotate keys for "alice" with viewing key prefix 0
    Then the transaction fails with "InvalidP256Prefix"

  # === revoke ===

  Scenario: Revoke by the sync delegate clears it but keeps entries
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    When "bob" revokes sync delegate for "alice"
    Then "alice" has no sync delegate and 1 entries

  Scenario: Revoke by the owner clears the sync delegate
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    When "alice" revokes sync delegate for "alice"
    Then "alice" has no sync delegate and 1 entries

  Scenario: A stranger cannot revoke
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    And a stranger "mallory"
    When "mallory" revokes sync delegate for "alice"
    Then the transaction fails with "UnauthorizedSigner"

  Scenario: Revoke fails when no sync delegate is set
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    When "alice" revokes sync delegate for "alice"
    Then the transaction fails with "SyncDelegateNotSet"

  Scenario: Revoke twice fails
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    And "bob" revokes sync delegate for "alice"
    When "alice" revokes sync delegate for "alice"
    Then the transaction fails with "SyncDelegateNotSet"

  Scenario: Re-appointing after revoke appends a new entry
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    And "bob" revokes sync delegate for "alice"
    When owner "alice" appoints sync delegate "bob"
    Then "alice" has sync delegate "bob" with 2 entries

  # === close ===

  Scenario: Close succeeds before any sync delegate entry
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    When "alice" closes the record
    Then "alice" has no user record
    And "alice" received the rent refund

  Scenario: Close fails after set_sync_delegate
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    When "alice" tries to close the record
    Then the transaction fails with "RecordNotEmpty"

  Scenario: Close fails even after revoke
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" appoints sync delegate "bob"
    And "bob" revokes sync delegate for "alice"
    When "alice" tries to close the record
    Then the transaction fails with "RecordNotEmpty"

  Scenario: A stranger cannot close another owner's record
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And a stranger "mallory"
    When stranger "mallory" tries to close the record of "alice"
    Then the transaction fails with "ConstraintSeeds"

  Scenario: Re-register after close succeeds
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    When "alice" closes the record
    And "alice" registers on-chain
    Then "alice" has a user record with no sync delegate
